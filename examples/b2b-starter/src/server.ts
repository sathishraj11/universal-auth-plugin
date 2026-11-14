import 'dotenv/config';
import express, { NextFunction, Request, Response } from 'express';
import cookieParser from 'cookie-parser';
import { PrismaClient } from '@prisma/client';
import { AuthService, CryptoEngine, OrgRole } from 'universal-auth-plugin';
import { PrismaAdapter } from 'universal-auth-plugin/adapters/prisma';
import { ConsoleEmailProvider } from 'universal-auth-plugin/adapters/email';
import {
  authErrorHandler,
  createAuthGuard,
  createAuthRouter,
  requireTenantRole as tenantRoleMiddleware,
} from 'universal-auth-plugin/transport/express';

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required environment variable: ${name}`);
  return value;
}

function refreshTokenTtlDays(value: string): number {
  const match = /^(\d+)(m|h|d)$/.exec(value);
  if (!match) throw new Error('REFRESH_TOKEN_TTL must be an integer followed by m, h, or d.');
  const amount = Number(match[1]);
  if (amount < 1) throw new Error('REFRESH_TOKEN_TTL must be positive.');
  return match[2] === 'd' ? amount : match[2] === 'h' ? amount / 24 : amount / 1440;
}

interface AuthenticatedRequest extends Request {
  user?: { userId: string; email: string };
}

const databaseUrl = requiredEnv('DATABASE_URL');
const accessSecret = requiredEnv('JWT_ACCESS_SECRET');
requiredEnv('JWT_REFRESH_SECRET'); // Reserved for host-owned refresh JWTs; this plugin stores opaque refresh tokens.
const port = Number(process.env.PORT ?? 4000);
const storageAdapter = new PrismaAdapter(new PrismaClient());
const crypto = new CryptoEngine(accessSecret);
const authService = new AuthService(
  storageAdapter,
  crypto,
  {
    jwtSecret: accessSecret,
    accessTokenExpiry: process.env.ACCESS_TOKEN_TTL ?? '15m',
    refreshTokenExpiryDays: refreshTokenTtlDays(process.env.REFRESH_TOKEN_TTL ?? '7d'),
    emailVerificationRequired: false,
  },
  new ConsoleEmailProvider()
);

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '16kb' }));
app.use(cookieParser());
app.use('/api/auth', createAuthRouter({ authService, crypto }));

app.post('/api/orgs', createAuthGuard(crypto), async (req: Request, res: Response, next: NextFunction) => {
  const actor = (req as AuthenticatedRequest).user;
  const name = req.body?.name;
  if (!actor || typeof name !== 'string' || !name.trim()) {
    res.status(400).json({ success: false, code: 'VALIDATION_ERROR', message: 'A non-empty organization name is required.' });
    return;
  }

  try {
    const organization = await authService.createOrganization(actor.userId, name);
    const tenantAccessToken = await authService.issueTenantAccessToken(actor.userId, organization.id);
    res.status(201).json({ organization, accessToken: tenantAccessToken });
  } catch (error) {
    next(error);
  }
});

function requireTenantRole(roles: OrgRole[]) {
  if (roles.length === 0) throw new Error('At least one tenant role is required.');
  const minimumRole: OrgRole = roles.includes('ADMIN') ? 'ADMIN' : roles.includes('OWNER') ? 'OWNER' : 'MEMBER';
  return tenantRoleMiddleware(crypto, storageAdapter, minimumRole);
}

app.get('/api/orgs/:orgId/dashboard', requireTenantRole(['OWNER', 'ADMIN']), (req, res) => {
  res.json({
    success: true,
    organizationId: res.locals.tenant.orgId,
    role: res.locals.tenant.role,
    dashboard: 'B2B organization dashboard',
  });
});

app.use(authErrorHandler);
app.use((error: unknown, _req: Request, res: Response, _next: NextFunction) => {
  console.error('Unhandled request error:', error);
  res.status(500).json({ success: false, message: 'Internal server error.' });
});
app.listen(port, () => {
  console.log(`B2B starter listening on http://localhost:${port}`);
  console.log('Database URL loaded from environment.');
});
