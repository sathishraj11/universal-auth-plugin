# Client Implementation Runbook

This runbook is for a Node.js 20+ Express application integrating `universal-auth-plugin`. Replace `@your-scope` with the npm scope under which the package is published.

## 1. Install

```sh
npm install @your-scope/universal-auth-plugin @prisma/client express zod cookie-parser
npm install --save-dev prisma
```

`@prisma/client`, `express`, and `zod` are optional peers so a consumer only needs the dependencies for the subpaths it imports. `cookie-parser` is needed by the Express refresh-cookie flow.

## 2. Copy the Prisma schema

The published package includes its schema at `prisma/schema.prisma`. Merge it with an existing application schema if that schema already defines overlapping models.

macOS/Linux:

```sh
mkdir -p prisma
cp node_modules/@your-scope/universal-auth-plugin/prisma/schema.prisma prisma/schema.prisma
```

PowerShell:

```powershell
New-Item -ItemType Directory -Force prisma | Out-Null
Copy-Item node_modules/@your-scope/universal-auth-plugin/prisma/schema.prisma prisma/schema.prisma
```

Set `DATABASE_URL` in the application's environment, then apply and generate the schema:

```sh
npx prisma db push
npx prisma generate
```

## 3. Configure environment

Keep secrets in your deployment secret manager or an uncommitted `.env` file. Generate independent random secrets of at least 32 bytes for the JWT variables.

| Variable | Example | Notes |
| --- | --- | --- |
| `DATABASE_URL` | `postgresql://user:password@localhost:5432/auth` | Required by Prisma. |
| `JWT_ACCESS_SECRET` | generated secret | Passed to `CryptoEngine` for access JWT signing. |
| `JWT_REFRESH_SECRET` | separate generated secret | The current plugin uses random opaque refresh tokens and does not consume this key. Keep it separate and use it only if host-application code independently signs refresh JWTs. |
| `ACCESS_TOKEN_TTL` | `15m` | `jose` duration string, e.g. `15m` or `1h`. |
| `REFRESH_TOKEN_TTL` | `7d` | Runbook accepts integer `m`, `h`, or `d` values and converts them to the plugin's `refreshTokenExpiryDays`. |
| `RESEND_API_KEY` | `re_...` | Required for production email delivery in the example below. |
| `RESEND_FROM_EMAIL` | `Auth <auth@example.com>` | Verified sender for Resend. |
| `PORT` | `3000` | Optional; defaults to `3000`. |

## 4. Wire Express and Prisma

Save as `src/server.ts`. `ConsoleEmailProvider` is used only in development; production startup requires Resend configuration.

```ts
import express, { NextFunction, Request, Response } from 'express';
import cookieParser from 'cookie-parser';
import {
  AuthService,
  CryptoEngine,
} from '@your-scope/universal-auth-plugin';
import { PrismaAdapter } from '@your-scope/universal-auth-plugin/adapters/prisma';
import {
  ConsoleEmailProvider,
  ResendEmailProvider,
} from '@your-scope/universal-auth-plugin/adapters/email';
import {
  authErrorHandler,
  createAuthGuard,
  createAuthRouter,
  InMemoryRateLimitStore,
  requireTenantRole,
} from '@your-scope/universal-auth-plugin/transport/express';

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required environment variable: ${name}`);
  return value;
}

function refreshTtlDays(value: string): number {
  const match = /^(\\d+)(m|h|d)$/.exec(value);
  if (!match) throw new Error('REFRESH_TOKEN_TTL must be an integer followed by m, h, or d.');
  const amount = Number(match[1]);
  if (amount < 1) throw new Error('REFRESH_TOKEN_TTL must be positive.');
  return match[2] === 'd' ? amount : match[2] === 'h' ? amount / 24 : amount / 1440;
}

interface AuthenticatedRequest extends Request {
  user?: { userId: string; email: string };
}

const app = express();
const port = Number(process.env.PORT ?? 3000);
const storageAdapter = new PrismaAdapter();
const accessSecret = requiredEnv('JWT_ACCESS_SECRET');
requiredEnv('JWT_REFRESH_SECRET'); // Reserved for host-owned refresh JWTs; this plugin uses opaque refresh tokens.
const crypto = new CryptoEngine(accessSecret);
const emailProvider = process.env.NODE_ENV === 'production'
  ? new ResendEmailProvider(requiredEnv('RESEND_API_KEY'), requiredEnv('RESEND_FROM_EMAIL'))
  : new ConsoleEmailProvider();
const authService = new AuthService(
  storageAdapter,
  crypto,
  {
    jwtSecret: accessSecret,
    accessTokenExpiry: process.env.ACCESS_TOKEN_TTL ?? '15m',
    refreshTokenExpiryDays: refreshTtlDays(process.env.REFRESH_TOKEN_TTL ?? '7d'),
    emailVerificationRequired: true,
  },
  emailProvider
);

app.use(express.json({ limit: '16kb' }));
app.use(cookieParser());

app.use('/api/auth', createAuthRouter({
  authService,
  crypto,
  rateLimitStore: new InMemoryRateLimitStore(),
}));

app.post('/api/organizations', createAuthGuard(crypto), async (req: Request, res: Response, next: NextFunction) => {
  const actor = (req as AuthenticatedRequest).user;
  const name = req.body?.name;
  if (!actor || typeof name !== 'string' || !name.trim()) {
    res.status(400).json({ success: false, code: 'VALIDATION_ERROR', message: 'A name is required.' });
    return;
  }
  try {
    const organization = await authService.createOrganization(actor.userId, name);
    res.status(201).json(organization);
  } catch (error) {
    next(error);
  }
});

app.post('/api/organizations/:orgId/access-token', createAuthGuard(crypto), async (req: Request, res: Response, next: NextFunction) => {
  const actor = (req as AuthenticatedRequest).user;
  if (!actor) {
    res.status(401).json({ success: false, message: 'Unauthorized.' });
    return;
  }
  try {
    const accessToken = await authService.issueTenantAccessToken(actor.userId, req.params.orgId);
    res.json({ accessToken });
  } catch (error) {
    next(error);
  }
});

app.get(
  '/api/organizations/:orgId/admin',
  requireTenantRole(crypto, storageAdapter, 'ADMIN'),
  (_req, res) => res.json({ success: true, tenant: res.locals.tenant })
);

app.use(authErrorHandler);
app.listen(port, () => console.log(`Auth server listening on port ${port}`));
```

`requireTenantRole` verifies the access token, checks live membership in the organization, and enforces the minimum role. Use it on each tenant-protected route. The example uses an in-memory limiter; use a shared `RateLimitStore` implementation when deploying multiple application instances.

## 5. Pre-deployment verification

- **Reverse proxy:** If behind a proxy, configure Express `trust proxy` for the exact trusted proxy hop count or address range. Do not blindly enable trust for arbitrary clients; client IPs feed rate limiting and session metadata.
- **Refresh rotation:** Smoke-test login and refresh, assert the rotated refresh cookie differs from the original, and confirm replaying the old token invalidates its session. The current `/api/auth/login` response does not return a `sessionId`, while `/api/auth/refresh` requires one in its body; expose the session ID through a trusted application flow or adjust that API before relying on HTTP-only rotation from a client.
- **Tenant isolation:** Create two organizations and verify a token scoped to one receives `403` for the other. Verify MEMBER access is denied on ADMIN routes, and re-check that a removed or downgraded member loses access.
- **Rate limiting:** Restart the local server to clear its in-memory limiter, then run `k6 run k6-load-test.js`. The script is intentionally limited to `127.0.0.1:3000`; verify five invalid login responses followed by `429` and a positive `Retry-After` header.
- **Secrets and database:** Confirm production secrets are configured, database migrations/schema are applied, Resend sender identity is verified, and no secret or console-email token appears in logs.
