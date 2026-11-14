import { requireTenantRole } from './rbac.middleware';
import assert from 'node:assert/strict';
import { createServer, Server } from 'node:http';
import { AddressInfo } from 'node:net';
import { test, TestContext } from 'node:test';
import cookieParser from 'cookie-parser';
import express from 'express';
import { InMemoryAdapter } from '../adapters/memory.adapter';
import { AuthService } from '../core/auth.service';
import { CryptoEngine } from '../core/crypto';
import { EmailProvider } from '../core/email.interface';
import { Session } from '../core/types';
import { authErrorHandler, createAuthGuard, createAuthRouter } from './express.routes';
import {
  AUTH_RATE_LIMIT_PRESETS,
  InMemoryRateLimitStore,
  RateLimitStore,
} from './rate-limiter';

class RecordingEmailProvider implements EmailProvider {
  verificationEmails: Array<{ email: string; token: string }> = [];
  passwordResetEmails: Array<{ email: string; token: string }> = [];

  async sendVerificationEmail(email: string, token: string): Promise<void> {
    this.verificationEmails.push({ email, token });
  }

  async sendPasswordResetEmail(email: string, token: string): Promise<void> {
    this.passwordResetEmails.push({ email, token });
  }
}

class CapturingInMemoryAdapter extends InMemoryAdapter {
  lastCreatedSession: Session | undefined;

  override async createSession(data: Omit<Session, 'id' | 'createdAt'>): Promise<Session> {
    this.lastCreatedSession = await super.createSession(data);
    return this.lastCreatedSession;
  }
}

async function startTestServer(
  t: TestContext,
  emailVerificationRequired = false,
  options: { isProduction?: boolean; rateLimitStore?: RateLimitStore } = {}
) {
  const adapter = new CapturingInMemoryAdapter();
  const crypto = new CryptoEngine('express-route-test-secret');
  const emailProvider = new RecordingEmailProvider();
  const authService = new AuthService(
    adapter,
    crypto,
    { jwtSecret: 'express-route-test-secret', emailVerificationRequired },
    emailProvider
  );
  const app = express();

  app.use(express.json());
  app.use(cookieParser());
  app.use('/api/auth', createAuthRouter({ authService, crypto, ...options }));
  app.get('/api/protected/profile', createAuthGuard(crypto), (req: any, res: any) => {
    res.json({ success: true, user: req.user });
  });
  app.get('/api/organizations/:orgId/member', requireTenantRole(crypto, adapter, 'MEMBER'), (req, res) => {
    res.json({ tenant: res.locals.tenant });
  });
  app.get('/api/organizations/:orgId/admin', requireTenantRole(crypto, adapter, 'ADMIN'), (req, res) => {
    res.json({ tenant: res.locals.tenant });
  });
  app.use(authErrorHandler);

  const server = createServer(app);
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  t.after(() => closeServer(server));

  const address = server.address() as AddressInfo;
  return { adapter, authService, crypto, emailProvider, url: `http://127.0.0.1:${address.port}` };
}

function closeServer(server: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
    server.closeAllConnections();
  });
}

async function postJson(url: string, path: string, body: Record<string, string>) {
  return fetch(`${url}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

function refreshTokenFrom(response: Response): string {
  const token = response.headers.get('set-cookie')?.match(/refreshToken=([^;]+)/)?.[1];
  assert.ok(token, 'login should set a refreshToken cookie');
  return token;
}

test('POST /api/auth/register creates an account', async (t) => {
  const { url } = await startTestServer(t);
  const response = await postJson(url, '/api/auth/register', {
    email: 'person@example.com',
    password: 'correct horse battery staple',
  });

  assert.equal(response.status, 201);
  const body = (await response.json()) as { success: boolean; userId: string };
  assert.equal(body.success, true);
  assert.ok(body.userId);
  assert.equal('verificationToken' in body, false);
});

test('POST /api/auth/login returns an access token and rejects invalid credentials', async (t) => {
  const { url } = await startTestServer(t);
  await postJson(url, '/api/auth/register', {
    email: 'person@example.com',
    password: 'correct horse battery staple',
  });

  const response = await postJson(url, '/api/auth/login', {
    email: 'person@example.com',
    password: 'correct horse battery staple',
  });
  assert.equal(response.status, 200);
  assert.ok(((await response.json()) as { accessToken: string }).accessToken);
  assert.ok(refreshTokenFrom(response));

  const rejected = await postJson(url, '/api/auth/login', {
    email: 'person@example.com',
    password: 'wrong password',
  });
  assert.equal(rejected.status, 401);
  assert.equal((await rejected.json() as { code: string }).code, 'INVALID_CREDENTIALS');
});

test('POST /api/auth/refresh rotates the refresh cookie', async (t) => {
  const { adapter, crypto, url } = await startTestServer(t);
  await postJson(url, '/api/auth/register', {
    email: 'person@example.com',
    password: 'correct horse battery staple',
  });
  const loginResponse = await postJson(url, '/api/auth/login', {
    email: 'person@example.com',
    password: 'correct horse battery staple',
  });
  const oldRefreshToken = refreshTokenFrom(loginResponse);
  const session = adapter.lastCreatedSession;
  assert.ok(session);

  const response = await postJson(url, '/api/auth/refresh', {
    sessionId: session.id,
    refreshToken: oldRefreshToken,
  });

  assert.equal(response.status, 200);
  assert.ok(((await response.json()) as { accessToken: string }).accessToken);
  const newRefreshToken = refreshTokenFrom(response);
  assert.notEqual(newRefreshToken, oldRefreshToken);
  const rotatedSession = await adapter.findSessionById(session.id);
  assert.equal(rotatedSession?.refreshTokenHash, crypto.hashOpaqueToken(newRefreshToken));
});

test('protected profile accepts a valid Bearer token and rejects missing or invalid tokens', async (t) => {
  const { crypto, url } = await startTestServer(t);
  const accessToken = await crypto.generateAccessToken('user-123', 'person@example.com');

  const authorized = await fetch(`${url}/api/protected/profile`, {
    headers: { authorization: `Bearer ${accessToken}` },
  });
  assert.equal(authorized.status, 200);
  assert.deepEqual(((await authorized.json()) as { user: { userId: string; email: string } }).user, {
    userId: 'user-123',
    email: 'person@example.com',
  });

  const missing = await fetch(`${url}/api/protected/profile`);
  assert.equal(missing.status, 401);

  const invalid = await fetch(`${url}/api/protected/profile`, {
    headers: { authorization: 'Bearer not-a-valid-token' },
  });
  assert.equal(invalid.status, 401);
});

test('email verification and password reset routes complete the account workflows', async (t) => {
  const { emailProvider, url } = await startTestServer(t, true);
  const registration = await postJson(url, '/api/auth/register', {
    email: 'person@example.com',
    password: 'old password',
  });
  assert.equal(registration.status, 201);
  const verificationToken = emailProvider.verificationEmails[0]?.token;
  assert.ok(verificationToken);

  const verification = await postJson(url, '/api/auth/verify-email', { token: verificationToken });
  assert.equal(verification.status, 200);

  const oldLogin = await postJson(url, '/api/auth/login', {
    email: 'person@example.com',
    password: 'old password',
  });
  assert.equal(oldLogin.status, 200);

  const missingAccountReset = await postJson(url, '/api/auth/forgot-password', {
    email: 'missing@example.com',
  });
  assert.equal(missingAccountReset.status, 200);
  assert.equal(emailProvider.passwordResetEmails.length, 0);

  const resetRequest = await postJson(url, '/api/auth/forgot-password', {
    email: 'person@example.com',
  });
  assert.equal(resetRequest.status, 200);
  const resetToken = emailProvider.passwordResetEmails[0]?.token;
  assert.ok(resetToken);

  const passwordReset = await postJson(url, '/api/auth/reset-password', {
    token: resetToken,
    newPassword: 'new password',
  });
  assert.equal(passwordReset.status, 200);

  const rejectedOldPassword = await postJson(url, '/api/auth/login', {
    email: 'person@example.com',
    password: 'old password',
  });
  assert.equal(rejectedOldPassword.status, 401);
  const acceptedNewPassword = await postJson(url, '/api/auth/login', {
    email: 'person@example.com',
    password: 'new password',
  });
  assert.equal(acceptedNewPassword.status, 200);
});

test('auth request schemas return field-specific 400 errors for invalid payloads', async (t) => {
  const { url } = await startTestServer(t);
  const invalidRequests = [
    ['/api/auth/register', { email: 'not-an-email', password: 'short' }, 'email'],
    ['/api/auth/login', { email: 'person@example.com', password: '' }, 'password'],
    ['/api/auth/refresh', { refreshToken: 'token' }, 'sessionId'],
    ['/api/auth/verify-email', {}, 'token'],
    ['/api/auth/reset-password', { token: 'token', newPassword: 'short' }, 'newPassword'],
  ] as const;

  for (const [path, body, expectedField] of invalidRequests) {
    const response = await postJson(url, path, body);
    assert.equal(response.status, 400, `${path} should reject invalid payloads`);
    const result = (await response.json()) as {
      code: string;
      errors: Array<{ field: string; message: string }>;
    };
    assert.equal(result.code, 'VALIDATION_ERROR');
    assert.ok(result.errors.some((error) => error.field === expectedField));
  }
});

test('rate limits registration and reports retry information', async (t) => {
  const { url } = await startTestServer(t);
  for (let attempt = 0; attempt < 10; attempt += 1) {
    assert.equal((await postJson(url, '/api/auth/register', {})).status, 400);
  }

  const limited = await postJson(url, '/api/auth/register', {});
  assert.equal(limited.status, 429);
  assert.equal(limited.headers.get('ratelimit-limit'), '10');
  assert.ok(Number(limited.headers.get('retry-after')) >= 1);
  assert.equal((await limited.json() as { code: string }).code, 'RATE_LIMIT_EXCEEDED');
});

test('in-memory rate store applies a sliding window and removes expired keys', async () => {
  const store = new InMemoryRateLimitStore();
  assert.deepEqual(AUTH_RATE_LIMIT_PRESETS, {
    register: { limit: 10, windowMs: 60 * 60 * 1000 },
    login: { limit: 5, windowMs: 15 * 60 * 1000 },
    forgotPassword: { limit: 5, windowMs: 15 * 60 * 1000 },
    resetPassword: { limit: 5, windowMs: 15 * 60 * 1000 },
  });

  assert.equal((await store.consume('user', 0, 10_000, 2)).allowed, true);
  assert.equal((await store.consume('user', 9_000, 10_000, 2)).allowed, true);
  assert.equal((await store.consume('user', 15_000, 10_000, 2)).allowed, true);
  assert.equal((await store.consume('user', 16_000, 10_000, 2)).allowed, false);

  store.cleanupExpired(26_000);
  assert.equal((await store.consume('user', 26_000, 10_000, 2)).allowed, true);
});

test('login, forgot-password, and reset-password enforce five-attempt presets', async (t) => {
  const { url } = await startTestServer(t);

  for (let attempt = 0; attempt < 5; attempt += 1) {
    assert.equal((await postJson(url, '/api/auth/login', {
      email: 'person@example.com',
      password: 'valid-length-password',
    })).status, 401);
  }
  const limitedLogin = await postJson(url, '/api/auth/login', {
    email: 'person@example.com',
    password: 'valid-length-password',
  });
  assert.equal(limitedLogin.status, 429);
  assert.ok(Number(limitedLogin.headers.get('retry-after')) >= 1);

  for (let attempt = 0; attempt < 5; attempt += 1) {
    assert.equal((await postJson(url, '/api/auth/forgot-password', {
      email: 'missing@example.com',
    })).status, 200);
  }
  assert.equal((await postJson(url, '/api/auth/forgot-password', {
    email: 'missing@example.com',
  })).status, 429);

  for (let attempt = 0; attempt < 5; attempt += 1) {
    assert.equal((await postJson(url, '/api/auth/reset-password', {
      token: 'unrecognized-token',
      newPassword: 'a-valid-new-password',
    })).status, 400);
  }
  assert.equal((await postJson(url, '/api/auth/reset-password', {
    token: 'unrecognized-token',
    newPassword: 'a-valid-new-password',
  })).status, 429);
});

test('login and refresh cookies preserve secure defaults and production Secure flag', async (t) => {
  const { adapter, url } = await startTestServer(t, false, { isProduction: true });
  await postJson(url, '/api/auth/register', {
    email: 'person@example.com',
    password: 'correct horse battery staple',
  });
  const login = await postJson(url, '/api/auth/login', {
    email: 'person@example.com',
    password: 'correct horse battery staple',
  });
  const loginCookie = login.headers.get('set-cookie') ?? '';
  assert.match(loginCookie, /HttpOnly/i);
  assert.match(loginCookie, /Secure/i);
  assert.match(loginCookie, /SameSite=Lax/i);
  const refreshToken = refreshTokenFrom(login);
  const session = adapter.lastCreatedSession;
  assert.ok(session);

  const refresh = await postJson(url, '/api/auth/refresh', {
    sessionId: session.id,
    refreshToken,
  });
  const refreshCookie = refresh.headers.get('set-cookie') ?? '';
  assert.equal(refresh.status, 200);
  assert.match(refreshCookie, /HttpOnly/i);
  assert.match(refreshCookie, /Secure/i);
  assert.match(refreshCookie, /SameSite=Lax/i);
});

test('RBAC checks live organization membership, role hierarchy, and token scope', async (t) => {
  const { adapter, authService, crypto, url } = await startTestServer(t);
  const owner = (await authService.register('owner@example.com', 'correct horse battery staple')).user;
  const member = (await authService.register('member@example.com', 'correct horse battery staple')).user;
  const organization = await authService.createOrganization(owner.id, 'Route Test Org');
  await authService.addOrganizationMember(owner.id, organization.id, member.id, 'MEMBER');
  const tenantToken = await authService.issueTenantAccessToken(member.id, organization.id);
  const authorization = { authorization: `Bearer ${tenantToken}` };

  const memberRoute = await fetch(`${url}/api/organizations/${organization.id}/member`, {
    headers: authorization,
  });
  assert.equal(memberRoute.status, 200);
  assert.deepEqual((await memberRoute.json() as { tenant: { orgId: string; role: string } }).tenant, {
    orgId: organization.id,
    role: 'MEMBER',
  });

  const adminRoute = await fetch(`${url}/api/organizations/${organization.id}/admin`, {
    headers: authorization,
  });
  assert.equal(adminRoute.status, 403);

  const otherOrganizationRoute = await fetch(`${url}/api/organizations/another-org/member`, {
    headers: authorization,
  });
  assert.equal(otherOrganizationRoute.status, 403);

  const nonTenantToken = await crypto.generateAccessToken(member.id, member.email);
  const nonTenantResponse = await fetch(`${url}/api/organizations/${organization.id}/member`, {
    headers: { authorization: `Bearer ${nonTenantToken}` },
  });
  assert.equal(nonTenantResponse.status, 403);
  assert.ok(await adapter.findOrganizationMember(member.id, organization.id));
});