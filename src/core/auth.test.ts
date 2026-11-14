import assert from 'node:assert/strict';
import { test } from 'node:test';
import { InMemoryAdapter } from '../adapters/memory.adapter.js';
import { AuthService } from './auth.service.js';
import { CryptoEngine } from './crypto.js';
import { EmailProvider } from './email.interface.js';
import { AuthError } from './errors.js';
import { Session } from './types.js';

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

function createHarness(emailVerificationRequired = false, emailProvider?: EmailProvider) {
  const adapter = new CapturingInMemoryAdapter();
  const crypto = new CryptoEngine('auth-service-test-secret');
  const service = new AuthService(
    adapter,
    crypto,
    { jwtSecret: 'auth-service-test-secret', emailVerificationRequired },
    emailProvider
  );
  return { adapter, crypto, service };
}

function hasAuthError(statusCode: number, code: AuthError['code']) {
  return (error: unknown): error is AuthError =>
    error instanceof AuthError && error.statusCode === statusCode && error.code === code;
}

test('registers a user and rejects duplicate email addresses with 409', async () => {
  const { service } = createHarness();
  const result = await service.register('person@example.com', 'correct horse battery staple');

  assert.equal(result.user.email, 'person@example.com');
  assert.equal(result.user.emailVerified, false);
  assert.equal(result.verificationToken, undefined);

  await assert.rejects(
    service.register('person@example.com', 'another password'),
    hasAuthError(409, 'USER_ALREADY_EXISTS')
  );
});

test('logs in with a valid password and rejects an invalid password with 401', async () => {
  const { service } = createHarness();
  await service.register('person@example.com', 'correct horse battery staple');

  const tokens = await service.login('person@example.com', 'correct horse battery staple');
  assert.ok(tokens.accessToken);
  assert.ok(tokens.refreshToken);

  await assert.rejects(
    service.login('person@example.com', 'wrong password'),
    hasAuthError(401, 'INVALID_CREDENTIALS')
  );
});

test('rotates a refresh token and invalidates the session after a token mismatch', async () => {
  const { adapter, crypto, service } = createHarness();
  await service.register('person@example.com', 'correct horse battery staple');
  const initialTokens = await service.login('person@example.com', 'correct horse battery staple');
  const session = adapter.lastCreatedSession;
  assert.ok(session);

  const rotatedTokens = await service.refreshSession(session.id, initialTokens.refreshToken);
  assert.notEqual(rotatedTokens.refreshToken, initialTokens.refreshToken);

  const rotatedSession = await adapter.findSessionById(session.id);
  assert.ok(rotatedSession);
  assert.equal(rotatedSession.refreshTokenHash, crypto.hashOpaqueToken(rotatedTokens.refreshToken));

  await assert.rejects(
    service.refreshSession(session.id, initialTokens.refreshToken),
    hasAuthError(401, 'INVALID_TOKEN')
  );
  assert.equal(await adapter.findSessionById(session.id), null);
});

test('sends and consumes a hashed, single-use email verification token', async () => {
  const emailProvider = new RecordingEmailProvider();
  const { adapter, crypto, service } = createHarness(true, emailProvider);
  const { user, verificationToken } = await service.register('person@example.com', 'correct horse battery staple');

  assert.ok(verificationToken);
  assert.deepEqual(emailProvider.verificationEmails, [
    { email: user.email, token: verificationToken },
  ]);
  const storedToken = await adapter.findVerificationToken(
    crypto.hashOpaqueToken(verificationToken),
    'EMAIL_VERIFICATION'
  );
  assert.ok(storedToken);
  assert.notEqual(storedToken.tokenHash, verificationToken);

  await service.verifyEmail(verificationToken);
  assert.equal((await adapter.findUserById(user.id))?.emailVerified, true);
  assert.equal(
    await adapter.findVerificationToken(crypto.hashOpaqueToken(verificationToken), 'EMAIL_VERIFICATION'),
    null
  );
  await assert.rejects(service.verifyEmail(verificationToken), hasAuthError(400, 'INVALID_TOKEN'));
});

test('sends password reset instructions without account enumeration and revokes sessions on reset', async () => {
  const emailProvider = new RecordingEmailProvider();
  const { adapter, crypto, service } = createHarness(false, emailProvider);
  await service.register('person@example.com', 'old password');
  await service.login('person@example.com', 'old password');
  const session = adapter.lastCreatedSession;
  assert.ok(session);

  await service.requestPasswordReset('missing@example.com');
  assert.equal(emailProvider.passwordResetEmails.length, 0);
  await service.requestPasswordReset('person@example.com');
  const resetEmail = emailProvider.passwordResetEmails[0];
  assert.deepEqual(resetEmail.email, 'person@example.com');

  const storedToken = await adapter.findVerificationToken(
    crypto.hashOpaqueToken(resetEmail.token),
    'PASSWORD_RESET'
  );
  assert.ok(storedToken);
  assert.notEqual(storedToken.tokenHash, resetEmail.token);

  await service.resetPassword(resetEmail.token, 'new password');
  assert.equal(await adapter.findSessionById(session.id), null);
  await assert.rejects(
    service.login('person@example.com', 'old password'),
    hasAuthError(401, 'INVALID_CREDENTIALS')
  );
  assert.ok((await service.login('person@example.com', 'new password')).accessToken);
  await assert.rejects(
    service.resetPassword(resetEmail.token, 'another password'),
    hasAuthError(400, 'INVALID_TOKEN')
  );
});

test('creates organizations with unique slugs and assigns the creator as owner', async () => {
  const { adapter, service } = createHarness();
  const creator = (await service.register('owner@example.com', 'correct horse battery staple')).user;

  const first = await service.createOrganization(creator.id, 'Acme Labs');
  const second = await service.createOrganization(creator.id, 'Acme Labs');

  assert.equal(first.slug, 'acme-labs');
  assert.equal(second.slug, 'acme-labs-2');
  assert.equal((await adapter.findOrganizationMember(creator.id, first.id))?.role, 'OWNER');
  assert.deepEqual((await service.findUserOrganizations(creator.id)).map(({ role }) => role), ['OWNER', 'OWNER']);
});

test('adds members with roles and issues organization-scoped JWT claims', async () => {
  const { adapter, crypto, service } = createHarness();
  const owner = (await service.register('owner@example.com', 'correct horse battery staple')).user;
  const member = (await service.register('member@example.com', 'correct horse battery staple')).user;
  const organization = await service.createOrganization(owner.id, 'Example Org');

  const membership = await service.addOrganizationMember(owner.id, organization.id, member.id, 'MEMBER');
  assert.equal(membership.role, 'MEMBER');
  await assert.rejects(
    service.addOrganizationMember(member.id, organization.id, owner.id, 'ADMIN'),
    hasAuthError(403, 'FORBIDDEN')
  );
  await assert.rejects(
    service.addOrganizationMember(member.id, organization.id, owner.id, 'OWNER'),
    hasAuthError(403, 'FORBIDDEN')
  );

  const token = await service.issueTenantAccessToken(member.id, organization.id);
  assert.deepEqual(await crypto.verifyAccessToken(token), {
    userId: member.id,
    email: member.email,
    orgId: organization.id,
    role: 'MEMBER',
  });
  await assert.rejects(
    service.issueTenantAccessToken(owner.id, 'not-a-member-org'),
    hasAuthError(403, 'FORBIDDEN')
  );
  assert.equal((await adapter.findUserOrganizations(member.id))[0]?.organization.slug, 'example-org');
});