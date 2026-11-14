import assert from 'node:assert/strict';
import { test } from 'node:test';
import { GitHubOAuthStrategy } from '../adapters/oauth/github.strategy.js';
import { GoogleOAuthStrategy } from '../adapters/oauth/google.strategy.js';
import { InMemoryAdapter } from '../adapters/memory.adapter.js';
import { AuthError } from './errors.js';
import { CryptoEngine } from './crypto.js';
import { OAuthStrategy, OAuthUserProfile } from './oauth.interface.js';
import { OAuthService } from './oauth.service.js';

class StubOAuthStrategy implements OAuthStrategy {
  exchangedCodes: string[] = [];

  constructor(
    readonly provider: 'google' | 'github',
    private readonly profile: OAuthUserProfile
  ) {}

  getAuthorizationUrl(state: string): string {
    return `https://oauth.example/${this.provider}?state=${encodeURIComponent(state)}`;
  }

  async exchangeCode(code: string): Promise<OAuthUserProfile> {
    this.exchangedCodes.push(code);
    return this.profile;
  }
}

test('Google and GitHub authorization URLs include provider scopes and state', () => {
  const google = new GoogleOAuthStrategy({
    clientId: 'google-client',
    clientSecret: 'google-secret',
    redirectUri: 'https://app.example/api/auth/google/callback',
  });
  const googleUrl = new URL(google.getAuthorizationUrl('google-state'));
  assert.equal(googleUrl.origin, 'https://accounts.google.com');
  assert.equal(googleUrl.searchParams.get('state'), 'google-state');
  assert.equal(googleUrl.searchParams.get('response_type'), 'code');
  assert.deepEqual(googleUrl.searchParams.get('scope')?.split(' ').sort(), ['email', 'openid', 'profile']);

  const github = new GitHubOAuthStrategy({
    clientId: 'github-client',
    clientSecret: 'github-secret',
    redirectUri: 'https://app.example/api/auth/github/callback',
  });
  const githubUrl = new URL(github.getAuthorizationUrl('github-state'));
  assert.equal(githubUrl.origin, 'https://github.com');
  assert.equal(githubUrl.searchParams.get('state'), 'github-state');
  assert.deepEqual(githubUrl.searchParams.get('scope')?.split(' ').sort(), ['read:user', 'user:email']);
});

test('OAuth service provisions verified users, links by email, and issues auth sessions', async () => {
  const adapter = new InMemoryAdapter();
  const crypto = new CryptoEngine('oauth-service-test-secret');
  const google = new StubOAuthStrategy('google', {
    providerId: 'google-subject-1',
    email: 'person@example.com',
    emailVerified: true,
  });
  const github = new StubOAuthStrategy('github', {
    providerId: 'github-user-1',
    email: 'person@example.com',
    emailVerified: true,
  });
  const service = new OAuthService(adapter, crypto, { jwtSecret: 'oauth-service-test-secret' }, [google, github]);

  const firstLogin = await service.authenticate('google', 'google-code', 'test-agent', '127.0.0.1');
  const user = await adapter.findUserById(firstLogin.user.id);
  assert.ok(user?.emailVerified);
  assert.equal(google.exchangedCodes[0], 'google-code');
  assert.deepEqual(await crypto.verifyAccessToken(firstLogin.accessToken), {
    userId: firstLogin.user.id,
    email: 'person@example.com',
  });
  const session = await adapter.findSessionById(firstLogin.sessionId);
  assert.equal(session?.refreshTokenHash, crypto.hashOpaqueToken(firstLogin.refreshToken));
  assert.equal(session?.userAgent, 'test-agent');

  const linkedLogin = await service.authenticate('github', 'github-code');
  assert.equal(linkedLogin.user.id, firstLogin.user.id);
  assert.equal(github.exchangedCodes[0], 'github-code');
});

test('OAuth service rejects unverified emails and reports missing provider configuration', async () => {
  const adapter = new InMemoryAdapter();
  const crypto = new CryptoEngine('oauth-service-test-secret');
  const unverified = new StubOAuthStrategy('google', {
    providerId: 'google-subject-2',
    email: 'person@example.com',
    emailVerified: false,
  });
  const service = new OAuthService(adapter, crypto, { jwtSecret: 'oauth-service-test-secret' }, [unverified]);

  await assert.rejects(
    service.authenticate('google', 'google-code'),
    (error: unknown) => error instanceof AuthError && error.code === 'OAUTH_PROFILE_INVALID'
  );
  await assert.rejects(
    Promise.resolve().then(() => service.getAuthorizationUrl('github', 'state')),
    (error: unknown) => error instanceof AuthError && error.statusCode === 503
  );
});