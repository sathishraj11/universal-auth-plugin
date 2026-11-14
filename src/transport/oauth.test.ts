import assert from 'node:assert/strict';
import { createServer, Server } from 'node:http';
import { AddressInfo } from 'node:net';
import { test, TestContext } from 'node:test';
import cookieParser from 'cookie-parser';
import express from 'express';
import { InMemoryAdapter } from '../adapters/memory.adapter.js';
import { CryptoEngine } from '../core/crypto.js';
import { AuthError } from '../core/errors.js';
import { OAuthStrategy, OAuthUserProfile } from '../core/oauth.interface.js';
import { OAuthService } from '../core/oauth.service.js';
import { authErrorHandler } from './express.middleware.js';
import { createOAuthRouter } from './oauth.middleware.js';

class StubOAuthStrategy implements OAuthStrategy {
  exchangedCodes: string[] = [];

  constructor(
    readonly provider: 'google' | 'github',
    private readonly profile: OAuthUserProfile
  ) {}

  getAuthorizationUrl(state: string): string {
    return `https://provider.example/${this.provider}?state=${encodeURIComponent(state)}`;
  }

  async exchangeCode(code: string): Promise<OAuthUserProfile> {
    this.exchangedCodes.push(code);
    return this.profile;
  }
}

async function startServer(t: TestContext) {
  const adapter = new InMemoryAdapter();
  const crypto = new CryptoEngine('oauth-routes-test-secret');
  const google = new StubOAuthStrategy('google', {
    providerId: 'google-subject',
    email: 'person@example.com',
    emailVerified: true,
  });
  const github = new StubOAuthStrategy('github', {
    providerId: 'github-user',
    email: 'other@example.com',
    emailVerified: true,
  });
  const oauthService = new OAuthService(
    adapter,
    crypto,
    { jwtSecret: 'oauth-routes-test-secret' },
    [google, github]
  );
  const app = express();
  app.use(cookieParser());
  app.use('/api/auth', createOAuthRouter({ oauthService }));
  app.use(authErrorHandler);

  const server = createServer(app);
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  t.after(() => closeServer(server));

  const address = server.address() as AddressInfo;
  return {
    adapter,
    crypto,
    google,
    github,
    url: `http://127.0.0.1:${address.port}`,
  };
}

function closeServer(server: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
    server.closeAllConnections();
  });
}

test('OAuth start and callback routes enforce state and create a refresh-token session', async (t) => {
  const { adapter, crypto, google, github, url } = await startServer(t);
  const googleStart = await fetch(`${url}/api/auth/google`, { redirect: 'manual' });
  assert.equal(googleStart.status, 302);
  const authorizationUrl = new URL(googleStart.headers.get('location') ?? '');
  assert.equal(authorizationUrl.origin, 'https://provider.example');
  assert.equal(authorizationUrl.pathname, '/google');

  const setCookie = googleStart.headers.get('set-cookie') ?? '';
  const state = setCookie.match(/oauth_state_google=([a-f0-9]{64})/)?.[1];
  assert.ok(state);
  assert.match(setCookie, /HttpOnly/i);

  const invalidState = await fetch(
    `${url}/api/auth/google/callback?${new URLSearchParams({ code: 'code', state: '0'.repeat(64) })}`,
    { headers: { cookie: `oauth_state_google=${state}` } }
  );
  assert.equal(invalidState.status, 401);
  assert.deepEqual(google.exchangedCodes, []);

  const googleStartAgain = await fetch(`${url}/api/auth/google`, { redirect: 'manual' });
  const validState = googleStartAgain.headers.get('set-cookie')?.match(/oauth_state_google=([a-f0-9]{64})/)?.[1];
  assert.ok(validState);
  const callback = await fetch(
    `${url}/api/auth/google/callback?${new URLSearchParams({ code: 'google-code', state: validState })}`,
    { headers: { cookie: `oauth_state_google=${validState}` } }
  );

  assert.equal(callback.status, 200);
  const result = (await callback.json()) as { success: boolean; accessToken: string; sessionId: string };
  assert.equal(result.success, true);
  assert.ok(await crypto.verifyAccessToken(result.accessToken));
  assert.ok(await adapter.findSessionById(result.sessionId));
  assert.equal(google.exchangedCodes[0], 'google-code');
  assert.match(callback.headers.get('set-cookie') ?? '', /refreshToken=.*HttpOnly/i);

  const githubStart = await fetch(`${url}/api/auth/github`, { redirect: 'manual' });
  assert.equal(githubStart.status, 302);
  assert.equal(new URL(githubStart.headers.get('location') ?? '').pathname, '/github');
  assert.deepEqual(github.exchangedCodes, []);
});

test('OAuth callback rejects requests without browser-bound state', async (t) => {
  const { google, url } = await startServer(t);
  const response = await fetch(`${url}/api/auth/google/callback?code=google-code&state=${'a'.repeat(64)}`);

  assert.equal(response.status, 401);
  const body = (await response.json()) as { code: AuthError['code'] };
  assert.equal(body.code, 'INVALID_TOKEN');
  assert.deepEqual(google.exchangedCodes, []);
});