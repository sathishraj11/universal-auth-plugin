import express from 'express';
import cookieParser from 'cookie-parser';
import { ConsoleEmailProvider } from './adapters/console-email.provider.js';
import { InMemoryAdapter } from './adapters/memory.adapter.js';
import { GitHubOAuthStrategy } from './adapters/oauth/github.strategy.js';
import { GoogleOAuthStrategy } from './adapters/oauth/google.strategy.js';
import { ResendEmailProvider } from './adapters/resend-email.provider.js';
import { CryptoEngine } from './core/crypto.js';
import { AuthService } from './core/auth.service.js';
import { EmailProvider } from './core/email.interface.js';
import { OAuthStrategy } from './core/oauth.interface.js';
import { OAuthService } from './core/oauth.service.js';
import { createAuthRouter, createAuthGuard, authErrorHandler } from './transport/express.routes.js';
import { createOAuthRouter } from './transport/oauth.middleware.js';

function createEmailProvider(): EmailProvider {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('RESEND_API_KEY is required in production.');
    }
    return new ConsoleEmailProvider();
  }

  const from = process.env.RESEND_FROM_EMAIL;
  if (!from) {
    throw new Error('RESEND_FROM_EMAIL is required when RESEND_API_KEY is set.');
  }
  return new ResendEmailProvider(apiKey, from);
}

function createOAuthStrategies(): OAuthStrategy[] {
  const strategies: OAuthStrategy[] = [];
  const googleClientId = process.env.GOOGLE_CLIENT_ID;
  const googleClientSecret = process.env.GOOGLE_CLIENT_SECRET;
  if (googleClientId || googleClientSecret) {
    if (!googleClientId || !googleClientSecret || !process.env.GOOGLE_REDIRECT_URI) {
      throw new Error('GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, and GOOGLE_REDIRECT_URI are required together.');
    }
    strategies.push(new GoogleOAuthStrategy({
      clientId: googleClientId,
      clientSecret: googleClientSecret,
      redirectUri: process.env.GOOGLE_REDIRECT_URI,
    }));
  }

  const githubClientId = process.env.GITHUB_CLIENT_ID;
  const githubClientSecret = process.env.GITHUB_CLIENT_SECRET;
  if (githubClientId || githubClientSecret) {
    if (!githubClientId || !githubClientSecret || !process.env.GITHUB_REDIRECT_URI) {
      throw new Error('GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, and GITHUB_REDIRECT_URI are required together.');
    }
    strategies.push(new GitHubOAuthStrategy({
      clientId: githubClientId,
      clientSecret: githubClientSecret,
      redirectUri: process.env.GITHUB_REDIRECT_URI,
    }));
  }

  return strategies;
}

const app = express();
app.use(express.json());
app.use(cookieParser());

const storageAdapter = new InMemoryAdapter();
const cryptoEngine = new CryptoEngine(process.env.JWT_SECRET || 'super-secret-jwt-key-change-me');
const emailProvider = createEmailProvider();
const authConfig = {
  jwtSecret: process.env.JWT_SECRET || 'super-secret-jwt-key-change-me',
  accessTokenExpiry: '15m',
  emailVerificationRequired: process.env.EMAIL_VERIFICATION_REQUIRED === 'true',
};
const authService = new AuthService(storageAdapter, cryptoEngine, authConfig, emailProvider);
const oauthService = new OAuthService(storageAdapter, cryptoEngine, authConfig, createOAuthStrategies());

app.use('/api/auth', createAuthRouter({
  authService,
  crypto: cryptoEngine,
  isProduction: process.env.NODE_ENV === 'production',
}));
app.use('/api/auth', createOAuthRouter({
  oauthService,
  isProduction: process.env.NODE_ENV === 'production',
  cookieDomain: process.env.COOKIE_DOMAIN,
}));

const authGuard = createAuthGuard(cryptoEngine);
app.get('/api/protected/profile', authGuard, (req: any, res: any) => {
  res.json({
    success: true,
    message: 'Welcome to the protected dashboard!',
    user: req.user,
  });
});

app.use(authErrorHandler);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Auth plugin server running on port ${PORT}`);
});
