import express from 'express';
import cookieParser from 'cookie-parser';
import { InMemoryAdapter } from './adapters/memory.adapter';
import { CryptoEngine } from './core/crypto';
import { AuthService } from './core/auth.service';
import { createAuthRouter, createAuthGuard, authErrorHandler } from './transport/express.middleware';

const app = express();
app.use(express.json());
app.use(cookieParser());

const storageAdapter = new InMemoryAdapter();
const cryptoEngine = new CryptoEngine(process.env.JWT_SECRET || 'super-secret-jwt-key-change-me');
const authService = new AuthService(storageAdapter, cryptoEngine, {
  jwtSecret: process.env.JWT_SECRET || 'super-secret-jwt-key-change-me',
  accessTokenExpiry: '15m',
  emailVerificationRequired: false,
});

app.use('/api/auth', createAuthRouter({
  authService,
  crypto: cryptoEngine,
  isProduction: process.env.NODE_ENV === 'production',
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
