import { Request, Response, NextFunction, Router } from 'express';
import { AuthService } from '../core/auth.service';
import { CryptoEngine } from '../core/crypto';
import { AuthError } from '../core/errors';

export interface AuthRouterOptions {
  authService: AuthService;
  crypto: CryptoEngine;
  cookieDomain?: string;
  isProduction?: boolean;
}

export function createAuthRouter(options: AuthRouterOptions): Router {
  const router = Router();
  const { authService, crypto, isProduction = false } = options;

  router.post('/register', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { email, password } = req.body;
      if (!email || !password) {
        throw new AuthError('INVALID_CREDENTIALS', 'Email and password are required.', 400);
      }

      const result = await authService.register(email, password);
      res.status(201).json({
        success: true,
        message: 'User registered successfully.',
        userId: result.user.id,
        verificationToken: result.verificationToken,
      });
    } catch (error) {
      next(error);
    }
  });

  router.post('/login', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { email, password } = req.body;
      const userAgent = req.headers['user-agent'];
      const ipAddress = req.ip;

      const { accessToken, refreshToken } = await authService.login(email, password, userAgent, ipAddress);

      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: isProduction,
        sameSite: 'lax',
        path: '/api/auth',
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      res.json({
        success: true,
        accessToken,
      });
    } catch (error) {
      next(error);
    }
  });

  router.post('/refresh', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const refreshToken = req.cookies?.refreshToken || req.body?.refreshToken;
      const sessionId = req.body?.sessionId;

      if (!refreshToken || !sessionId) {
        throw new AuthError('INVALID_TOKEN', 'Missing refresh token or session identifier.', 401);
      }

      const tokens = await authService.refreshSession(sessionId, refreshToken);

      res.cookie('refreshToken', tokens.refreshToken, {
        httpOnly: true,
        secure: isProduction,
        sameSite: 'lax',
        path: '/api/auth',
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      res.json({
        success: true,
        accessToken: tokens.accessToken,
      });
    } catch (error) {
      next(error);
    }
  });

  return router;
}

export function createAuthGuard(crypto: CryptoEngine) {
  return async (req: Request & { user?: { userId: string; email: string } }, res: Response, next: NextFunction) => {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        throw new AuthError('INVALID_TOKEN', 'Missing or malformed authorization header.', 401);
      }

      const token = authHeader.split(' ')[1];
      const payload = await crypto.verifyAccessToken(token);

      req.user = payload;
      next();
    } catch (error) {
      res.status(401).json({ success: false, message: 'Unauthorized access.' });
    }
  };
}

export function authErrorHandler(err: Error, req: Request, res: Response, next: NextFunction) {
  if (err instanceof AuthError) {
    return res.status(err.statusCode).json({
      success: false,
      code: err.code,
      message: err.message,
    });
  }
  next(err);
}
