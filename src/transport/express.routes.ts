import { NextFunction, Request, Response, Router } from 'express';
import { AuthService } from '../core/auth.service';
import { CryptoEngine } from '../core/crypto';
import { AuthError } from '../core/errors';
import { InMemoryRateLimitStore, RateLimitStore, createAuthRateLimiter } from './rate-limiter';
import {
  forgotPasswordBodySchema,
  loginBodySchema,
  refreshBodySchema,
  registerBodySchema,
  resetPasswordBodySchema,
  sendValidationError,
  validateRequest,
  verifyEmailBodySchema,
} from './validation';

export interface AuthRouterOptions {
  authService: AuthService;
  crypto: CryptoEngine;
  cookieDomain?: string;
  isProduction?: boolean;
  rateLimitStore?: RateLimitStore;
}

export function createAuthRouter(options: AuthRouterOptions): Router {
  const router = Router();
  const {
    authService,
    crypto,
    cookieDomain,
    isProduction = process.env.NODE_ENV === 'production',
    rateLimitStore = new InMemoryRateLimitStore(),
  } = options;

  router.post('/register', createAuthRateLimiter('register', rateLimitStore), validateRequest(registerBodySchema), async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { email, password } = req.body;
      const result = await authService.register(email, password);
      res.status(201).json({
        success: true,
        message: 'User registered successfully.',
        userId: result.user.id,
      });
    } catch (error) {
      next(error);
    }
  });

  router.post('/login', createAuthRateLimiter('login', rateLimitStore), validateRequest(loginBodySchema), async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { email, password } = req.body;
      const { accessToken, refreshToken } = await authService.login(
        email,
        password,
        req.headers['user-agent'],
        req.ip
      );
      res.cookie('refreshToken', refreshToken, refreshCookieOptions(isProduction, cookieDomain));
      res.json({ success: true, accessToken });
    } catch (error) {
      next(error);
    }
  });

  router.post('/refresh', validateRequest(refreshBodySchema), async (req: Request, res: Response, next: NextFunction) => {
    try {
      const refreshToken = req.cookies?.refreshToken || req.body?.refreshToken;
      const { sessionId } = req.body;
      if (!refreshToken) {
        sendValidationError(res, [{
          field: 'refreshToken',
          message: 'A refresh token is required in the body or cookie.',
        }]);
        return;
      }

      const tokens = await authService.refreshSession(sessionId, refreshToken);
      res.cookie('refreshToken', tokens.refreshToken, refreshCookieOptions(isProduction, cookieDomain));
      res.json({ success: true, accessToken: tokens.accessToken });
    } catch (error) {
      next(error);
    }
  });

  router.post('/verify-email', validateRequest(verifyEmailBodySchema), async (req: Request, res: Response, next: NextFunction) => {
    try {
      await authService.verifyEmail(req.body.token);
      res.json({ success: true, message: 'Email verified successfully.' });
    } catch (error) {
      next(error);
    }
  });

  router.post('/forgot-password', createAuthRateLimiter('forgotPassword', rateLimitStore), validateRequest(forgotPasswordBodySchema), async (req: Request, res: Response, next: NextFunction) => {
    try {
      await authService.requestPasswordReset(req.body.email);
      res.json({
        success: true,
        message: 'If an account exists for this email, password reset instructions will be sent.',
      });
    } catch (error) {
      next(error);
    }
  });

  router.post('/reset-password', createAuthRateLimiter('resetPassword', rateLimitStore), validateRequest(resetPasswordBodySchema), async (req: Request, res: Response, next: NextFunction) => {
    try {
      await authService.resetPassword(req.body.token, req.body.newPassword);
      res.json({ success: true, message: 'Password reset successfully.' });
    } catch (error) {
      next(error);
    }
  });

  return router;
}

function refreshCookieOptions(isProduction: boolean, cookieDomain?: string) {
  return {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'lax' as const,
    path: '/api/auth',
    maxAge: 7 * 24 * 60 * 60 * 1000,
    ...(cookieDomain ? { domain: cookieDomain } : {}),
  };
}

export function createAuthGuard(crypto: CryptoEngine) {
  return async (req: Request & { user?: { userId: string; email: string } }, res: Response, next: NextFunction) => {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        throw new AuthError('INVALID_TOKEN', 'Missing or malformed authorization header.', 401);
      }
      req.user = await crypto.verifyAccessToken(authHeader.split(' ')[1]);
      next();
    } catch {
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