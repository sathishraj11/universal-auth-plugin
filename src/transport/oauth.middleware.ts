import { randomBytes, timingSafeEqual } from 'node:crypto';
import { NextFunction, Request, Response, Router } from 'express';
import { AuthError } from '../core/errors';
import { OAuthProviderName } from '../core/oauth.interface';
import { OAuthService } from '../core/oauth.service';

export interface OAuthRouterOptions {
  oauthService: OAuthService;
  isProduction?: boolean;
  cookieDomain?: string;
}

const stateCookieMaxAge = 10 * 60 * 1000;

export function createOAuthRouter(options: OAuthRouterOptions): Router {
  const { oauthService, isProduction = false, cookieDomain } = options;
  const router = Router();

  for (const provider of ['google', 'github'] as const) {
    router.get(`/${provider}`, (req: Request, res: Response, next: NextFunction) => {
      try {
        const state = randomBytes(32).toString('hex');
        const authorizationUrl = oauthService.getAuthorizationUrl(provider, state);
        res.cookie(stateCookieName(provider), state, {
          httpOnly: true,
          secure: isProduction,
          sameSite: 'lax',
          path: `/api/auth/${provider}`,
          maxAge: stateCookieMaxAge,
          ...(cookieDomain ? { domain: cookieDomain } : {}),
        });
        res.redirect(authorizationUrl);
      } catch (error) {
        next(error);
      }
    });

    router.get(`/${provider}/callback`, async (req: Request, res: Response, next: NextFunction) => {
      const cookieName = stateCookieName(provider);
      const cookieOptions = {
        path: `/api/auth/${provider}`,
        ...(cookieDomain ? { domain: cookieDomain } : {}),
      };
      res.clearCookie(cookieName, cookieOptions);

      try {
        const code = typeof req.query.code === 'string' ? req.query.code : '';
        const state = typeof req.query.state === 'string' ? req.query.state : '';
        const storedState = req.cookies?.[cookieName];
        if (!code || !state || !validState(state, storedState)) {
          throw new AuthError('INVALID_TOKEN', 'Invalid or missing OAuth state.', 401);
        }
        if (typeof req.query.error === 'string') {
          throw new AuthError('INVALID_CREDENTIALS', 'OAuth authorization was not completed.', 401);
        }

        const result = await oauthService.authenticate(
          provider,
          code,
          req.headers['user-agent'],
          req.ip
        );
        res.cookie('refreshToken', result.refreshToken, {
          httpOnly: true,
          secure: isProduction,
          sameSite: 'lax',
          path: '/api/auth',
          maxAge: Math.max(0, result.refreshTokenExpiresAt.getTime() - Date.now()),
          ...(cookieDomain ? { domain: cookieDomain } : {}),
        });
        res.json({
          success: true,
          accessToken: result.accessToken,
          sessionId: result.sessionId,
          user: result.user,
        });
      } catch (error) {
        next(error);
      }
    });
  }

  return router;
}

function stateCookieName(provider: OAuthProviderName): string {
  return `oauth_state_${provider}`;
}

function validState(state: string, storedState: unknown): storedState is string {
  if (
    typeof storedState !== 'string' ||
    !/^[a-f0-9]{64}$/.test(state) ||
    !/^[a-f0-9]{64}$/.test(storedState)
  ) {
    return false;
  }
  return timingSafeEqual(Buffer.from(state), Buffer.from(storedState));
}