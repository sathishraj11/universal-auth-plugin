import { NextFunction, Request, Response } from 'express';

export interface RateLimitResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  resetAt: number;
}

export interface RateLimitStore {
  consume(key: string, now: number, windowMs: number, limit: number): Promise<RateLimitResult>;
}

export interface RateLimitOptions {
  limit: number;
  windowMs: number;
  keyPrefix: string;
  store: RateLimitStore;
  keyGenerator?: (req: Request) => string;
}

interface WindowEntry {
  timestamps: number[];
  expiresAt: number;
}

export class InMemoryRateLimitStore implements RateLimitStore {
  private readonly entries = new Map<string, WindowEntry>();
  private readonly cleanupTimer: ReturnType<typeof setInterval>;

  constructor(cleanupIntervalMs = 60_000) {
    this.cleanupTimer = setInterval(() => this.cleanupExpired(), cleanupIntervalMs);
    this.cleanupTimer.unref?.();
  }

  async consume(key: string, now: number, windowMs: number, limit: number): Promise<RateLimitResult> {
    const cutoff = now - windowMs;
    const active = (this.entries.get(key)?.timestamps ?? []).filter((timestamp) => timestamp > cutoff);
    const resetAt = active.length > 0 ? active[0] + windowMs : now + windowMs;
    const allowed = active.length < limit;

    if (allowed) active.push(now);
    if (active.length > 0) {
      this.entries.set(key, {
        timestamps: active,
        expiresAt: active[active.length - 1] + windowMs,
      });
    } else {
      this.entries.delete(key);
    }

    return {
      allowed,
      limit,
      remaining: Math.max(0, limit - active.length),
      resetAt,
    };
  }

  cleanupExpired(now = Date.now()): void {
    for (const [key, entry] of this.entries) {
      if (entry.expiresAt <= now) this.entries.delete(key);
    }
  }
}

export const AUTH_RATE_LIMIT_PRESETS = {
  register: { limit: 10, windowMs: 60 * 60 * 1000 },
  login: { limit: 5, windowMs: 15 * 60 * 1000 },
  forgotPassword: { limit: 5, windowMs: 15 * 60 * 1000 },
  resetPassword: { limit: 5, windowMs: 15 * 60 * 1000 },
} as const;

export function createRateLimiter(options: RateLimitOptions) {
  if (!Number.isInteger(options.limit) || options.limit < 1 || options.windowMs < 1) {
    throw new RangeError('Rate limit and window duration must be positive values.');
  }
  const keyGenerator = options.keyGenerator ?? ((req: Request) => req.ip || 'unknown');

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const now = Date.now();
      const key = `${options.keyPrefix}:${keyGenerator(req)}`;
      const result = await options.store.consume(key, now, options.windowMs, options.limit);
      res.setHeader('RateLimit-Limit', String(result.limit));
      res.setHeader('RateLimit-Remaining', String(result.remaining));
      res.setHeader('RateLimit-Reset', String(Math.ceil(result.resetAt / 1000)));

      if (!result.allowed) {
        res.setHeader('Retry-After', String(Math.max(1, Math.ceil((result.resetAt - now) / 1000))));
        res.status(429).json({
          success: false,
          code: 'RATE_LIMIT_EXCEEDED',
          message: 'Too many requests. Please try again later.',
        });
        return;
      }
      next();
    } catch (error) {
      next(error);
    }
  };
}

export function createAuthRateLimiter(
  endpoint: keyof typeof AUTH_RATE_LIMIT_PRESETS,
  store: RateLimitStore
) {
  return createRateLimiter({
    ...AUTH_RATE_LIMIT_PRESETS[endpoint],
    keyPrefix: endpoint,
    store,
  });
}

export const createRateLimitMiddleware = createRateLimiter;