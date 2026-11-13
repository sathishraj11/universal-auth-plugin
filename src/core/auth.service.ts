import { StorageAdapter } from './adapter.interface';
import { CryptoEngine } from './crypto';
import { AuthError } from './errors';
import { AuthPluginConfig, User } from './types';

export class AuthService {
  constructor(
    private adapter: StorageAdapter,
    private crypto: CryptoEngine,
    private config: AuthPluginConfig
  ) {}

  async register(email: string, passwordPlain: string): Promise<{ user: User; verificationToken?: string }> {
    const existing = await this.adapter.findUserByEmail(email);
    if (existing) {
      throw new AuthError('USER_ALREADY_EXISTS', 'An account with this email already exists.', 409);
    }

    const passwordHash = await this.crypto.hashPassword(passwordPlain);
    const user = await this.adapter.createUser({ email, passwordHash });

    let rawVerificationToken: string | undefined;
    if (this.config.emailVerificationRequired) {
      const { rawToken, tokenHash } = this.crypto.generateOpaqueToken();
      rawVerificationToken = rawToken;
      const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
      
      await this.adapter.saveVerificationToken({
        userId: user.id,
        tokenHash,
        purpose: 'EMAIL_VERIFICATION',
        expiresAt,
      });
    }

    return { user, verificationToken: rawVerificationToken };
  }

  async login(email: string, passwordPlain: string, userAgent?: string, ipAddress?: string): Promise<{ accessToken: string; refreshToken: string }> {
    const user = await this.adapter.findUserByEmail(email);
    if (!user) {
      throw new AuthError('INVALID_CREDENTIALS', 'Invalid email or password.', 401);
    }

    const isValid = await this.crypto.verifyPassword(passwordPlain, user.passwordHash);
    if (!isValid) {
      throw new AuthError('INVALID_CREDENTIALS', 'Invalid email or password.', 401);
    }

    if (this.config.emailVerificationRequired && !user.emailVerified) {
      throw new AuthError('EMAIL_NOT_VERIFIED', 'Please verify your email address before logging in.', 403);
    }

    const accessToken = await this.crypto.generateAccessToken(user.id, user.email, this.config.accessTokenExpiry || '15m');
    const { rawToken: refreshToken, tokenHash: refreshTokenHash } = this.crypto.generateOpaqueToken();

    const expiryDays = this.config.refreshTokenExpiryDays || 7;
    const expiresAt = new Date(Date.now() + expiryDays * 24 * 60 * 60 * 1000);

    await this.adapter.createSession({
      userId: user.id,
      refreshTokenHash,
      userAgent,
      ipAddress,
      expiresAt,
    });

    return { accessToken, refreshToken };
  }

  async refreshSession(sessionId: string, rawRefreshToken: string): Promise<{ accessToken: string; refreshToken: string }> {
    const session = await this.adapter.findSessionById(sessionId);
    if (!session || session.expiresAt < new Date()) {
      throw new AuthError('SESSION_REVOKED', 'Session expired or invalid.', 401);
    }

    const providedHash = this.crypto.hashOpaqueToken(rawRefreshToken);
    if (providedHash !== session.refreshTokenHash) {
      await this.adapter.invalidateSession(sessionId);
      throw new AuthError('INVALID_TOKEN', 'Security violation: Refresh token mismatch.', 401);
    }

    const user = await this.adapter.findUserById(session.userId);
    if (!user) {
      throw new AuthError('USER_NOT_FOUND', 'User no longer exists.', 401);
    }

    const accessToken = await this.crypto.generateAccessToken(user.id, user.email, this.config.accessTokenExpiry || '15m');
    const { rawToken: newRawRefresh, tokenHash: newRefreshHash } = this.crypto.generateOpaqueToken();
    const expiryDays = this.config.refreshTokenExpiryDays || 7;
    const newExpiresAt = new Date(Date.now() + expiryDays * 24 * 60 * 60 * 1000);

    await this.adapter.rotateSession(session.id, newRefreshHash, newExpiresAt);

    return { accessToken, refreshToken: newRawRefresh };
  }
}
