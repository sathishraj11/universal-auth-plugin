import { StorageAdapter } from './adapter.interface.js';
import { CryptoEngine } from './crypto.js';
import { AuthError } from './errors.js';
import { OAuthProviderName, OAuthStrategy } from './oauth.interface.js';
import { AuthPluginConfig, User } from './types.js';

export interface OAuthLoginResult {
  user: Pick<User, 'id' | 'email'>;
  accessToken: string;
  refreshToken: string;
  sessionId: string;
  refreshTokenExpiresAt: Date;
}

export class OAuthService {
  private readonly strategies: Partial<Record<OAuthProviderName, OAuthStrategy>>;

  constructor(
    private readonly adapter: StorageAdapter,
    private readonly crypto: CryptoEngine,
    private readonly config: AuthPluginConfig,
    strategies: OAuthStrategy[] = []
  ) {
    this.strategies = Object.fromEntries(strategies.map((strategy) => [strategy.provider, strategy]));
  }

  getAuthorizationUrl(provider: OAuthProviderName, state: string): string {
    return this.getStrategy(provider).getAuthorizationUrl(state);
  }

  async authenticate(
    provider: OAuthProviderName,
    code: string,
    userAgent?: string,
    ipAddress?: string
  ): Promise<OAuthLoginResult> {
    const profile = await this.getStrategy(provider).exchangeCode(code);
    if (!profile.providerId || !profile.email || !profile.emailVerified) {
      throw new AuthError('OAUTH_PROFILE_INVALID', 'The OAuth provider did not return a verified email address.', 401);
    }

    let user = await this.adapter.findUserByEmail(profile.email);
    if (!user) {
      const passwordHash = await this.crypto.hashPassword(this.crypto.generateOpaqueToken().rawToken);
      try {
        user = await this.adapter.createUser({ email: profile.email, passwordHash });
      } catch (error) {
        user = await this.adapter.findUserByEmail(profile.email);
        if (!user) throw error;
      }
    }

    if (!user.emailVerified) {
      await this.adapter.updateUserVerification(user.id, true);
      user = (await this.adapter.findUserById(user.id)) ?? { ...user, emailVerified: true };
    }

    const accessToken = await this.crypto.generateAccessToken(
      user.id,
      user.email,
      this.config.accessTokenExpiry || '15m'
    );
    const { rawToken: refreshToken, tokenHash: refreshTokenHash } = this.crypto.generateOpaqueToken();
    const expiryDays = this.config.refreshTokenExpiryDays || 7;
    const refreshTokenExpiresAt = new Date(Date.now() + expiryDays * 24 * 60 * 60 * 1000);
    const session = await this.adapter.createSession({
      userId: user.id,
      refreshTokenHash,
      userAgent,
      ipAddress,
      expiresAt: refreshTokenExpiresAt,
    });

    return {
      user: { id: user.id, email: user.email },
      accessToken,
      refreshToken,
      sessionId: session.id,
      refreshTokenExpiresAt,
    };
  }

  private getStrategy(provider: OAuthProviderName): OAuthStrategy {
    const strategy = this.strategies[provider];
    if (!strategy) {
      throw new AuthError('OAUTH_PROVIDER_NOT_CONFIGURED', `${provider} login is not configured.`, 503);
    }
    return strategy;
  }
}