import { StorageAdapter } from './adapter.interface';
import { CryptoEngine } from './crypto';
import { EmailProvider } from './email.interface';
import { AuthError } from './errors';
import { AuthPluginConfig, OrgRole, Organization, User, UserOrganization } from './types';

export class AuthService {
  constructor(
    private adapter: StorageAdapter,
    private crypto: CryptoEngine,
    private config: AuthPluginConfig,
    private emailProvider?: EmailProvider
  ) {
    if (config.emailVerificationRequired && !emailProvider) {
      throw new Error('An EmailProvider is required when email verification is enabled.');
    }
  }

  async createOrganization(creatorUserId: string, name: string): Promise<Organization> {
    if (!name.trim()) {
      throw new AuthError('INVALID_CREDENTIALS', 'Organization name is required.', 400);
    }
    const creator = await this.adapter.findUserById(creatorUserId);
    if (!creator) throw new AuthError('USER_NOT_FOUND', 'Organization creator does not exist.', 404);
    return this.adapter.createOrganization(name.trim(), creatorUserId);
  }

  async addOrganizationMember(
    actorUserId: string,
    organizationId: string,
    memberUserId: string,
    role: OrgRole = 'MEMBER'
  ) {
    const actorMembership = await this.adapter.findOrganizationMember(actorUserId, organizationId);
    if (!actorMembership || !['OWNER', 'ADMIN'].includes(actorMembership.role)) {
      throw new AuthError('FORBIDDEN', 'Only organization owners and admins can add members.', 403);
    }
    if (role === 'OWNER' && actorMembership.role !== 'OWNER') {
      throw new AuthError('FORBIDDEN', 'Only an organization owner can assign the OWNER role.', 403);
    }
    const member = await this.adapter.findUserById(memberUserId);
    if (!member) throw new AuthError('USER_NOT_FOUND', 'Organization member does not exist.', 404);
    return this.adapter.addOrganizationMember(memberUserId, organizationId, role);
  }

  async findUserOrganizations(userId: string): Promise<UserOrganization[]> {
    return this.adapter.findUserOrganizations(userId);
  }

  async issueTenantAccessToken(userId: string, organizationId: string): Promise<string> {
    const [user, membership] = await Promise.all([
      this.adapter.findUserById(userId),
      this.adapter.findOrganizationMember(userId, organizationId),
    ]);
    if (!user) throw new AuthError('USER_NOT_FOUND', 'User does not exist.', 404);
    if (!membership) throw new AuthError('FORBIDDEN', 'User is not a member of this organization.', 403);

    return this.crypto.generateAccessToken(
      user.id,
      user.email,
      this.config.accessTokenExpiry || '15m',
      { orgId: organizationId, role: membership.role }
    );
  }

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
      await this.requireEmailProvider().sendVerificationEmail(user.email, rawToken);
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

  async verifyEmail(rawToken: string): Promise<void> {
    const token = await this.adapter.findVerificationToken(
      this.crypto.hashOpaqueToken(rawToken),
      'EMAIL_VERIFICATION'
    );
    if (!token) {
      throw new AuthError('INVALID_TOKEN', 'Invalid or expired email verification token.', 400);
    }

    await this.adapter.updateUserVerification(token.userId, true);
    await this.adapter.deleteUserVerificationTokens(token.userId, 'EMAIL_VERIFICATION');
  }

  async requestPasswordReset(email: string): Promise<void> {
    const emailProvider = this.requireEmailProvider();
    const user = await this.adapter.findUserByEmail(email);
    if (!user) return;

    const { rawToken, tokenHash } = this.crypto.generateOpaqueToken();
    await this.adapter.deleteUserVerificationTokens(user.id, 'PASSWORD_RESET');
    await this.adapter.saveVerificationToken({
      userId: user.id,
      tokenHash,
      purpose: 'PASSWORD_RESET',
      expiresAt: new Date(Date.now() + 60 * 60 * 1000),
    });
    await emailProvider.sendPasswordResetEmail(user.email, rawToken);
  }

  async resetPassword(rawToken: string, newPassword: string): Promise<void> {
    const token = await this.adapter.findVerificationToken(
      this.crypto.hashOpaqueToken(rawToken),
      'PASSWORD_RESET'
    );
    if (!token) {
      throw new AuthError('INVALID_TOKEN', 'Invalid or expired password reset token.', 400);
    }

    const passwordHash = await this.crypto.hashPassword(newPassword);
    await this.adapter.updateUserPassword(token.userId, passwordHash);
    await this.adapter.invalidateAllUserSessions(token.userId);
    await this.adapter.deleteUserVerificationTokens(token.userId, 'PASSWORD_RESET');
  }

  private requireEmailProvider(): EmailProvider {
    if (!this.emailProvider) {
      throw new Error('An EmailProvider is required for email workflows.');
    }
    return this.emailProvider;
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
