import { StorageAdapter } from '../core/adapter.interface';
import {
  CreateUserDto,
  Session,
  User,
  VerificationToken,
  TokenPurpose,
  Organization,
  OrganizationMember,
  OrgRole,
  UserOrganization,
} from '../core/types';

export class InMemoryAdapter implements StorageAdapter {
  private users: Map<string, User> = new Map();
  private sessions: Map<string, Session> = new Map();
  private tokens: Map<string, VerificationToken> = new Map();
  private organizations: Map<string, Organization> = new Map();
  private organizationMembers: Map<string, OrganizationMember> = new Map();

  async findUserById(id: string): Promise<User | null> {
    return this.users.get(id) || null;
  }

  async findUserByEmail(email: string): Promise<User | null> {
    for (const user of this.users.values()) {
      if (user.email === email) return user;
    }
    return null;
  }

  async createUser(data: CreateUserDto): Promise<User> {
    const id = Math.random().toString(36).substring(2);
    const user: User = {
      id,
      email: data.email,
      passwordHash: data.passwordHash,
      emailVerified: false,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    this.users.set(id, user);
    return user;
  }

  async updateUserVerification(userId: string, verified: boolean): Promise<void> {
    const user = this.users.get(userId);
    if (user) {
      user.emailVerified = verified;
      user.updatedAt = new Date();
    }
  }

  async updateUserPassword(userId: string, newPasswordHash: string): Promise<void> {
    const user = this.users.get(userId);
    if (user) {
      user.passwordHash = newPasswordHash;
      user.updatedAt = new Date();
    }
  }

  async createSession(data: Omit<Session, 'id' | 'createdAt'>): Promise<Session> {
    const id = Math.random().toString(36).substring(2);
    const session: Session = { id, createdAt: new Date(), ...data };
    this.sessions.set(id, session);
    return session;
  }

  async findSessionById(sessionId: string): Promise<Session | null> {
    return this.sessions.get(sessionId) || null;
  }

  async rotateSession(sessionId: string, newRefreshTokenHash: string, newExpiresAt: Date): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (session) {
      session.refreshTokenHash = newRefreshTokenHash;
      session.expiresAt = newExpiresAt;
    }
  }

  async invalidateSession(sessionId: string): Promise<void> {
    this.sessions.delete(sessionId);
  }

  async invalidateAllUserSessions(userId: string): Promise<void> {
    for (const [id, session] of this.sessions.entries()) {
      if (session.userId === userId) this.sessions.delete(id);
    }
  }

  async saveVerificationToken(data: Omit<VerificationToken, 'id' | 'createdAt'>): Promise<VerificationToken> {
    const id = Math.random().toString(36).substring(2);
    const token: VerificationToken = { id, createdAt: new Date(), ...data };
    this.tokens.set(token.tokenHash, token);
    return token;
  }

  async findVerificationToken(tokenHash: string, purpose: TokenPurpose): Promise<VerificationToken | null> {
    const token = this.tokens.get(tokenHash);
    if (!token || token.purpose !== purpose || token.expiresAt < new Date()) return null;
    return token;
  }

  async deleteVerificationToken(id: string): Promise<void> {
    for (const [hash, token] of this.tokens.entries()) {
      if (token.id === id) {
        this.tokens.delete(hash);
        break;
      }
    }
  }

  async deleteUserVerificationTokens(userId: string, purpose: TokenPurpose): Promise<void> {
    for (const [hash, token] of this.tokens.entries()) {
      if (token.userId === userId && token.purpose === purpose) {
        this.tokens.delete(hash);
      }
    }
  }

  async createOrganization(name: string, ownerUserId: string): Promise<Organization> {
    if (!this.users.has(ownerUserId)) throw new Error('Organization owner does not exist.');
    const now = new Date();
    const organization: Organization = {
      id: Math.random().toString(36).substring(2),
      name,
      slug: await this.generateUniqueOrganizationSlug(name),
      createdAt: now,
      updatedAt: now,
    };
    this.organizations.set(organization.id, organization);
    await this.addOrganizationMember(ownerUserId, organization.id, 'OWNER');
    return organization;
  }

  async generateUniqueOrganizationSlug(name: string): Promise<string> {
    const baseSlug = name.normalize('NFKD')
      .replace(/[\u0300-\u036f]/g, '')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-|-$/g, '') || 'organization';
    const existingSlugs = new Set([...this.organizations.values()].map(({ slug }) => slug));
    let slug = baseSlug;
    let suffix = 2;
    while (existingSlugs.has(slug)) slug = `${baseSlug}-${suffix++}`;
    return slug;
  }

  async addOrganizationMember(
    userId: string,
    organizationId: string,
    role: OrgRole
  ): Promise<OrganizationMember> {
    if (!this.users.has(userId)) throw new Error('Organization member does not exist.');
    if (!this.organizations.has(organizationId)) throw new Error('Organization does not exist.');
    const key = `${userId}:${organizationId}`;
    if (this.organizationMembers.has(key)) throw new Error('User is already a member of this organization.');

    const now = new Date();
    const member: OrganizationMember = {
      id: Math.random().toString(36).substring(2),
      userId,
      organizationId,
      role,
      createdAt: now,
      updatedAt: now,
    };
    this.organizationMembers.set(key, member);
    return member;
  }

  async findOrganizationMember(userId: string, organizationId: string): Promise<OrganizationMember | null> {
    return this.organizationMembers.get(`${userId}:${organizationId}`) ?? null;
  }

  async findUserOrganizations(userId: string): Promise<UserOrganization[]> {
    const memberships: UserOrganization[] = [];
    for (const member of this.organizationMembers.values()) {
      if (member.userId !== userId) continue;
      const organization = this.organizations.get(member.organizationId);
      if (organization) memberships.push({ organization, role: member.role });
    }
    return memberships;
  }
}
