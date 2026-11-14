import { OrgRole as PrismaOrgRole, PrismaClient } from '@prisma/client';
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

export class PrismaAdapter implements StorageAdapter {
  constructor(private readonly prisma: PrismaClient = new PrismaClient()) {}

  async findUserById(id: string): Promise<User | null> {
    const user = await this.prisma.user.findUnique({ where: { id } });
    return user;
  }

  async findUserByEmail(email: string): Promise<User | null> {
    const user = await this.prisma.user.findUnique({ where: { email } });
    return user;
  }

  async createUser(data: CreateUserDto): Promise<User> {
    return this.prisma.user.create({ data });
  }

  async updateUserVerification(userId: string, verified: boolean): Promise<void> {
    await this.prisma.user.updateMany({
      where: { id: userId },
      data: { emailVerified: verified },
    });
  }

  async updateUserPassword(userId: string, newPasswordHash: string): Promise<void> {
    await this.prisma.user.updateMany({
      where: { id: userId },
      data: { passwordHash: newPasswordHash },
    });
  }

  async createSession(data: Omit<Session, 'id' | 'createdAt'>): Promise<Session> {
    const session = await this.prisma.session.create({
      data: {
        ...data,
        userAgent: data.userAgent ?? null,
        ipAddress: data.ipAddress ?? null,
      },
    });
    return this.toSession(session);
  }

  async findSessionById(sessionId: string): Promise<Session | null> {
    const session = await this.prisma.session.findUnique({ where: { id: sessionId } });
    return session ? this.toSession(session) : null;
  }

  async rotateSession(sessionId: string, newRefreshTokenHash: string, newExpiresAt: Date): Promise<void> {
    await this.prisma.session.updateMany({
      where: { id: sessionId },
      data: { refreshTokenHash: newRefreshTokenHash, expiresAt: newExpiresAt },
    });
  }

  async invalidateSession(sessionId: string): Promise<void> {
    await this.prisma.session.deleteMany({ where: { id: sessionId } });
  }

  async invalidateAllUserSessions(userId: string): Promise<void> {
    await this.prisma.session.deleteMany({ where: { userId } });
  }

  async saveVerificationToken(
    data: Omit<VerificationToken, 'id' | 'createdAt'>
  ): Promise<VerificationToken> {
    return this.prisma.verificationToken.create({ data });
  }

  async findVerificationToken(tokenHash: string, purpose: TokenPurpose): Promise<VerificationToken | null> {
    return this.prisma.verificationToken.findFirst({
      where: { tokenHash, purpose, expiresAt: { gt: new Date() } },
    });
  }

  async deleteVerificationToken(id: string): Promise<void> {
    await this.prisma.verificationToken.deleteMany({ where: { id } });
  }

  async deleteUserVerificationTokens(userId: string, purpose: TokenPurpose): Promise<void> {
    await this.prisma.verificationToken.deleteMany({ where: { userId, purpose } });
  }

  async createOrganization(name: string, ownerUserId: string): Promise<Organization> {
    for (let attempt = 0; attempt < 5; attempt += 1) {
      const slug = await this.generateUniqueOrganizationSlug(name);
      try {
        return await this.prisma.$transaction(async (transaction) => {
          const organization = await transaction.organization.create({ data: { name, slug } });
          await transaction.organizationMember.create({
            data: {
              userId: ownerUserId,
              organizationId: organization.id,
              role: PrismaOrgRole.OWNER,
            },
          });
          return organization;
        });
      } catch (error) {
        if (!isPrismaUniqueConstraintError(error)) throw error;
      }
    }
    throw new Error('Could not generate a unique organization slug.');
  }

  async generateUniqueOrganizationSlug(name: string): Promise<string> {
    const baseSlug = slugify(name) || 'organization';
    let slug = baseSlug;
    let suffix = 2;
    while (await this.prisma.organization.findUnique({ where: { slug }, select: { id: true } })) {
      slug = `${baseSlug}-${suffix++}`;
    }
    return slug;
  }

  async addOrganizationMember(
    userId: string,
    organizationId: string,
    role: OrgRole
  ): Promise<OrganizationMember> {
    return this.prisma.organizationMember.create({
      data: { userId, organizationId, role: role as PrismaOrgRole },
    });
  }

  async findOrganizationMember(userId: string, organizationId: string): Promise<OrganizationMember | null> {
    return this.prisma.organizationMember.findUnique({
      where: { userId_organizationId: { userId, organizationId } },
    });
  }

  async findUserOrganizations(userId: string): Promise<UserOrganization[]> {
    const memberships = await this.prisma.organizationMember.findMany({
      where: { userId },
      include: { organization: true },
      orderBy: { createdAt: 'asc' },
    });
    return memberships.map(({ organization, role }) => ({
      organization,
      role: role as OrgRole,
    }));
  }

  private toSession(session: {
    id: string;
    userId: string;
    refreshTokenHash: string;
    userAgent: string | null;
    ipAddress: string | null;
    expiresAt: Date;
    createdAt: Date;
  }): Session {
    return {
      ...session,
      userAgent: session.userAgent ?? undefined,
      ipAddress: session.ipAddress ?? undefined,
    };
  }
}

function slugify(name: string): string {
  return name.normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '');
}

function isPrismaUniqueConstraintError(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === 'P2002';
}