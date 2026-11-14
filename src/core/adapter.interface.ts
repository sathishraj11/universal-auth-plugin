import {
  User,
  Session,
  CreateUserDto,
  VerificationToken,
  TokenPurpose,
  Organization,
  OrganizationMember,
  OrgRole,
  UserOrganization,
} from './types.js';

export interface StorageAdapter {
  // User Operations
  findUserById(id: string): Promise<User | null>;
  findUserByEmail(email: string): Promise<User | null>;
  createUser(data: CreateUserDto): Promise<User>;
  updateUserVerification(userId: string, verified: boolean): Promise<void>;
  updateUserPassword(userId: string, newPasswordHash: string): Promise<void>;

  // Session & Refresh Token Operations
  createSession(session: Omit<Session, 'id' | 'createdAt'>): Promise<Session>;
  findSessionById(sessionId: string): Promise<Session | null>;
  rotateSession(sessionId: string, newRefreshTokenHash: string, newExpiresAt: Date): Promise<void>;
  invalidateSession(sessionId: string): Promise<void>;
  invalidateAllUserSessions(userId: string): Promise<void>;

  // Verification & Reset Token Operations
  saveVerificationToken(data: Omit<VerificationToken, 'id' | 'createdAt'>): Promise<VerificationToken>;
  findVerificationToken(tokenHash: string, purpose: TokenPurpose): Promise<VerificationToken | null>;
  deleteVerificationToken(id: string): Promise<void>;
  deleteUserVerificationTokens(userId: string, purpose: TokenPurpose): Promise<void>;

  // Organization and membership operations
  createOrganization(name: string, ownerUserId: string): Promise<Organization>;
  generateUniqueOrganizationSlug(name: string): Promise<string>;
  addOrganizationMember(userId: string, organizationId: string, role: OrgRole): Promise<OrganizationMember>;
  findOrganizationMember(userId: string, organizationId: string): Promise<OrganizationMember | null>;
  findUserOrganizations(userId: string): Promise<UserOrganization[]>;
}
