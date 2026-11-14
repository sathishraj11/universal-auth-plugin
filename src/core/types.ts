export interface User {
  id: string;
  email: string;
  passwordHash: string;
  emailVerified: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface Session {
  id: string;
  userId: string;
  refreshTokenHash: string;
  userAgent?: string;
  ipAddress?: string;
  expiresAt: Date;
  createdAt: Date;
}

export interface CreateUserDto {
  email: string;
  passwordHash: string;
}

export interface AuthPluginConfig {
  jwtSecret: string;
  accessTokenExpiry?: string;
  refreshTokenExpiryDays?: number;
  emailVerificationRequired?: boolean;
}

export type TokenPurpose = 'EMAIL_VERIFICATION' | 'PASSWORD_RESET';

export interface VerificationToken {
  id: string;
  userId: string;
  tokenHash: string;
  purpose: TokenPurpose;
  expiresAt: Date;
  createdAt: Date;
}

export type OrgRole = 'OWNER' | 'ADMIN' | 'MEMBER';

export interface Organization {
  id: string;
  name: string;
  slug: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface OrganizationMember {
  id: string;
  userId: string;
  organizationId: string;
  role: OrgRole;
  createdAt: Date;
  updatedAt: Date;
}

export interface UserOrganization {
  organization: Organization;
  role: OrgRole;
}

export interface TenantAccessTokenPayload {
  userId: string;
  email: string;
  orgId?: string;
  role?: OrgRole;
}
