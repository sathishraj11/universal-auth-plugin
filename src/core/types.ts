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
