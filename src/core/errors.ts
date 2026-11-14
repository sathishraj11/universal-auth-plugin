export type AuthErrorCode =
  | 'USER_ALREADY_EXISTS'
  | 'INVALID_CREDENTIALS'
  | 'USER_NOT_FOUND'
  | 'FORBIDDEN'
  | 'EMAIL_NOT_VERIFIED'
  | 'INVALID_TOKEN'
  | 'TOKEN_EXPIRED'
  | 'SESSION_REVOKED'
  | 'OAUTH_PROVIDER_NOT_CONFIGURED'
  | 'OAUTH_PROFILE_INVALID'
  | 'RATE_LIMIT_EXCEEDED';

export class AuthError extends Error {
  constructor(public code: AuthErrorCode, message: string, public statusCode: number = 400) {
    super(message);
    this.name = 'AuthError';
  }
}
