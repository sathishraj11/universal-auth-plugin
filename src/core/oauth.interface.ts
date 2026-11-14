export type OAuthProviderName = 'google' | 'github';

export interface OAuthUserProfile {
  providerId: string;
  email: string;
  emailVerified: boolean;
}

export interface OAuthStrategy {
  readonly provider: OAuthProviderName;
  getAuthorizationUrl(state: string): string;
  exchangeCode(code: string): Promise<OAuthUserProfile>;
}