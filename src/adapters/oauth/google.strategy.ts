import { OAuthStrategy, OAuthUserProfile } from '../../core/oauth.interface';
import { bearerHeaders, exchangeOAuthCode, requestOAuthJson } from './oauth-http';

export interface GoogleOAuthConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}

export class GoogleOAuthStrategy implements OAuthStrategy {
  readonly provider = 'google' as const;

  constructor(private readonly config: GoogleOAuthConfig) {}

  getAuthorizationUrl(state: string): string {
    const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
    url.search = new URLSearchParams({
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      response_type: 'code',
      scope: 'openid email profile',
      state,
    }).toString();
    return url.toString();
  }

  async exchangeCode(code: string): Promise<OAuthUserProfile> {
    const accessToken = await exchangeOAuthCode(
      'https://oauth2.googleapis.com/token',
      code,
      this.config.clientId,
      this.config.clientSecret,
      this.config.redirectUri
    );
    const profile = await requestOAuthJson(
      'https://openidconnect.googleapis.com/v1/userinfo',
      { headers: bearerHeaders(accessToken) },
      'Google user profile request failed.'
    );

    if (typeof profile.sub !== 'string' || typeof profile.email !== 'string') {
      throw new Error('Google returned an incomplete user profile.');
    }
    return {
      providerId: profile.sub,
      email: profile.email,
      emailVerified: profile.email_verified === true,
    };
  }
}