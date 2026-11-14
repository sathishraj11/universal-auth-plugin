import { OAuthStrategy, OAuthUserProfile } from '../../core/oauth.interface';
import { bearerHeaders, exchangeOAuthCode, requestOAuthJson } from './oauth-http';

export interface GitHubOAuthConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}

export class GitHubOAuthStrategy implements OAuthStrategy {
  readonly provider = 'github' as const;

  constructor(private readonly config: GitHubOAuthConfig) {}

  getAuthorizationUrl(state: string): string {
    const url = new URL('https://github.com/login/oauth/authorize');
    url.search = new URLSearchParams({
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      scope: 'read:user user:email',
      state,
    }).toString();
    return url.toString();
  }

  async exchangeCode(code: string): Promise<OAuthUserProfile> {
    const accessToken = await exchangeOAuthCode(
      'https://github.com/login/oauth/access_token',
      code,
      this.config.clientId,
      this.config.clientSecret,
      this.config.redirectUri
    );
    const headers = {
      ...bearerHeaders(accessToken),
      'X-GitHub-Api-Version': '2022-11-28',
    };
    const [profile, emails] = await Promise.all([
      requestOAuthJson('https://api.github.com/user', { headers }, 'GitHub user profile request failed.'),
      requestOAuthJson('https://api.github.com/user/emails', { headers }, 'GitHub email request failed.'),
    ]);

    if ((typeof profile.id !== 'string' && typeof profile.id !== 'number') || !Array.isArray(emails)) {
      throw new Error('GitHub returned an incomplete user profile.');
    }
    const addresses = emails.filter(
      (entry): entry is Record<string, unknown> =>
        typeof entry === 'object' && entry !== null && !Array.isArray(entry)
    );
    const selected =
      addresses.find((entry) => entry.primary === true && entry.verified === true) ??
      addresses.find((entry) => entry.verified === true);
    const email = selected?.email;
    const fallbackEmail = profile.email;

    if (typeof email !== 'string' && typeof fallbackEmail !== 'string') {
      throw new Error('GitHub did not return an email address.');
    }
    return {
      providerId: String(profile.id),
      email: typeof email === 'string' ? email : fallbackEmail as string,
      emailVerified: typeof email === 'string',
    };
  }
}