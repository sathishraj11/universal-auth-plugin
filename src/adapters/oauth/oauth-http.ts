export async function requestOAuthJson(
  url: string,
  init: RequestInit,
  errorMessage: string
): Promise<Record<string, unknown>> {
  let response: Response;
  try {
    response = await fetch(url, init);
  } catch {
    throw new Error(errorMessage);
  }

  if (!response.ok) throw new Error(errorMessage);

  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new Error(errorMessage);
  }

  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    throw new Error(errorMessage);
  }
  return payload as Record<string, unknown>;
}

export async function exchangeOAuthCode(
  tokenUrl: string,
  code: string,
  clientId: string,
  clientSecret: string,
  redirectUri: string
): Promise<string> {
  const token = await requestOAuthJson(
    tokenUrl,
    {
      method: 'POST',
      headers: { accept: 'application/json', 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: redirectUri,
      }),
    },
    'OAuth code exchange failed.'
  );

  if (typeof token.access_token !== 'string' || !token.access_token) {
    throw new Error('OAuth code exchange returned no access token.');
  }
  return token.access_token;
}

export function bearerHeaders(accessToken: string): Record<string, string> {
  return { authorization: `Bearer ${accessToken}`, accept: 'application/json' };
}