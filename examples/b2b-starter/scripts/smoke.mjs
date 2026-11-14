const baseUrl = process.env.BASE_URL ?? 'http://127.0.0.1:4000';
const email = `b2b-smoke-${Date.now()}@example.invalid`;
const password = 'local-smoke-password-2026';

async function postJson(path, body, accessToken) {
  const response = await fetch(`${baseUrl}${path}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...(accessToken ? { authorization: `Bearer ${accessToken}` } : {}),
    },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = { nonJsonResponse: text.slice(0, 300) };
  }
  if (!response.ok) throw new Error(`${path} returned ${response.status}: ${JSON.stringify(json)}`);
  return json;
}

const registration = await postJson('/api/auth/register', { email, password });
console.log('POST /api/auth/register:', JSON.stringify(registration));

const login = await postJson('/api/auth/login', { email, password });
console.log('POST /api/auth/login:', JSON.stringify({ ...login, accessToken: '<redacted>' }));

const organization = await postJson('/api/orgs', { name: `B2B Smoke ${Date.now()}` }, login.accessToken);
console.log('POST /api/orgs:', JSON.stringify({
  organization: organization.organization,
  accessToken: '<redacted>',
}));

const dashboardResponse = await fetch(`${baseUrl}/api/orgs/${organization.organization.id}/dashboard`, {
  headers: { authorization: `Bearer ${organization.accessToken}` },
});
const dashboard = await dashboardResponse.json();
if (!dashboardResponse.ok) {
  throw new Error(`/api/orgs/:orgId/dashboard returned ${dashboardResponse.status}: ${JSON.stringify(dashboard)}`);
}
console.log('GET /api/orgs/:orgId/dashboard:', JSON.stringify(dashboard));
