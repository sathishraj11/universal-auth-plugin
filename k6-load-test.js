import http from 'k6/http';
import { check } from 'k6';
import { Rate, Trend } from 'k6/metrics';

// Intentionally restricted to local development: do not change this target to a public host.
const loginUrl = 'http://127.0.0.1:3000/api/auth/login';
const limitReached = new Rate('login_rate_limit_reached');
const retryAfterPresent = new Rate('retry_after_present');
const invalidCredentialResponses = new Rate('invalid_credential_responses');
const throttledRequestDuration = new Trend('throttled_request_duration');

http.setResponseCallback(http.expectedStatuses(401, 429));

export const options = {
  vus: 1,
  iterations: 1,
  thresholds: {
    http_req_duration: ['p(95)<1000'],
    invalid_credential_responses: ['rate==1'],
    login_rate_limit_reached: ['rate==1'],
    retry_after_present: ['rate==1'],
    throttled_request_duration: ['p(95)<1000'],
  },
};

export default function () {
  const body = JSON.stringify({
    email: `k6-invalid-${__VU}-${__ITER}@example.invalid`,
    password: 'intentionally-incorrect-k6-password',
  });
  const params = {
    headers: { 'Content-Type': 'application/json' },
    tags: { endpoint: 'auth-login', test_type: 'local-rate-limit-check' },
  };

  // Five bad logins are below the configured limit; the sixth must be throttled.
  for (let attempt = 1; attempt <= 6; attempt += 1) {
    const response = http.post(loginUrl, body, params);

    if (attempt < 6) {
      const isInvalidCredentialResponse = response.status === 401;
      invalidCredentialResponses.add(isInvalidCredentialResponse);
      check(response, {
        'login attempt is rejected as invalid credentials': () => isInvalidCredentialResponse,
      });
      continue;
    }

    const retryAfter = Number(response.headers['Retry-After']);
    const isThrottled = response.status === 429;
    const hasRetryAfter = Number.isInteger(retryAfter) && retryAfter > 0;
    limitReached.add(isThrottled);
    retryAfterPresent.add(isThrottled && hasRetryAfter);
    if (isThrottled) throttledRequestDuration.add(response.timings.duration);

    check(response, {
      'sixth login attempt is rate-limited': () => isThrottled,
      '429 response has a positive Retry-After header': () => isThrottled && hasRetryAfter,
    });
  }
}

/*
Local setup:
- Install k6: Windows: winget install k6; macOS: brew install k6; Debian/Ubuntu: use Grafana's k6 apt repository.
- Start or restart the development server on http://127.0.0.1:3000 so its in-memory limiter starts clean.
- From the project root, run: k6 run k6-load-test.js

This intentionally sends only six sequential requests from one VU to loopback.
*/
