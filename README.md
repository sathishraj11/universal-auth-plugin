# universal-auth-plugin

A modular, hexagonal TypeScript authentication plugin. The core exposes framework-neutral authentication services and ports; adapters provide persistence, email, and OAuth integrations; the Express transport provides HTTP routes, validation, rate limiting, and tenant RBAC.

## Architecture

- **Core:** `AuthService`, `OAuthService`, `CryptoEngine`, domain types, and the `StorageAdapter` port.
- **Adapters:** Prisma and in-memory persistence, Google/GitHub OAuth strategies, and console/Resend email providers.
- **Transport:** Express auth/OAuth routes, request validation, sliding-window rate limiting, and tenant role middleware.

## Exports

| Import | Contents | Optional peer dependencies |
| --- | --- | --- |
| `universal-auth-plugin` | Core services, types, configuration, and errors | None |
| `universal-auth-plugin/adapters/prisma` | `PrismaAdapter` | `@prisma/client` |
| `universal-auth-plugin/transport/express` | Express routers, validation, rate limiting, and `requireTenantRole` | `express`, `zod` |
| `universal-auth-plugin/adapters/oauth` | Google and GitHub OAuth strategies | None |
| `universal-auth-plugin/adapters/email` | Console and Resend email providers | None |

## Quick Start

```sh
npm install universal-auth-plugin @prisma/client express zod cookie-parser
npm install --save-dev prisma
```

Copy and apply the included Prisma schema, then instantiate the adapter and mount the auth router:

```sh
cp node_modules/universal-auth-plugin/prisma/schema.prisma prisma/schema.prisma
npx prisma db push
npx prisma generate
```

```ts
import express from 'express';
import cookieParser from 'cookie-parser';
import { AuthService, CryptoEngine } from 'universal-auth-plugin';
import { PrismaAdapter } from 'universal-auth-plugin/adapters/prisma';
import { createAuthRouter } from 'universal-auth-plugin/transport/express';

const storage = new PrismaAdapter();
const crypto = new CryptoEngine(process.env.JWT_ACCESS_SECRET!);
const auth = new AuthService(storage, crypto, {
  jwtSecret: process.env.JWT_ACCESS_SECRET!,
  accessTokenExpiry: '15m',
  refreshTokenExpiryDays: 7,
});
const app = express();
app.use(express.json());
app.use(cookieParser());
app.use('/api/auth', createAuthRouter({ authService: auth, crypto }));
```

See the [Client Implementation Runbook](./RUNBOOK.md) for complete server wiring, environment configuration, tenant RBAC, and pre-deployment checks.
