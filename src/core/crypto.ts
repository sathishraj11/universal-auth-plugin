import * as argon2 from '@node-rs/argon2';
import * as jose from 'jose';
import { createHash, randomBytes } from 'crypto';
import { OrgRole, TenantAccessTokenPayload } from './types';

export interface TenantTokenClaims {
  orgId: string;
  role: OrgRole;
}

export class CryptoEngine {
  constructor(private jwtSecret: string) {}

  async hashPassword(password: string): Promise<string> {
    return await argon2.hash(password, {
      memoryCost: 19456,
      timeCost: 2,
      outputLen: 32,
      parallelism: 1,
    });
  }

  async verifyPassword(password: string, hash: string): Promise<boolean> {
    try {
      return await argon2.verify(hash, password);
    } catch {
      return false;
    }
  }

  async generateAccessToken(
    userId: string,
    email: string,
    expiresIn: string = '15m',
    tenant?: TenantTokenClaims
  ): Promise<string> {
    const secretKey = new TextEncoder().encode(this.jwtSecret);
    return await new jose.SignJWT({ sub: userId, email, ...tenant })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setExpirationTime(expiresIn)
      .sign(secretKey);
  }

  async verifyAccessToken(token: string): Promise<TenantAccessTokenPayload> {
    const secretKey = new TextEncoder().encode(this.jwtSecret);
    const { payload } = await jose.jwtVerify(token, secretKey);
    const role = isOrgRole(payload.role) ? payload.role : undefined;
    return {
      userId: payload.sub as string,
      email: payload.email as string,
      ...(typeof payload.orgId === 'string' ? { orgId: payload.orgId } : {}),
      ...(role ? { role } : {}),
    };
  }

  generateOpaqueToken(): { rawToken: string; tokenHash: string } {
    const rawToken = randomBytes(32).toString('hex');
    const tokenHash = createHash('sha256').update(rawToken).digest('hex');
    return { rawToken, tokenHash };
  }

  hashOpaqueToken(rawToken: string): string {
    return createHash('sha256').update(rawToken).digest('hex');
  }
}

function isOrgRole(role: unknown): role is OrgRole {
  return role === 'OWNER' || role === 'ADMIN' || role === 'MEMBER';
}
