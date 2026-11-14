import { NextFunction, Request, Response } from 'express';
import { StorageAdapter } from '../core/adapter.interface';
import { CryptoEngine } from '../core/crypto';
import { OrgRole, TenantAccessTokenPayload } from '../core/types';

export interface TenantRequestContext {
  orgId: string;
  role: OrgRole;
}

const roleWeight: Record<OrgRole, number> = {
  MEMBER: 1,
  ADMIN: 2,
  OWNER: 3,
};

export function requireTenantRole(
  crypto: CryptoEngine,
  adapter: StorageAdapter,
  minimumRole: OrgRole
) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const authorization = req.headers.authorization;
    const match = authorization?.match(/^Bearer\s+([^\s]+)$/i);
    if (!match) {
      res.status(401).json({ success: false, code: 'INVALID_TOKEN', message: 'A bearer token is required.' });
      return;
    }

    let payload: TenantAccessTokenPayload;
    try {
      payload = await crypto.verifyAccessToken(match[1]);
    } catch {
      res.status(401).json({ success: false, code: 'INVALID_TOKEN', message: 'The bearer token is invalid.' });
      return;
    }

    if (!payload.orgId || !payload.role) {
      res.status(403).json({ success: false, code: 'FORBIDDEN', message: 'A tenant-scoped token is required.' });
      return;
    }

    const requestedOrgId = req.params.orgId || req.get('x-organization-id');
    if (requestedOrgId && requestedOrgId !== payload.orgId) {
      res.status(403).json({ success: false, code: 'FORBIDDEN', message: 'Token is scoped to a different organization.' });
      return;
    }

    try {
      const membership = await adapter.findOrganizationMember(payload.userId, payload.orgId);
      if (!membership || roleWeight[membership.role] < roleWeight[minimumRole]) {
        res.status(403).json({ success: false, code: 'FORBIDDEN', message: 'Insufficient organization permissions.' });
        return;
      }

      res.locals.tenant = { orgId: payload.orgId, role: membership.role } satisfies TenantRequestContext;
      res.locals.auth = payload;
      next();
    } catch (error) {
      next(error);
    }
  };
}