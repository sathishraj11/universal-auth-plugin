import { NextFunction, Request, RequestHandler, Response } from 'express';
import { z } from 'zod';

export const registerBodySchema = z.object({
  email: z.string().trim().email().max(254),
  password: z.string().min(8).max(128),
}).strict();

export const loginBodySchema = z.object({
  email: z.string().trim().email().max(254),
  password: z.string().min(1).max(128),
}).strict();

export const refreshBodySchema = z.object({
  sessionId: z.string().trim().min(1).max(256),
  refreshToken: z.string().trim().min(1).max(512).optional(),
}).strict();

export const verifyEmailBodySchema = z.object({
  token: z.string().trim().min(1).max(512),
}).strict();

export const forgotPasswordBodySchema = z.object({
  email: z.string().trim().email().max(254),
}).strict();

export const resetPasswordBodySchema = z.object({
  token: z.string().trim().min(1).max(512),
  newPassword: z.string().min(8).max(128),
}).strict();

export function sendValidationError(res: Response, errors: Array<{ field: string; message: string }>): void {
  res.status(400).json({
    success: false,
    code: 'VALIDATION_ERROR',
    message: 'Request validation failed.',
    errors,
  });
}

export function validateRequest(schema: z.ZodType): RequestHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    const result = schema.safeParse(req.body);
    if (!result.success) {
      sendValidationError(res, result.error.issues.map((issue) => ({
        field: issue.path.length > 0 ? issue.path.map(String).join('.') : 'body',
        message: issue.message,
      })));
      return;
    }

    req.body = result.data;
    next();
  };
}

export const validateBody = validateRequest;