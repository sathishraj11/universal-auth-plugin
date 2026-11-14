import { EmailProvider } from '../core/email.interface';

export class ConsoleEmailProvider implements EmailProvider {
  async sendVerificationEmail(email: string, token: string): Promise<void> {
    console.info(`[auth] Email verification token for ${email}: ${token}`);
  }

  async sendPasswordResetEmail(email: string, token: string): Promise<void> {
    console.info(`[auth] Password reset token for ${email}: ${token}`);
  }
}