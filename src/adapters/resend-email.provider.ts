import { Resend } from 'resend';
import { EmailProvider } from '../core/email.interface.js';

export class ResendEmailProvider implements EmailProvider {
  private readonly resend: Resend;

  constructor(apiKey: string, private readonly from: string) {
    this.resend = new Resend(apiKey);
  }

  async sendVerificationEmail(email: string, token: string): Promise<void> {
    const { error } = await this.resend.emails.send({
      from: this.from,
      to: email,
      subject: 'Verify your email address',
      text: `Use this token to verify your email address: ${token}`,
    });
    if (error) throw new Error(`Failed to send verification email: ${error.message}`);
  }

  async sendPasswordResetEmail(email: string, token: string): Promise<void> {
    const { error } = await this.resend.emails.send({
      from: this.from,
      to: email,
      subject: 'Reset your password',
      text: `Use this token to reset your password: ${token}`,
    });
    if (error) throw new Error(`Failed to send password reset email: ${error.message}`);
  }
}