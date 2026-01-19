import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import nodemailer from 'nodemailer';

@Injectable()
export class EmailService {
  private readonly logger = new Logger(EmailService.name);
  private transporter: nodemailer.Transporter;

  constructor(private readonly config: ConfigService) {
    const host = this.config.get<string>('MAIL_HOST');
    const portRaw = this.config.get<string>('MAIL_PORT');
    const port = portRaw ? Number(portRaw) : NaN;
    const secure = this.config.get<string>('MAIL_SECURE') === 'true';
    const user = this.config.get<string>('MAIL_USER');
    const pass = this.config.get<string>('MAIL_PASS');
    const frontendUrl = this.config.get<string>('FRONTEND_URL');

    const isProd = this.config.get<string>('NODE_ENV') === 'production';

    if (isProd) {
      const missing: string[] = [];
      if (!frontendUrl) missing.push('FRONTEND_URL');
      if (!host) missing.push('MAIL_HOST');
      if (!portRaw || Number.isNaN(port)) missing.push('MAIL_PORT');
      if (!user) missing.push('MAIL_USER');
      if (!pass) missing.push('MAIL_PASS');

      if (missing.length > 0) {
        // Fail-fast: no arrancar en prod si faltan envs clave
        throw new Error(
          `Email misconfigured for production. Missing/invalid: ${missing.join(
            ', ',
          )}`,
        );
      }
    }

    // En DEV permitimos que falte config (para no romperte el dev),
    // pero si llamás a sendMail sin config, va a fallar al enviar.
    this.transporter = nodemailer.createTransport({
      host,
      port,
      secure,
      auth: user && pass ? { user, pass } : undefined,
    });
  }

  async sendMail(params: {
    to: string;
    subject: string;
    html: string;
    text?: string;
  }) {
    const host = this.config.get<string>('MAIL_HOST');
    const port = this.config.get<string>('MAIL_PORT');
    const user = this.config.get<string>('MAIL_USER');
    const pass = this.config.get<string>('MAIL_PASS');

    // En DEV: error claro si falta config (en PROD ya fallaste en el constructor)
    if (!host || !port || !user || !pass) {
      throw new Error('Email transport not configured (MAIL_* missing).');
    }

    const from =
      this.config.get<string>('MAIL_FROM') ||
      this.config.get<string>('MAIL_USER');

    await this.transporter.sendMail({
      from,
      to: params.to,
      subject: params.subject,
      text: params.text,
      html: params.html,
    });
  }

  async sendSetupPasswordEmail(to: string, setupUrl: string) {
    await this.sendMail({
      to,
      subject: 'Activación de cuenta - Inventiva',
      text: `Hola! Para activar tu cuenta, abrí este enlace: ${setupUrl}`,
      html: `
        <div style="font-family: Arial, sans-serif">
          <p>Hola!</p>
          <p>Para activar tu cuenta, hacé clic aquí:</p>
          <p><a href="${setupUrl}">${setupUrl}</a></p>
          <p>Si vos no solicitaste esto, ignorá este correo.</p>
        </div>
      `,
    });
  }

  async sendResetPasswordEmail(to: string, resetUrl: string) {
    await this.sendMail({
      to,
      subject: 'Recuperación de contraseña - Inventiva',
      text: `Hola! Para restablecer tu contraseña, abrí este enlace: ${resetUrl}`,
      html: `
        <div style="font-family: Arial, sans-serif">
          <p>Hola!</p>
          <p>Para restablecer tu contraseña, hacé clic aquí:</p>
          <p><a href="${resetUrl}">${resetUrl}</a></p>
          <p>Si vos no solicitaste esto, ignorá este correo.</p>
        </div>
      `,
    });
  }
}
