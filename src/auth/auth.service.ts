import {
  ForbiddenException,
  Injectable,
  NotFoundException,
  BadRequestException,
  UnauthorizedException,
} from '@nestjs/common';
import type { Response } from 'express';
import { randomBytes, createHash } from 'crypto';
import { DatabaseService } from '../database/database.service';
import { AdminCreateUserDto } from './dto/admin-create-user.dto';
import { AdminCreateUserResponseDto } from './dto/admin-create-user.response';
import * as bcrypt from 'bcrypt';
import { SetPasswordDto } from './dto/set-password.dto';
import { JwtService } from '@nestjs/jwt';
import { LoginDto } from './dto/login.dto';
import { ResendSetupDto } from './dto/resend-setup.dto';
import { ResendSetupResponseDto } from './dto/resend-setup.response.dto';
import { ConfigService } from '@nestjs/config';
import { ChangePasswordDto } from './dto/change-password.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { EmailService } from '../email/email.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly db: DatabaseService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly emailService: EmailService,
  ) {}

  //Helpers
  private isProd(): boolean {
    return this.configService.get<string>('NODE_ENV') === 'production';
  }

  private buildUrl(path: string, token: string): string {
    const base = (this.configService.get<string>('FRONTEND_URL') || '').replace(
      /\/$/,
      '',
    );
    return `${base}${path}?token=${encodeURIComponent(token)}`;
  }

  //Metodos

  async adminCreateUser(
    dto: AdminCreateUserDto,
  ): Promise<AdminCreateUserResponseDto> {
    const email = dto.email.trim().toLowerCase();
    const fullName = dto.fullName?.trim() ?? null;
    const SETUP_EXPIRES_HOURS = 24;

    const existing = await this.db.query<{ CNT: number }>(
      `
      SELECT COUNT(1) CNT
      FROM WN_APP_USERS
      WHERE LOWER(EMAIL) = :email
      `,
      { email },
    );

    if ((existing[0]?.CNT ?? 0) > 0) {
      throw new BadRequestException('El email ya está registrado');
    }

    // 1) Insertar user (con commit)
    await this.db.query(
      `
      INSERT INTO WN_APP_USERS (EMAIL, FULL_NAME, IS_ACTIVE, EMAIL_VERIFIED, ROLE)
      VALUES (:email, :fullName, 'Y', 'N', 'USER')
      `,
      { email, fullName },
      { autoCommit: true },
    );

    // 2) Obtener ID por email
    const row = await this.db.query<{ ID: number }>(
      `SELECT ID FROM WN_APP_USERS WHERE LOWER(EMAIL) = :email`,
      { email },
    );

    const userId = row[0]?.ID;
    if (!userId)
      throw new BadRequestException(
        'No se pudo obtener el ID del usuario creado',
      );

    // 3) Generar token (se enviará por email más adelante)
    const token = randomBytes(32).toString('hex');
    const tokenHash = createHash('sha256').update(token).digest('hex');

    // 4) Guardar token (con commit)
    await this.db.query(
      `
      INSERT INTO WN_PWD_SETUP_TOKENS (USER_ID, TOKEN_HASH, EXPIRES_AT)
      VALUES (:userId, :tokenHash, SYSTIMESTAMP + INTERVAL '1' DAY)
      `,
      { userId, tokenHash },
      { autoCommit: true },
    );

    //const setupUrl = `${frontendUrl.replace(/\/$/, '')}/set-password?token=${token}`;

    const setupUrl = this.buildUrl('/setup-password', token);

    if (this.isProd()) {
      await this.emailService.sendSetupPasswordEmail(email, setupUrl);

      return {
        ok: true,
        userId,
        email,
        expiresInHours: SETUP_EXPIRES_HOURS, // si lo tenés como const
      };
    }

    //para dev
    return {
      ok: true,
      userId,
      email,
      token,
      expiresInHours: SETUP_EXPIRES_HOURS,
      setupUrl,
    };
  }

  async setPassword(dto: SetPasswordDto): Promise<{ ok: true }> {
    const token = dto.token.trim();
    const newPassword = dto.newPassword;

    if (!newPassword || newPassword.length < 8) {
      throw new BadRequestException(
        'La contraseña debe tener al menos 8 caracteres',
      );
    }

    const tokenHash = createHash('sha256').update(token).digest('hex');

    // 1) validar token
    const rows = await this.db.query<{ USER_ID: number }>(
      `
    SELECT USER_ID
    FROM WN_PWD_SETUP_TOKENS
    WHERE TOKEN_HASH = :tokenHash
      AND USED_AT IS NULL
      AND EXPIRES_AT > SYSTIMESTAMP
    `,
      { tokenHash },
    );

    const userId = rows[0]?.USER_ID;
    if (!userId) {
      throw new BadRequestException('Token inválido, vencido o ya utilizado');
    }

    // 2) hash password
    const passwordHash = await bcrypt.hash(newPassword, 10);

    // 3) guardar password y activar/verificar
    await this.db.query(
      `
    UPDATE WN_APP_USERS
       SET PASSWORD_HASH = :passwordHash,
           EMAIL_VERIFIED = 'Y',
           UPDATED_AT = SYSTIMESTAMP
     WHERE ID = :userId
    `,
      { passwordHash, userId },
      { autoCommit: true },
    );

    // 4) marcar token como usado
    await this.db.query(
      `
    UPDATE WN_PWD_SETUP_TOKENS
       SET USED_AT = SYSTIMESTAMP
     WHERE TOKEN_HASH = :tokenHash
    `,
      { tokenHash },
      { autoCommit: true },
    );

    return { ok: true };
  }

  async login(dto: LoginDto, res: Response): Promise<{ ok: true }> {
    const email = dto.email.trim().toLowerCase();

    // ... mismo código de validación de usuario ...
    const rows = await this.db.query<{
      ID: number;
      EMAIL: string;
      PASSWORD_HASH: string | null;
      IS_ACTIVE: string;
      EMAIL_VERIFIED: string;
      ROLE: string;
    }>(
      `
    SELECT ID, EMAIL, PASSWORD_HASH, IS_ACTIVE, EMAIL_VERIFIED, ROLE
    FROM WN_APP_USERS
    WHERE LOWER(EMAIL) = :email
    `,
      { email },
    );

    const user = rows[0];
    if (!user) throw new UnauthorizedException('Credenciales inválidas');

    if (user.IS_ACTIVE !== 'Y')
      throw new UnauthorizedException('Usuario inactivo');

    if (user.EMAIL_VERIFIED !== 'Y')
      throw new UnauthorizedException('Usuario no verificado');

    if (!user.PASSWORD_HASH)
      throw new UnauthorizedException('Usuario sin contraseña');

    // ✅ validar password primero
    const ok = await bcrypt.compare(dto.password, user.PASSWORD_HASH);
    if (!ok) throw new UnauthorizedException('Credenciales inválidas');

    // ✅ crear sesión
    const sid = randomBytes(24).toString('hex');

    await this.db.query(
      `
    INSERT INTO WN_USER_SESSIONS (USER_ID, SID, EXPIRES_AT)
    VALUES (:userId, :sid, SYSTIMESTAMP + INTERVAL '7' DAY)
    `,
      { userId: user.ID, sid },
      { autoCommit: true },
    );

    const payload = {
      sub: user.ID,
      email: user.EMAIL,
      role: user.ROLE,
      sid,
    };

    // Generar el token JWT
    const access_token = await this.jwtService.signAsync(payload);

    // 👇 NUEVO: Setear cookie HttpOnly en la respuesta
    // Parámetros:
    // 1. Nombre de la cookie: 'access_token'
    // 2. Valor: el token JWT
    // 3. Opciones:
    res.cookie('access_token', access_token, {
      httpOnly: true, // ✅ No accesible desde JavaScript (seguridad)
      secure: this.isProd(), // ✅ Solo HTTPS en producción
      sameSite: 'lax', // ✅ Protección contra CSRF
      maxAge: 7 * 24 * 60 * 60 * 1000, // ✅ 7 días en milisegundos
      path: '/', // ✅ Disponible en todas las rutas
    });

    // 👇 CAMBIO 3: Devolver solo { ok: true }
    // El token ya está en la cookie, no lo devolvemos en JSON
    return { ok: true };
  }

  async resendSetup(dto: ResendSetupDto): Promise<ResendSetupResponseDto> {
    const email = dto.email.trim().toLowerCase();
    const SETUP_EXPIRES_HOURS = 24;

    // 1) Buscar usuario
    const users = await this.db.query<{
      ID: number;
      EMAIL: string;
      IS_ACTIVE: string;
      EMAIL_VERIFIED: string;
    }>(
      `
    SELECT ID, EMAIL, IS_ACTIVE, EMAIL_VERIFIED
    FROM WN_APP_USERS
    WHERE LOWER(EMAIL) = :email
    `,
      { email },
    );

    const user = users[0];
    if (!user) throw new NotFoundException('Usuario no encontrado');

    if (user.IS_ACTIVE !== 'Y') {
      throw new ForbiddenException('Usuario inactivo');
    }

    // Si ya está verificado, normalmente no tiene sentido reenviar setup
    if (user.EMAIL_VERIFIED === 'Y') {
      throw new ForbiddenException('El usuario ya está verificado');
    }

    // 2) Invalidate tokens anteriores no usados (RECOMENDADO)
    await this.db.query(
      `
        UPDATE WN_PWD_SETUP_TOKENS
        SET USED_AT = SYSTIMESTAMP
        WHERE USER_ID = :userId
          AND USED_AT IS NULL
          AND EXPIRES_AT > SYSTIMESTAMP
      `,
      { userId: user.ID },
      { autoCommit: true },
    );

    // 3) Generar token nuevo
    const token = randomBytes(32).toString('hex');
    const tokenHash = createHash('sha256').update(token).digest('hex');

    await this.db.query(
      `
    INSERT INTO WN_PWD_SETUP_TOKENS (USER_ID, TOKEN_HASH, EXPIRES_AT)
    VALUES (:userId, :tokenHash, SYSTIMESTAMP + INTERVAL '1' DAY)
    `,
      { userId: user.ID, tokenHash },
      { autoCommit: true },
    );

    const setupUrl = this.buildUrl('/setup-password', token);

    if (this.isProd()) {
      await this.emailService.sendSetupPasswordEmail(user.EMAIL, setupUrl);

      return {
        ok: true,
        userId: user.ID,
        email: user.EMAIL,
        expiresInHours: SETUP_EXPIRES_HOURS,
      };
    }

    return {
      ok: true,
      userId: user.ID,
      email: user.EMAIL,
      token,
      expiresInHours: SETUP_EXPIRES_HOURS,
      setupUrl,
    };
  }

  async changePassword(
    userId: number,
    dto: ChangePasswordDto,
  ): Promise<{ ok: true }> {
    if (dto.newPassword !== dto.confirmNewPassword) {
      throw new BadRequestException('Las contraseñas no coinciden');
    }

    const rows = await this.db.query<{
      ID: number;
      PASSWORD_HASH: string | null;
      IS_ACTIVE: string;
    }>(
      `
    SELECT ID, PASSWORD_HASH, IS_ACTIVE
    FROM WN_APP_USERS
    WHERE ID = :userId
    `,
      { userId },
    );

    const user = rows[0];
    if (!user) throw new UnauthorizedException('Usuario inválido');
    if (user.IS_ACTIVE !== 'Y')
      throw new ForbiddenException('Usuario inactivo');
    if (!user.PASSWORD_HASH)
      throw new ForbiddenException('Usuario sin contraseña (use set-password)');

    const ok = await bcrypt.compare(dto.currentPassword, user.PASSWORD_HASH);
    if (!ok) throw new UnauthorizedException('Contraseña actual incorrecta');

    const newHash = await bcrypt.hash(dto.newPassword, 10);

    await this.db.query(
      `
    UPDATE WN_APP_USERS
       SET PASSWORD_HASH = :newHash,
           UPDATED_AT = SYSTIMESTAMP
     WHERE ID = :userId
    `,
      { newHash, userId },
      { autoCommit: true },
    );

    return { ok: true };
  }

  async forgotPassword(dto: ForgotPasswordDto) {
    const WINDOW_MINUTES = 15;
    const MAX_REQUESTS = 3;

    const email = dto.email.trim().toLowerCase();

    // Por seguridad: NO revelar si existe o no.
    const users = await this.db.query<{
      ID: number;
      EMAIL: string;
      IS_ACTIVE: string;
    }>(
      `
    SELECT ID, EMAIL, IS_ACTIVE
    FROM WN_APP_USERS
    WHERE LOWER(EMAIL) = :email
    `,
      { email },
    );

    const user = users[0];

    // Si no existe o está inactivo: devolver ok igual (anti-enumeración)
    if (!user || user.IS_ACTIVE !== 'Y') {
      return { ok: true };
    }

    // Invalida tokens anteriores aún válidos (opcional pero recomendado)
    await this.db.query(
      `
    UPDATE WN_PWD_RESET_TOKENS
       SET USED_AT = SYSTIMESTAMP
     WHERE USER_ID = :userId
       AND USED_AT IS NULL
       AND EXPIRES_AT > SYSTIMESTAMP
    `,
      { userId: user.ID },
      { autoCommit: true },
    );

    // Verificamos si no hay mas de 3 intentos..
    // Rate limit por DB: max 3 requests por 15 minutos
    const counts = await this.db.query<{ CNT: number }>(
      `
      SELECT COUNT(1) CNT
      FROM WN_PWD_RESET_TOKENS
      WHERE USER_ID = :userId
        AND CREATED_AT > SYSTIMESTAMP - NUMTODSINTERVAL(:windowMinutes, 'MINUTE')
      `,
      { userId: user.ID, windowMinutes: WINDOW_MINUTES },
    );

    const cnt = counts[0]?.CNT ?? 0;

    if (cnt >= MAX_REQUESTS) {
      if (this.isProd()) return { ok: true };

      // En DEV devolvemos info útil para vos
      return {
        ok: true,
        rateLimited: true,
        windowMinutes: WINDOW_MINUTES,
        maxRequests: MAX_REQUESTS,
      };
    }

    const token = randomBytes(32).toString('hex');
    const tokenHash = createHash('sha256').update(token).digest('hex');

    // Expira en 1 hora
    await this.db.query(
      `
    INSERT INTO WN_PWD_RESET_TOKENS (USER_ID, TOKEN_HASH, EXPIRES_AT)
    VALUES (:userId, :tokenHash, SYSTIMESTAMP + INTERVAL '1' HOUR)
    `,
      { userId: user.ID, tokenHash },
      { autoCommit: true },
    );

    // ... si el usuario existe y está activo:
    const resetUrl = this.buildUrl('/reset-password', token);

    if (this.isProd()) {
      await this.emailService.sendResetPasswordEmail(user.EMAIL, resetUrl);
      return { ok: true };
    }

    return {
      ok: true,
      email: user.EMAIL,
      token,
      expiresInMinutes: 60,
      resetUrl,
    };
  }

  async resetPassword(dto: ResetPasswordDto): Promise<{ ok: true }> {
    if (dto.newPassword !== dto.confirmNewPassword) {
      throw new BadRequestException('Las contraseñas no coinciden');
    }

    const tokenHash = createHash('sha256').update(dto.token).digest('hex');

    const rows = await this.db.query<{
      ID: number;
      USER_ID: number;
    }>(
      `
    SELECT ID, USER_ID
    FROM WN_PWD_RESET_TOKENS
    WHERE TOKEN_HASH = :tokenHash
      AND USED_AT IS NULL
      AND EXPIRES_AT > SYSTIMESTAMP
    `,
      { tokenHash },
    );

    const t = rows[0];
    if (!t) throw new BadRequestException('Token inválido o expirado');

    const newHash = await bcrypt.hash(dto.newPassword, 10);

    // 1) Actualiza password
    await this.db.query(
      `
    UPDATE WN_APP_USERS
       SET PASSWORD_HASH = :newHash,
           UPDATED_AT = SYSTIMESTAMP
     WHERE ID = :userId
    `,
      { newHash, userId: t.USER_ID },
      { autoCommit: true },
    );

    // 2) Marca token como usado
    await this.db.query(
      `
    UPDATE WN_PWD_RESET_TOKENS
       SET USED_AT = SYSTIMESTAMP
     WHERE ID = :id
    `,
      { id: t.ID },
      { autoCommit: true },
    );

    return { ok: true };
  }

  async logout(
    userId: number,
    sid: string,
    res: Response,
  ): Promise<{ ok: true }> {
    await this.db.query(
      `
    UPDATE WN_USER_SESSIONS
       SET REVOKED_AT = SYSTIMESTAMP
     WHERE USER_ID = :userId
       AND SID = :sid
       AND REVOKED_AT IS NULL
    `,
      { userId, sid },
      { autoCommit: true },
    );

    // Limpiar cookie
    res.clearCookie('access_token', {
      httpOnly: true,
      secure: this.isProd(),
      sameSite: 'lax',
      path: '/',
    });

    return { ok: true };
  }

  async logoutAll(userId: number, res: Response): Promise<{ ok: true }> {
    await this.db.query(
      `
    UPDATE WN_USER_SESSIONS
       SET REVOKED_AT = SYSTIMESTAMP
     WHERE USER_ID = :userId
       AND REVOKED_AT IS NULL
    `,
      { userId },
      { autoCommit: true },
    );

    res.clearCookie('access_token', {
      httpOnly: true,
      secure: this.isProd(),
      sameSite: 'lax',
      path: '/',
    });

    return { ok: true };
  }

  async getMe(userId: number) {
    const users = await this.db.query<{
      ID: number;
      EMAIL: string;
      FULL_NAME: string;
      ROLE: string;
    }>(
      `
    SELECT ID, EMAIL, FULL_NAME, ROLE
    FROM WN_APP_USERS
    WHERE ID = :userId
    `,
      { userId },
    );

    const user = users[0];
    if (!user) {
      throw new UnauthorizedException('Usuario no encontrado');
    }

    // TODO: Aquí más adelante traer permisos desde tu tabla de permisos
    const permisos: string[] = [];

    return {
      usuario: {
        id: user.ID,
        email: user.EMAIL,
        nombre: user.FULL_NAME || user.EMAIL,
        role: user.ROLE,
      },
      permisos,
    };
  }

  /**
   * Limpia la cookie de autenticación sin validar el token.
   * Usado cuando el token ya es inválido pero la cookie persiste.
   */
  clearCookie(res: Response): void {
    res.clearCookie('access_token', {
      httpOnly: true,
      secure: this.isProd(),
      sameSite: 'lax',
      path: '/',
    });

    res.json({ ok: true });
  }
}
