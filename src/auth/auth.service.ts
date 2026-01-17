import {
  ForbiddenException,
  Injectable,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import { randomBytes, createHash } from 'crypto';
import { DatabaseService } from '../database/database.service';
import { AdminCreateUserDto } from './dto/admin-create-user.dto';
import { AdminCreateUserResponseDto } from './dto/admin-create-user.response';
import * as bcrypt from 'bcrypt';
import { UnauthorizedException } from '@nestjs/common';
import { SetPasswordDto } from './dto/set-password.dto';
import { JwtService } from '@nestjs/jwt';
import { LoginDto } from './dto/login.dto';
import { ResendSetupDto } from './dto/resend-setup.dto';
import { ResendSetupResponseDto } from './dto/resend-setup.response.dto';
import { ConfigService } from '@nestjs/config';
import { ChangePasswordDto } from './dto/change-password.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly db: DatabaseService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  async adminCreateUser(
    dto: AdminCreateUserDto,
  ): Promise<AdminCreateUserResponseDto> {
    const email = dto.email.trim().toLowerCase();
    const fullName = dto.fullName?.trim() ?? null;

    const frontendUrl =
      this.configService.get<string>('FRONTEND_URL') ?? 'http://localhost:3001';

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
    if (!userId) throw new Error('No se pudo obtener el ID del usuario creado');

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

    const setupUrl = `${frontendUrl.replace(/\/$/, '')}/set-password?token=${token}`;

    // Por ahora devolvemos el token para pruebas sin email
    return {
      ok: true,
      userId,
      email,
      token,
      expiresInHours: 24,
      setupUrl,
    };
  }

  async setPassword(dto: SetPasswordDto) {
    const token = dto.token.trim();
    const newPassword = dto.newPassword;

    if (newPassword.length < 8) {
      throw new Error('La contraseña debe tener al menos 8 caracteres');
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
      throw new Error('Token inválido, vencido o ya utilizado');
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

  async login(dto: LoginDto): Promise<{ access_token: string }> {
    const email = dto.email.trim().toLowerCase();

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

    const ok = await bcrypt.compare(dto.password, user.PASSWORD_HASH);
    if (!ok) throw new UnauthorizedException('Credenciales inválidas');

    // payload JWT
    const payload = {
      sub: user.ID,
      email: user.EMAIL,
      role: user.ROLE,
    };

    const access_token = await this.jwtService.signAsync(payload);

    return { access_token };
  }

  async resendSetup(dto: ResendSetupDto): Promise<ResendSetupResponseDto> {
    const email = dto.email.trim().toLowerCase();

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

    const frontendUrl =
      this.configService.get<string>('FRONTEND_URL') ?? 'http://localhost:3001';

    const setupUrl = `${frontendUrl.replace(/\/$/, '')}/set-password?token=${token}`;

    return {
      ok: true,
      userId: user.ID,
      email: user.EMAIL,
      token,
      expiresInHours: 24,
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
    AND CREATED_AT > SYSTIMESTAMP - INTERVAL '${WINDOW_MINUTES}' MINUTE
  `,
      { userId: user.ID },
    );

    const cnt = counts[0]?.CNT ?? 0;

    if (cnt >= MAX_REQUESTS) {
      // En PROD no revelamos nada: ok true y listo (como si se envió)
      const nodeEnv =
        this.configService.get<string>('NODE_ENV') ?? 'development';
      const isProd = nodeEnv === 'production';

      if (isProd) return { ok: true };

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

    // DEV helper (para probar sin email)
    const frontendUrl =
      this.configService.get<string>('FRONTEND_URL') ?? 'http://localhost:3001';
    const resetUrl = `${frontendUrl.replace(/\/$/, '')}/reset-password?token=${token}`;

    const nodeEnv = this.configService.get<string>('NODE_ENV') ?? 'development';
    const isProd = nodeEnv === 'production';

    if (isProd) {
      // En PROD: no devolver token/url
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
}
