// ============================================
// Leer token desde cookie.
// El token es mejor del lado del servidor con httpOnly cookie, que almacenar en el storage del cliente.
// ============================================
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import type { Request } from 'express';
import { DatabaseService } from 'src/database/database.service';

export type JwtPayload = {
  sub: number;
  email: string;
  role: 'ADMIN' | 'USER';
  sid: string;
};

interface RequestWithCookies extends Request {
  cookies: {
    access_token?: string;
  };
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(
    configService: ConfigService,
    private readonly db: DatabaseService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (request: Request) => {
          const req = request as RequestWithCookies;

          // console.log('🍪 All cookies:', req.cookies);
          // console.log('🔑 Token extraido:', req.cookies?.access_token);

          return req.cookies?.access_token || null;
        },
      ]),
      ignoreExpiration: false,
      secretOrKey:
        configService.get<string>('JWT_SECRET') || 'dev_secret_change_me',
      passReqToCallback: false,
    });
  }

  async validate(payload: JwtPayload) {
    const sessions = await this.db.query<{ ID: number }>(
      `
        SELECT ID
        FROM WN_USER_SESSIONS
        WHERE SID = :sid
          AND USER_ID = :userId
          AND REVOKED_AT IS NULL
          AND EXPIRES_AT > SYSTIMESTAMP
      `,
      { sid: payload.sid, userId: payload.sub },
    );

    if (!sessions[0]) {
      throw new UnauthorizedException('Sesión inválida o expirada');
    }

    await this.db.query(
      `
        UPDATE WN_USER_SESSIONS
        SET LAST_SEEN_AT = SYSTIMESTAMP
        WHERE SID = :sid
        AND USER_ID = :userId
      `,
      { sid: payload.sid, userId: payload.sub },
      { autoCommit: true },
    );

    return payload;
  }
}
