import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { DatabaseService } from 'src/database/database.service';

export type JwtPayload = {
  sub: number;
  email: string;
  role: 'ADMIN' | 'USER';
  sid: string;
};

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(
    configService: ConfigService,
    private readonly db: DatabaseService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey:
        configService.get<string>('JWT_SECRET') || 'dev_secret_change_me',
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

    // opcional: marcar actividad
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
    // esto va a quedar disponible como req.user
    return payload;
  }
}
