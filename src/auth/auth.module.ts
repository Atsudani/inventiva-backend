import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { DatabaseModule } from 'src/database/database.module';
import type { StringValue } from 'ms';
import { JwtStrategy } from './jwt.strategy';
import { RolesGuard } from './roles.guard';
import { EmailModule } from 'src/email/email.module';

@Module({
  imports: [
    DatabaseModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => {
        const isProd = config.get<string>('NODE_ENV') === 'production';

        const secret = config.get<string>('JWT_SECRET');
        const expiresIn = (config.get<string>('JWT_EXPIRES_IN') ||
          '1d') as StringValue;

        if (isProd && (!secret || secret.trim().length < 16)) {
          throw new Error(
            'JWT misconfigured for production. Missing/weak JWT_SECRET (min 16 chars).',
          );
        }

        // En DEV se permite secreto vacío SOLO si vos querés.
        // Yo igual recomiendo siempre setearlo.
        return {
          secret: secret || 'dev_secret_change_me',
          signOptions: { expiresIn },
        };
      },
    }),
    EmailModule,
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy, RolesGuard],
})
export class AuthModule {}
