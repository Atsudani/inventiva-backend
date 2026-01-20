import { Body, Controller, Get, Post, Req, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SetPasswordDto } from './dto/set-password.dto';
import { AdminCreateUserDto } from './dto/admin-create-user.dto';
import { LoginDto } from './dto/login.dto';
import { JwtAuthGuard } from './jwt-auth.guard';
import type { JwtPayload } from './jwt.strategy';
import { RolesGuard } from './roles.guard';
import { Roles } from './roles.decorator';
import { ResendSetupDto } from './dto/resend-setup.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { Throttle } from '@nestjs/throttler';

type AuthRequest = Request & { user: JwtPayload };

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('ADMIN')
  @Post('admin/create-user')
  adminCreateUser(@Body() dto: AdminCreateUserDto) {
    return this.authService.adminCreateUser(dto);
  }

  @Throttle({ default: { limit: 10, ttl: 60_000 } })
  @Post('set-password')
  setPassword(@Body() dto: SetPasswordDto) {
    return this.authService.setPassword(dto);
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('ADMIN')
  @Post('admin/resend-setup')
  resendSetup(@Body() dto: ResendSetupDto) {
    return this.authService.resendSetup(dto);
  }

  @Throttle({ default: { limit: 10, ttl: 60_000 } })
  @Post('login')
  login(@Body() dto: LoginDto) {
    return this.authService.login(dto);
  }

  @UseGuards(JwtAuthGuard)
  @Get('me')
  me(@Req() req: AuthRequest) {
    return { ok: true, user: req.user };
  }

  @UseGuards(JwtAuthGuard)
  @Post('change-password')
  changePassword(@Req() req: AuthRequest, @Body() dto: ChangePasswordDto) {
    return this.authService.changePassword(req.user.sub, dto);
  }

  @Throttle({ default: { limit: 5, ttl: 60_000 } })
  @Post('forgot-password')
  forgotPassword(@Body() dto: ForgotPasswordDto) {
    return this.authService.forgotPassword(dto);
  }

  @Throttle({ default: { limit: 5, ttl: 60_000 } })
  @Post('reset-password')
  resetPassword(@Body() dto: ResetPasswordDto) {
    return this.authService.resetPassword(dto);
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  logout(@Req() req: AuthRequest) {
    return this.authService.logout(req.user.sub, req.user.sid);
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout-all')
  logoutAll(@Req() req: AuthRequest) {
    return this.authService.logoutAll(req.user.sub);
  }
}
