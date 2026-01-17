import { IsString, MaxLength, MinLength } from 'class-validator';

export class ResetPasswordDto {
  @IsString()
  @MinLength(20)
  @MaxLength(500)
  token!: string;

  @IsString()
  @MinLength(8)
  @MaxLength(80)
  newPassword!: string;

  @IsString()
  @MinLength(8)
  @MaxLength(80)
  confirmNewPassword!: string;
}
