import { IsString, MaxLength, MinLength } from 'class-validator';

export class ChangePasswordDto {
  @IsString()
  @MinLength(1)
  @MaxLength(80)
  currentPassword!: string;

  @IsString()
  @MinLength(8)
  @MaxLength(80)
  newPassword!: string;

  @IsString()
  @MinLength(8)
  @MaxLength(80)
  confirmNewPassword!: string;
}
