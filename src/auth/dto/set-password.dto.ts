import { IsString, MaxLength, MinLength } from 'class-validator';

export class SetPasswordDto {
  @IsString()
  @MinLength(20) // token hex (64 chars), mínimo 20 para no aceptar basura
  @MaxLength(500)
  token!: string;

  @IsString()
  @MinLength(8)
  @MaxLength(80)
  newPassword!: string;
}
