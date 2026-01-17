import { IsEmail, MaxLength } from 'class-validator';

export class ForgotPasswordDto {
  @IsEmail()
  @MaxLength(150)
  email!: string;
}
