import { IsEmail, MaxLength } from 'class-validator';

export class ResendSetupDto {
  @IsEmail()
  @MaxLength(150)
  email!: string;
}
