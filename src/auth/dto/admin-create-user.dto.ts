import { IsEmail, IsOptional, IsString, MaxLength } from 'class-validator';

export class AdminCreateUserDto {
  @IsEmail()
  @MaxLength(150)
  email!: string;

  @IsOptional()
  @IsString()
  @MaxLength(120)
  fullName?: string;
}
