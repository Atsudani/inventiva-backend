import {
  IsEmail,
  IsNotEmpty,
  IsString,
  MaxLength,
  MinLength,
} from 'class-validator';

export class LoginDto {
  @IsEmail()
  @MaxLength(150)
  email!: string;

  @IsString()
  @MinLength(1)
  @MaxLength(80)
  password!: string;

  @IsString()
  @IsNotEmpty({ message: 'Empresa es requerida' })
  codEmpresa: string;
}
