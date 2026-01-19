export class AdminCreateUserResponseDto {
  ok!: true;
  userId!: number;
  email!: string;
  token?: string;
  expiresInHours!: number;

  setupUrl?: string;
}
