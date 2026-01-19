export class ResendSetupResponseDto {
  ok!: true;
  userId!: number;
  email!: string;
  token?: string;
  expiresInHours!: number;
  setupUrl?: string;
}
