import { Controller, Get } from '@nestjs/common';
import { DatabaseService } from './database/database.service';

@Controller()
export class AppController {
  constructor(private readonly db: DatabaseService) {}

  @Get()
  async hello() {
    const rows = await this.db.query<{ MENSAJE: string }>(
      `SELECT 'Hola desde Oracle + NestJS 🚀' AS MENSAJE FROM DUAL`,
    );

    return {
      ok: true,
      data: rows[0],
    };
  }
}
