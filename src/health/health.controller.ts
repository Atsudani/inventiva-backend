import { Controller, Get } from '@nestjs/common';
import { DatabaseService } from '../database/database.service';

@Controller('health')
export class HealthController {
  constructor(private readonly db: DatabaseService) {}

  @Get()
  health() {
    return {
      ok: true,
      status: 'UP',
      timestamp: new Date().toISOString(),
    };
  }

  @Get('db')
  async healthDb() {
    const rows = await this.db.query<{ OK: number }>(
      `SELECT 1 AS OK FROM DUAL`,
    );

    return {
      ok: true,
      db: rows[0]?.OK === 1 ? 'UP' : 'DOWN',
      test: rows[0]?.OK ?? null,
      timestamp: new Date().toISOString(),
    };
  }
}
