/* eslint-disable @typescript-eslint/no-unsafe-member-access */
import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Pool } from 'oracledb';
import * as oracledb from 'oracledb';

@Injectable()
export class DatabaseService implements OnModuleInit, OnModuleDestroy {
  private pool: Pool | null = null;
  private static oracleClientInitialized = false;

  constructor(private readonly configService: ConfigService) {}

  async onModuleInit(): Promise<void> {
    // ✅ THICK mode: necesario para tu error NJS-116 (password verifier 0x939)
    const libDir =
      this.configService.get<string>('ORACLE_CLIENT_LIB_DIR') ??
      '/Users/atsushikusunose/instantclient_23_3';

    if (!DatabaseService.oracleClientInitialized) {
      try {
        oracledb.initOracleClient({ libDir });
        DatabaseService.oracleClientInitialized = true;
        console.log(
          '✅ Oracle Instant Client inicializado (THICK mode):',
          libDir,
        );
      } catch (e: any) {
        const msg = e?.message ? String(e.message) : String(e);

        // DPI-1050: Oracle Client library has already been initialized
        if (msg.includes('DPI-1050')) {
          DatabaseService.oracleClientInitialized = true;
          console.log(
            'ℹ️ Oracle Instant Client ya estaba inicializado (DPI-1050).',
          );
        } else {
          throw e;
        }
      }
    }

    const user = this.configService.get<string>('ORACLE_USER') ?? '';
    const password = this.configService.get<string>('ORACLE_PASSWORD') ?? '';
    const connectString =
      this.configService.get<string>('ORACLE_CONNECT_STRING') ?? '';

    const poolMin = Number(
      this.configService.get<string>('ORACLE_POOL_MIN') ?? '1',
    );
    const poolMax = Number(
      this.configService.get<string>('ORACLE_POOL_MAX') ?? '10',
    );
    const poolInc = Number(
      this.configService.get<string>('ORACLE_POOL_INC') ?? '1',
    );

    console.log('🔎 Oracle connectString:', connectString);
    console.log('🔎 poolMin/poolMax/poolInc:', poolMin, poolMax, poolInc);

    if (!user || !password || !connectString) {
      throw new Error(
        'Faltan ORACLE_USER / ORACLE_PASSWORD / ORACLE_CONNECT_STRING en .env',
      );
    }

    if (!Number.isInteger(poolMin) || poolMin < 0)
      throw new Error(`poolMin invalido: ${poolMin}`);
    if (!Number.isInteger(poolMax) || poolMax < 1)
      throw new Error(`poolMax invalido: ${poolMax}`);
    if (!Number.isInteger(poolInc) || poolInc < 0)
      throw new Error(`poolIncrement invalido: ${poolInc}`);
    if (poolMax < poolMin)
      throw new Error(
        `poolMax (${poolMax}) no puede ser menor que poolMin (${poolMin})`,
      );

    this.pool = await oracledb.createPool({
      user,
      password,
      connectString,
      poolMin,
      poolMax,
      poolIncrement: poolInc,
    });

    console.log('✅ Oracle Pool creado correctamente');
  }

  async onModuleDestroy(): Promise<void> {
    if (this.pool) {
      await this.pool.close(10);
      this.pool = null;
      console.log('🛑 Oracle Pool cerrado');
    }
  }

  async query<T = Record<string, unknown>>(
    sql: string,
    binds: oracledb.BindParameters = [],
    options: oracledb.ExecuteOptions = {},
  ): Promise<T[]> {
    if (!this.pool) throw new Error('Oracle pool no inicializado');

    const connection = await this.pool.getConnection();
    try {
      const result = await connection.execute(sql, binds, {
        outFormat: oracledb.OUT_FORMAT_OBJECT,
        autoCommit: false,
        ...options,
      });

      return (result.rows ?? []) as T[];
    } finally {
      await connection.close();
    }
  }
}
