import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { DatabaseService } from 'src/database/database.service';
import { GetSifenComprobantesQueryDto } from './dto/get-sifen-comprobantes.query';
import {
  OracleBinds,
  ResultadoPaginado,
  calcularPaginacion,
  construirWhere,
  envolverConPaginacionRowNumber,
  obtenerTotal,
} from '../common/oracle/paginacion-oracle';

export type LgkEnviadosRow = {
  COD_EMPRESA: string;
  TIPO: string;
  SERIE: string;
  NUMERO: number;
  TIP_COMPROBANTE: number;
  NRO_COMPROBANTE: string;
  TIMBRADO: number;
  FECHA: Date;
  ESTADO: string | null;
  OBSERVACION: string | null;
  IND_REENVIAR: 'S' | 'N';
  CDC: string | null;
  LINK_QR: string | null;
  FEC_MIGRADO: Date;
  IND_ANULADO: 'S' | 'N';
  FEC_ANU_SISTEMA: Date | null;
  FEC_ANU_SIFEN: Date | null;
  TOTAL_COUNT?: number;
};

@Injectable()
export class SifenService {
  constructor(private readonly db: DatabaseService) {}

  private normalizeEstado(estado: string | null | undefined): string {
    return (estado ?? '').trim().toUpperCase();
  }

  async findOne(pk: {
    codEmpresa: string;
    tipo: string;
    serie: string;
    numero: number;
  }): Promise<LgkEnviadosRow> {
    const rows = await this.db.query<LgkEnviadosRow>(
      `SELECT
         COD_EMPRESA, TIPO, SERIE, NUMERO,
         TIP_COMPROBANTE, NRO_COMPROBANTE, TIMBRADO, FECHA,
         ESTADO, OBSERVACION, IND_REENVIAR, CDC, LINK_QR,
         FEC_MIGRADO, IND_ANULADO, FEC_ANU_SISTEMA, FEC_ANU_SIFEN
       FROM LGK_ENVIADOS
       WHERE COD_EMPRESA = :codEmpresa
         AND TIPO = :tipo
         AND SERIE = :serie
         AND NUMERO = :numero`,
      pk,
    );

    if (rows.length === 0)
      throw new NotFoundException('Comprobante no encontrado en LGK_ENVIADOS');
    return rows[0];
  }

  // async findMany(q: GetSifenComprobantesQueryDto): Promise<{
  //   page: number;
  //   pageSize: number;
  //   total: number;
  //   items: LgkEnviadosRow[];
  // }> {
  //   const where: string[] = [];
  //   const binds: Record<string, any> = {};

  //   if (q.codEmpresa) {
  //     where.push('COD_EMPRESA = :codEmpresa');
  //     binds.codEmpresa = q.codEmpresa;
  //   }
  //   if (q.estado) {
  //     where.push('UPPER(TRIM(ESTADO)) = UPPER(TRIM(:estado))');
  //     binds.estado = q.estado;
  //   }
  //   if (q.tipo) {
  //     where.push('TIPO = :tipo');
  //     binds.tipo = q.tipo;
  //   }
  //   if (q.serie) {
  //     where.push('SERIE = :serie');
  //     binds.serie = q.serie;
  //   }
  //   if (typeof q.numero === 'number') {
  //     where.push('NUMERO = :numero');
  //     binds.numero = q.numero;
  //   }
  //   if (typeof q.tipComprobante === 'number') {
  //     where.push('TIP_COMPROBANTE = :tipComprobante');
  //     binds.tipComprobante = q.tipComprobante;
  //   }
  //   if (q.nroComprobante) {
  //     where.push('NRO_COMPROBANTE = :nroComprobante');
  //     binds.nroComprobante = q.nroComprobante;
  //   }
  //   if (typeof q.timbrado === 'number') {
  //     where.push('TIMBRADO = :timbrado');
  //     binds.timbrado = q.timbrado;
  //   }
  //   if (q.anulado) {
  //     where.push('IND_ANULADO = :anulado');
  //     binds.anulado = q.anulado;
  //   }
  //   if (q.reenviar) {
  //     where.push('IND_REENVIAR = :reenviar');
  //     binds.reenviar = q.reenviar;
  //   }

  //   if (q.from) {
  //     where.push(`FECHA >= TO_DATE(:fromDate, 'YYYY-MM-DD')`);
  //     binds.fromDate = q.from;
  //   }

  //   //OJO: Aqui esta sumando un dia mas a le fecha hasta.. despues voy a sacar esto.
  //   if (q.to) {
  //     where.push(`FECHA < (TO_DATE(:toDate, 'YYYY-MM-DD') + 1)`);
  //     binds.toDate = q.to;
  //   }

  //   const page = q.page ?? 1;
  //   const pageSize = q.pageSize ?? 50;

  //   binds.rowFrom = (page - 1) * pageSize + 1;
  //   binds.rowTo = page * pageSize;

  //   const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

  //   const sql = `
  //     SELECT *
  //     FROM (
  //       SELECT
  //         COD_EMPRESA, TIPO, SERIE, NUMERO,
  //         TIP_COMPROBANTE, NRO_COMPROBANTE, TIMBRADO, FECHA,
  //         ESTADO, OBSERVACION, IND_REENVIAR, CDC, LINK_QR,
  //         FEC_MIGRADO, IND_ANULADO, FEC_ANU_SISTEMA, FEC_ANU_SIFEN,
  //         COUNT(1) OVER () AS TOTAL_COUNT,
  //         ROW_NUMBER() OVER (ORDER BY FECHA DESC, FEC_MIGRADO DESC, NUMERO DESC) AS RN
  //       FROM LGK_ENVIADOS
  //       ${whereSql}
  //     )
  //     WHERE RN BETWEEN :rowFrom AND :rowTo
  //   `;

  //   const rows = await this.db.query<LgkEnviadosRow>(sql, binds);
  //   const total = rows.length ? Number(rows[0].TOTAL_COUNT ?? 0) : 0;

  //   const items = rows.map((r) => ({
  //     COD_EMPRESA: r.COD_EMPRESA,
  //     TIPO: r.TIPO,
  //     SERIE: r.SERIE,
  //     NUMERO: r.NUMERO,
  //     TIP_COMPROBANTE: r.TIP_COMPROBANTE,
  //     NRO_COMPROBANTE: r.NRO_COMPROBANTE,
  //     TIMBRADO: r.TIMBRADO,
  //     FECHA: r.FECHA,
  //     ESTADO: r.ESTADO,
  //     OBSERVACION: r.OBSERVACION,
  //     IND_REENVIAR: r.IND_REENVIAR,
  //     CDC: r.CDC,
  //     LINK_QR: r.LINK_QR,
  //     FEC_MIGRADO: r.FEC_MIGRADO,
  //     IND_ANULADO: r.IND_ANULADO,
  //     FEC_ANU_SISTEMA: r.FEC_ANU_SISTEMA,
  //     FEC_ANU_SIFEN: r.FEC_ANU_SIFEN,
  //   }));

  //   return { page, pageSize, total, items };
  // }

  async findMany(
    q: GetSifenComprobantesQueryDto,
  ): Promise<ResultadoPaginado<LgkEnviadosRow>> {
    const where: string[] = [];
    const binds: OracleBinds = {};

    if (q.codEmpresa) {
      where.push('COD_EMPRESA = :codEmpresa');
      binds.codEmpresa = q.codEmpresa;
    }
    if (q.estado) {
      where.push('UPPER(TRIM(ESTADO)) = UPPER(TRIM(:estado))');
      binds.estado = q.estado;
    }
    if (q.tipo) {
      where.push('TIPO = :tipo');
      binds.tipo = q.tipo;
    }
    if (q.serie) {
      where.push('SERIE = :serie');
      binds.serie = q.serie;
    }
    if (typeof q.numero === 'number') {
      where.push('NUMERO = :numero');
      binds.numero = q.numero;
    }
    if (typeof q.tipComprobante === 'number') {
      where.push('TIP_COMPROBANTE = :tipComprobante');
      binds.tipComprobante = q.tipComprobante;
    }
    if (q.nroComprobante) {
      where.push('NRO_COMPROBANTE = :nroComprobante');
      binds.nroComprobante = q.nroComprobante;
    }
    if (typeof q.timbrado === 'number') {
      where.push('TIMBRADO = :timbrado');
      binds.timbrado = q.timbrado;
    }
    if (q.anulado) {
      where.push('IND_ANULADO = :anulado');
      binds.anulado = q.anulado;
    }
    if (q.reenviar) {
      where.push('IND_REENVIAR = :reenviar');
      binds.reenviar = q.reenviar;
    }

    if (q.from) {
      where.push(`FECHA >= TO_DATE(:fromDate, 'YYYY-MM-DD')`);
      binds.fromDate = q.from;
    }
    if (q.to) {
      where.push(`FECHA < (TO_DATE(:toDate, 'YYYY-MM-DD') + 1)`);
      binds.toDate = q.to;
    }

    const whereSql = construirWhere(where);

    const { page, pageSize, rowFrom, rowTo } = calcularPaginacion({
      page: q.page,
      pageSize: q.pageSize,
      defaultPageSize: 50,
      maxPageSize: 200,
    });

    binds.rowFrom = rowFrom;
    binds.rowTo = rowTo;

    const baseSelectSql = `
    SELECT
      COD_EMPRESA, TIPO, SERIE, NUMERO,
      TIP_COMPROBANTE, NRO_COMPROBANTE, TIMBRADO, FECHA,
      ESTADO, OBSERVACION, IND_REENVIAR, CDC, LINK_QR,
      FEC_MIGRADO, IND_ANULADO, FEC_ANU_SISTEMA, FEC_ANU_SIFEN
    FROM LGK_ENVIADOS
    ${whereSql}
  `;

    const sql = envolverConPaginacionRowNumber({
      baseSelectSql,
      orderBySql: 'FECHA DESC, FEC_MIGRADO DESC, NUMERO DESC',
    });

    const rows = await this.db.query<
      LgkEnviadosRow & { TOTAL_COUNT?: unknown }
    >(sql, binds);

    const total = obtenerTotal(rows);

    const items: LgkEnviadosRow[] = rows.map((r) => ({
      COD_EMPRESA: r.COD_EMPRESA,
      TIPO: r.TIPO,
      SERIE: r.SERIE,
      NUMERO: r.NUMERO,
      TIP_COMPROBANTE: r.TIP_COMPROBANTE,
      NRO_COMPROBANTE: r.NRO_COMPROBANTE,
      TIMBRADO: r.TIMBRADO,
      FECHA: r.FECHA,
      ESTADO: r.ESTADO,
      OBSERVACION: r.OBSERVACION,
      IND_REENVIAR: r.IND_REENVIAR,
      CDC: r.CDC,
      LINK_QR: r.LINK_QR,
      FEC_MIGRADO: r.FEC_MIGRADO,
      IND_ANULADO: r.IND_ANULADO,
      FEC_ANU_SISTEMA: r.FEC_ANU_SISTEMA,
      FEC_ANU_SIFEN: r.FEC_ANU_SIFEN,
    }));

    return { page, pageSize, total, items };
  }

  async marcarParaReenvio(pk: {
    codEmpresa: string;
    tipo: string;
    serie: string;
    numero: number;
  }): Promise<void> {
    const current = await this.findOne(pk);

    const estado = this.normalizeEstado(current.ESTADO);
    if (estado !== 'ERROR' && estado !== 'RECHAZADO') {
      throw new BadRequestException(
        'Solo se puede marcar para reenvío si el estado es ERROR o RECHAZADO.',
      );
    }

    await this.db.query(
      `UPDATE LGK_ENVIADOS
       SET IND_REENVIAR = 'S'
       WHERE COD_EMPRESA = :codEmpresa
         AND TIPO = :tipo
         AND SERIE = :serie
         AND NUMERO = :numero`,
      pk,
      { autoCommit: true },
    );
  }
}
