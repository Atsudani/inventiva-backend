import { BindParameters } from 'oracledb';

// export type OracleBinds = Record<string, unknown>;
export type OracleBinds = BindParameters;

export interface EntradaPaginacion {
  page?: number;
  pageSize?: number;
  maxPageSize?: number;
  defaultPageSize?: number;
}

export interface PaginacionCalculada {
  page: number;
  pageSize: number;
  rowFrom: number;
  rowTo: number;
}

export interface ResultadoPaginado<T> {
  page: number;
  pageSize: number;
  total: number;
  items: T[];
}

/**
 * Normaliza page/pageSize y calcula rowFrom/rowTo (para RN BETWEEN).
 */
export function calcularPaginacion(
  input: EntradaPaginacion,
): PaginacionCalculada {
  const page = Math.max(1, Number(input.page ?? 1));

  const defaultPageSize = input.defaultPageSize ?? 50;
  const maxPageSize = input.maxPageSize ?? 200;

  const rawPageSize = Number(input.pageSize ?? defaultPageSize);
  const pageSize = Math.min(Math.max(1, rawPageSize), maxPageSize);

  const rowFrom = (page - 1) * pageSize + 1;
  const rowTo = page * pageSize;

  return { page, pageSize, rowFrom, rowTo };
}

/**
 * Arma el SQL del WHERE dinámico.
 */
export function construirWhere(where: string[]): string {
  return where.length ? `WHERE ${where.join(' AND ')}` : '';
}

/**
 * Envuelve un SELECT base para devolver:
 * - TOTAL_COUNT (COUNT OVER)
 * - RN (ROW_NUMBER OVER)
 * y filtra RN BETWEEN :rowFrom AND :rowTo
 *
 * Importante:
 * - baseSelectSql: SELECT ... FROM ... ${whereSql}
 * - orderBySql: sin la palabra ORDER BY
 */
export function envolverConPaginacionRowNumber(params: {
  baseSelectSql: string;
  orderBySql: string;
}): string {
  const base = params.baseSelectSql.trim().replace(/;$/, '');

  return `
    SELECT *
    FROM (
      SELECT
        T.*,
        COUNT(1) OVER () AS TOTAL_COUNT,
        ROW_NUMBER() OVER (ORDER BY ${params.orderBySql}) AS RN
      FROM (
        ${base}
      ) T
    )
    WHERE RN BETWEEN :rowFrom AND :rowTo
  `;
}

/**
 * Obtiene el total desde la primera fila (TOTAL_COUNT viene repetido).
 */
export function obtenerTotal(rows: Array<{ TOTAL_COUNT?: unknown }>): number {
  return rows.length ? Number(rows[0].TOTAL_COUNT ?? 0) : 0;
}
