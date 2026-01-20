import { Type } from 'class-transformer';
import { IsIn, IsInt, IsOptional, IsString, Max, Min } from 'class-validator';

/**
 * Query params para listar comprobantes de LGK_ENVIADOS.
 *
 * `from` y `to` se esperan en formato YYYY-MM-DD.
 * `to` es inclusivo (internamente se usa FECHA < (to + 1 día)).
 */
export class GetSifenComprobantesQueryDto {
  @IsOptional()
  @IsString()
  codEmpresa?: string;

  @IsOptional()
  @IsString()
  estado?: string;

  @IsOptional()
  @IsString()
  tipo?: string;

  @IsOptional()
  @IsString()
  serie?: string;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  numero?: number;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  tipComprobante?: number;

  @IsOptional()
  @IsString()
  nroComprobante?: string;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  timbrado?: number;

  @IsOptional()
  @IsIn(['S', 'N'])
  anulado?: 'S' | 'N';

  @IsOptional()
  @IsIn(['S', 'N'])
  reenviar?: 'S' | 'N';

  /** YYYY-MM-DD */
  @IsOptional()
  @IsString()
  from?: string;

  /** YYYY-MM-DD (inclusive) */
  @IsOptional()
  @IsString()
  to?: string;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  page: number = 1;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(200)
  pageSize: number = 50;
}
