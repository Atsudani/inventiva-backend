import {
  Controller,
  Get,
  Param,
  ParseIntPipe,
  Patch,
  Query,
} from '@nestjs/common';
import { GetSifenComprobantesQueryDto } from './dto/get-sifen-comprobantes.query';
import { SifenService } from './sifen.service';

@Controller('sifen')
export class SifenController {
  constructor(private readonly sifenService: SifenService) {}

  @Get('comprobantes')
  async getComprobantes(@Query() query: GetSifenComprobantesQueryDto) {
    const result = await this.sifenService.findMany(query);

    return {
      ...result,
      items: result.items.map((r) => ({
        codEmpresa: r.COD_EMPRESA,
        tipo: r.TIPO,
        serie: r.SERIE,
        numero: r.NUMERO,
        tipComprobante: r.TIP_COMPROBANTE,
        nroComprobante: r.NRO_COMPROBANTE,
        timbrado: r.TIMBRADO,
        fecha: r.FECHA,
        estado: r.ESTADO,
        observacion: r.OBSERVACION,
        indReenviar: r.IND_REENVIAR,
        cdc: r.CDC,
        linkQr: r.LINK_QR,
        fecMigrado: r.FEC_MIGRADO,
        indAnulado: r.IND_ANULADO,
        fecAnuSistema: r.FEC_ANU_SISTEMA,
        fecAnuSifen: r.FEC_ANU_SIFEN,
      })),
    };
  }

  @Get('comprobantes/:codEmpresa/:tipo/:serie/:numero')
  async getComprobante(
    @Param('codEmpresa') codEmpresa: string,
    @Param('tipo') tipo: string,
    @Param('serie') serie: string,
    @Param('numero', ParseIntPipe) numero: number,
  ) {
    const r = await this.sifenService.findOne({
      codEmpresa,
      tipo,
      serie,
      numero,
    });

    return {
      codEmpresa: r.COD_EMPRESA,
      tipo: r.TIPO,
      serie: r.SERIE,
      numero: r.NUMERO,
      tipComprobante: r.TIP_COMPROBANTE,
      nroComprobante: r.NRO_COMPROBANTE,
      timbrado: r.TIMBRADO,
      fecha: r.FECHA,
      estado: r.ESTADO,
      observacion: r.OBSERVACION,
      indReenviar: r.IND_REENVIAR,
      cdc: r.CDC,
      linkQr: r.LINK_QR,
      fecMigrado: r.FEC_MIGRADO,
      indAnulado: r.IND_ANULADO,
      fecAnuSistema: r.FEC_ANU_SISTEMA,
      fecAnuSifen: r.FEC_ANU_SIFEN,
    };
  }

  @Patch('comprobantes/:codEmpresa/:tipo/:serie/:numero/reenviar')
  async marcarReenvio(
    @Param('codEmpresa') codEmpresa: string,
    @Param('tipo') tipo: string,
    @Param('serie') serie: string,
    @Param('numero', ParseIntPipe) numero: number,
  ) {
    await this.sifenService.marcarParaReenvio({
      codEmpresa,
      tipo,
      serie,
      numero,
    });
    return { ok: true };
  }
}
