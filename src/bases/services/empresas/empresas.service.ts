import { Injectable, NotFoundException } from '@nestjs/common';
import { DatabaseService } from 'src/database/database.service';

@Injectable()
export class EmpresasService {
  constructor(private readonly db: DatabaseService) {}

  async findAll() {
    const query = `
      SELECT 
        cod_empresa,
        descripcion,
        nombre_corto,
        ruc_empresa
      FROM empresas
      ORDER BY descripcion
    `;

    const empresas = await this.db.query<{
      COD_EMPRESA: string;
      DESCRIPCION: string;
      NOMBRE_CORTO: string;
      RUC_EMPRESA: string;
    }>(query, {});

    if (empresas.length === 0) {
      throw new NotFoundException(`No se han encontrado empresas.`);
    }

    return empresas.map((e) => ({
      codigo: e.COD_EMPRESA,
      descripcion: e.DESCRIPCION,
      nombreCorto: e.NOMBRE_CORTO,
      ruc: e.RUC_EMPRESA,
    }));
  }

  async findById(codEmpresa: string) {
    const query = `
      SELECT 
        cod_empresa,
        descripcion,
        nombre_corto,
        ruc_empresa,
        direccion,
        actividad
      FROM empresas
      WHERE cod_empresa = :codEmpresa
    `;

    const empresas = await this.db.query<{
      COD_EMPRESA: string;
      DESCRIPCION: string;
      NOMBRE_CORTO: string;
      RUC_EMPRESA: string;
      DIRECCION: string;
      ACTIVIDAD: string;
    }>(query, { codEmpresa });

    // ✅ Si no existe, lanzar 404
    if (empresas.length === 0) {
      throw new NotFoundException(
        `Empresa con código ${codEmpresa} no encontrada`,
      );
    }

    const e = empresas[0];
    return {
      codigo: e.COD_EMPRESA,
      descripcion: e.DESCRIPCION,
      nombreCorto: e.NOMBRE_CORTO,
      ruc: e.RUC_EMPRESA,
      direccion: e.DIRECCION,
      actividad: e.ACTIVIDAD,
    };
  }
}
