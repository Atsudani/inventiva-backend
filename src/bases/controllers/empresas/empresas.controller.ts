import { Controller, Get, Param } from '@nestjs/common';
import { EmpresasService } from 'src/bases/services/empresas/empresas.service';

@Controller('empresas')
export class EmpresasController {
  constructor(private readonly empresasService: EmpresasService) {}

  @Get()
  async findAll() {
    return this.empresasService.findAll();
  }

  @Get(':codigo')
  async findOne(@Param('codigo') codigo: string) {
    return this.empresasService.findById(codigo);
  }
}
