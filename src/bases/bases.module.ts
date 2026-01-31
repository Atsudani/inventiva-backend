import { Module } from '@nestjs/common';
import { EmpresasController } from './controllers/empresas/empresas.controller';
import { PersonasController } from './controllers/personas/personas.controller';
import { EmpresasService } from './services/empresas/empresas.service';
import { PersonasService } from './services/personas/personas.service';
import { DatabaseModule } from 'src/database/database.module';

@Module({
  imports: [DatabaseModule],
  controllers: [EmpresasController, PersonasController],
  providers: [EmpresasService, PersonasService],
  exports: [EmpresasService, PersonasService],
})
export class BasesModule {}
