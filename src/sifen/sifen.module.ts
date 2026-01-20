import { Module } from '@nestjs/common';
import { SifenController } from './sifen.controller';
import { SifenService } from './sifen.service';
import { DatabaseModule } from 'src/database/database.module';

@Module({
  imports: [DatabaseModule],
  controllers: [SifenController],
  providers: [SifenService],
})
export class SifenModule {}
