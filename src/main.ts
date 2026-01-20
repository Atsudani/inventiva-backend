import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true, // elimina campos extra
      forbidNonWhitelisted: true, // error si mandan campos que no existen
      transform: true, // convierte tipos
    }),
  );

  await app.listen(process.env.PORT ?? 3000);
}

// bootstrap(); me tira warning jeje
bootstrap().catch((err) => {
  console.error('Nest bootstrap failed', err);
  process.exit(1);
});
