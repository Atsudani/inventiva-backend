import 'colors';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import cookieParser from 'cookie-parser'; // 👈 DEBE ESTAR ESTE IMPORT

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // 👇 ESTO DEBE ESTAR **ANTES** DE enableCors()
  app.use(cookieParser());

  app.enableCors({
    origin: ['http://localhost:3000'],
    credentials: true,
  });

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true, // elimina campos extra
      forbidNonWhitelisted: true, // error si mandan campos que no existen
      transform: true, // convierte tipos
    }),
  );

  await app.listen(process.env.PORT ?? 3005);
  console.log(':::::::Aplicacion corriendo en puerto 3005 🚀✅:::::::'.bgGreen);
}

// bootstrap(); me tira warning jeje
bootstrap().catch((err) => {
  console.error('Nest bootstrap failed', err);
  process.exit(1);
});
