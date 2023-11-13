import { INestApplication } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Logger } from 'nestjs-pino';
import { CorsOptions } from '@nestjs/common/interfaces/external/cors-options.interface';

export function setupCors(app: INestApplication, config: ConfigService) {
  const corsOptions: CorsOptions = {
    maxAge: config.get<number>('CORS_MAX_AGE'),
    credentials: true,
    origin:
      config.get<string>('CORS_ORIGIN') === '*'
        ? '*'
        : config.get<string>('CORS_ORIGIN')?.match(',')
          ? config
              .get<string>('CORS_ORIGIN')
              ?.split(',')
              .map((o) => o.trim())
          : config.get<string>('CORS_ORIGIN'),
  };

  app
    .get(Logger)
    .debug(
      `setting CORS headers with settings: ${JSON.stringify(corsOptions)}`,
    );
  app.enableCors(corsOptions);
}
