import { Logger } from 'nestjs-pino';
import { ConfigService } from '@nestjs/config';
import { INestApplication } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

export function setupSwagger(
  app: INestApplication,
  config: ConfigService,
  logger: Logger,
) {
  logger.debug('setting Swagger');

  SwaggerModule.setup(
    config.get<string>('SWAGGER_PATH'),
    app,
    SwaggerModule.createDocument(
      app,
      new DocumentBuilder()
        .setTitle('Energy Web DID Auth Service')
        .setVersion('0.0.1')
        .addBearerAuth(
          { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
          'access-token',
        )
        .build(),
    ),
    {
      customSiteTitle:
        'Swagger documentation for Energy Web DID Auth Service API',
      swaggerOptions: {
        persistAuthorization: true,
      },
    },
  );
}
