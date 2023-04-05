import { Logger } from 'nestjs-pino';
import { ConfigService } from '@nestjs/config';
import { INestApplication } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { readFileSync } from 'fs';
import { resolve } from 'path';

export function setupSwagger(
  app: INestApplication,
  config: ConfigService,
  logger: Logger,
) {
  logger.debug('setting Swagger');

  const version = readVersion();
  const buildInfo = readBuildInfo();

  SwaggerModule.setup(
    config.get<string>('SWAGGER_PATH'),
    app,
    SwaggerModule.createDocument(
      app,
      new DocumentBuilder()
        .setTitle('Energy Web DID Auth Service')
        .setVersion(
          `${version}${
            buildInfo ? ` (${buildInfo.gitSha}.${buildInfo.timestamp})` : ''
          }`,
        )
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

function readVersion(): string {
  let pkg;
  try {
    pkg = JSON.parse(
      readFileSync(resolve(__dirname, '../package.json')).toString('utf8'),
    );
  } catch (err) {
    console.log(`error reading/parsing package.json: ${err}`);
    return '';
  }

  return pkg.version;
}

function readBuildInfo(): { timestamp: string; gitSha: string } | null {
  let buildInfo;

  try {
    buildInfo = JSON.parse(
      readFileSync(resolve(__dirname, '../build.json')).toString('utf8'),
    );
  } catch (err) {
    console.log(`error reading/parsing build.json: ${err}`);
    return null;
  }

  return buildInfo;
}
