import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

const logger = new Logger('bootstrap', { timestamp: true });
logger.log('starting');
logger.log(`NODE_ENV=${process.env.NODE_ENV}`);

const webserverLogger = new Logger('webserver', { timestamp: true });

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.enableShutdownHooks();

  const config = app.get<ConfigService>(ConfigService);

  SwaggerModule.setup(
    'swagger',
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

  const PORT = config.get('PORT');
  const BIND = config.get('BIND');

  logger.log(`starting http server bound to ${BIND}:${PORT}`);

  await app.listen(PORT, BIND, () => {
    webserverLogger.log(
      `Listening at http://localhost:${PORT}, bound to ${BIND}`,
    );
  });

  const server = app.getHttpServer();

  server.on('connection', connectionHandler);
}

bootstrap();

function connectionHandler(socket) {
  webserverLogger.debug(
    `connection from ${socket.remoteAddress}:${socket.remotePort}`,
  );

  const start = Date.now();

  socket.on('close', (error) => {
    webserverLogger.debug(
      `connection from ${socket.remoteAddress}:${socket.remotePort} closed${
        error ? ' with error' : ''
      }, ` +
        `${socket.bytesRead} bytes read, ${
          socket.bytesWritten
        } bytes written, ${Date.now() - start}ms elapsed`,
    );
  });
}
