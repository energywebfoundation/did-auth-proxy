import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { LoggerService, LogLevel } from './logger/logger.service';
import { ConfigService } from '@nestjs/config';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { Socket } from 'net';
import * as cookieParser from 'cookie-parser';

console.log(`${new Date().toISOString()} process starting`);

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    bufferLogs: true,
  });

  const config = app.get<ConfigService>(ConfigService);

  if (config.get<boolean>('AUTH_COOKIE_ENABLED')) {
    app.use(cookieParser());
  }

  app.useLogger(
    new LoggerService(null, {
      logLevels: config.get<string>('LOG_LEVELS').split(',') as LogLevel[],
    }),
  );

  app.enableShutdownHooks();

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

  const webserverLogger = new LoggerService('webserver', {
    logLevels: config.get<string>('LOG_LEVELS').split(',') as LogLevel[],
  });

  await app.listen(PORT, BIND, () => {
    webserverLogger.log(
      `Listening at http://localhost:${PORT}, bound to ${BIND}`,
    );
  });

  const server = app.getHttpServer();

  // Set server timeout to 5 minutes (in milliseconds)
  server.setTimeout(300000); // 300000ms = 5 minutes

  server.on('connection', (socket: Socket) =>
    connectionHandler(socket, webserverLogger),
  );
}

bootstrap();

function connectionHandler(socket: Socket, logger: LoggerService) {
  logger.debug(`connection from ${socket.remoteAddress}:${socket.remotePort}`);

  const start = Date.now();

  socket.on('close', (error) => {
    logger.debug(
      `connection from ${socket.remoteAddress}:${socket.remotePort} closed${
        error ? ' with error' : ''
      }, ` +
        `${socket.bytesRead} bytes read, ${
          socket.bytesWritten
        } bytes written, ${Date.now() - start}ms elapsed`,
    );
  });
}
