import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

const logger = new Logger('bootstrap', { timestamp: true });
logger.log('starting');
logger.log(`NODE_ENV=${process.env.NODE_ENV}`);

const webserverLogger = new Logger('webserver', { timestamp: true });

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.enableShutdownHooks();

  const config = app.get<ConfigService>(ConfigService);

  const PORT = config.get('PORT');

  await app.listen(PORT, () => {
    webserverLogger.log('Listening at http://localhost:' + PORT);
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
