import { NestFactory } from '@nestjs/core';
import { AppModule } from './modules';
import { ConfigService } from '@nestjs/config';
import { Socket } from 'net';
import * as cookieParser from 'cookie-parser';
import { AxiosExceptionFilter } from './exception-filters/axios-exception-filter';
import { Logger, LoggerErrorInterceptor, PinoLogger } from 'nestjs-pino';
import { setupSwagger } from './setup-swagger.function';
import { setupCors } from './setup-cors.function';

console.log(`${new Date().toISOString()} process starting`);

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    bufferLogs: true,
  });

  const config = app.get<ConfigService>(ConfigService);

  if (config.get<boolean>('AUTH_COOKIE_ENABLED')) {
    app.use(cookieParser());
  }

  app.useLogger(app.get(Logger));
  app.flushLogs();

  setupCors(app, config);

  app.useGlobalInterceptors(new LoggerErrorInterceptor());
  app.useGlobalFilters(
    new AxiosExceptionFilter(app.getHttpAdapter(), new PinoLogger({})),
  );

  setupSwagger(app, config, app.get(Logger));

  const signals: Record<string, number> = {
    SIGHUP: 1,
    SIGINT: 2,
    SIGTERM: 15,
  };

  Object.keys(signals).forEach((signal) => {
    process.on(signal, async () => {
      await app.close();

      /** default behavior of the nodejs when receiving `SIGTERM` and `SIGINT` signals is to
       *  exit with code 128 + signal number. Here, we overwrite default handlers, so to keep
       *  this behavior unchanged, process needs to exit with `signals[signal] + 128` exit signal
       */
      const exitSignal = signals[signal] + 128;

      process.on('exit', () =>
        console.log(
          `INFO [${new Date().toISOString()}] (${
            process.pid
          }) exiting with signal ${exitSignal}`,
        ),
      );

      await app.flushLogs();
      process.exit(exitSignal);
    });
  });

  const PORT = config.get('PORT');
  const BIND = config.get('BIND');

  const webserverLogger = new PinoLogger({});

  webserverLogger.setContext('webserver');

  await app.listen(PORT, BIND, () => {
    webserverLogger.info(
      `Listening at http://localhost:${PORT}, bound to ${BIND}`,
    );

    webserverLogger.info(
      `Swagger doc server at ` +
        `http://localhost:${PORT}/${config.get('SWAGGER_PATH')}`,
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

function connectionHandler(socket: Socket, logger: PinoLogger) {
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
