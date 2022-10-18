import { DynamicModule, Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AuthModule } from '../auth';
import { LoggerModule } from 'nestjs-pino';
import { envVarsValidationSchema } from './env-vars-validation-schema';
import { Request, Response } from 'express';
import { randomUUID } from 'crypto';

const validationOptions = {
  allowUnknown: true,
  abortEarly: false,
};

let config: DynamicModule;

try {
  config = ConfigModule.forRoot({
    isGlobal: true,
    validationOptions,
    validationSchema: envVarsValidationSchema,
  });
} catch (err) {
  console.log(err.toString());
  console.log('exiting');
  process.exit(1);
}

@Module({
  imports: [
    LoggerModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        pinoHttp: {
          genReqId: (req: Request) =>
            req.headers['x-request-id'] || randomUUID(),
          transport:
            configService.get<string>('NODE_ENV') !== 'production'
              ? {
                  target: 'pino-pretty',
                  options: {
                    colorize: !configService.get<string>('NO_COLOR'),
                    levelFirst: true,
                    translateTime: "UTC:yyyy-mm-dd'T'HH:MM:ss.l'Z'",
                    singleLine: true,
                  },
                }
              : null,
          level: configService.get<string>('LOG_LEVEL'),

          customLogLevel: function (req: Request, res: Response, err) {
            if (res.statusCode >= 400 && res.statusCode < 500) {
              return 'warn';
            } else if (res.statusCode >= 500 || err) {
              return 'error';
            }
            return 'info';
          },

          customReceivedMessage: function (req: Request) {
            return `request received: ${req.method} ${req.url}`;
          },

          customSuccessMessage: function (req: Request, res: Response) {
            return `request completed: ${req.method} ${req.url} (${res.statusCode} ${res.statusMessage})`;
          },

          customErrorMessage: function (req: Request, res: Response) {
            return `request errored: ${req.method} ${req.url} (${res.statusCode} ${res.statusMessage})`;
          },
        },
      }),
    }),
    config,
    AuthModule,
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
