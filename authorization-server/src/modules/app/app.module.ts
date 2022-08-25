import { DynamicModule, Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AuthModule } from '../auth';
import { LoggerModule } from 'nestjs-pino';
import { envVarsValidationSchema } from './env-vars-validation-schema';
import { Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';

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
          genReqId: (req: Request) => req.headers['x-request-id'] || uuidv4(),
          transport:
            configService.get<string>('NODE_ENV') !== 'production'
              ? {
                  target: 'pino-pretty',
                  options: {
                    colorize: true,
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
