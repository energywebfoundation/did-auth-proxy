import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AuthModule } from '../auth';
import { LoggerModule } from 'nestjs-pino';
import { envVarsValidationSchema } from './env-vars-validation-schema';
import { Request } from 'express';
import { v4 as uuidv4 } from 'uuid';

const validationOptions = {
  allowUnknown: true,
  abortEarly: false,
};

@Module({
  imports: [
    LoggerModule.forRootAsync({
      useFactory: () => ({
        pinoHttp: {
          genReqId: (req: Request) => req.headers['x-request-id'] || uuidv4(),
          transport: {
            target: 'pino-pretty',
            options: {
              colorize: true,
              levelFirst: true,
              translateTime: "UTC:yyyy-mm-dd'T'HH:MM:ss.l'Z'",
              singleLine: true,
            },
          },
          level: 'debug',
        },
      }),
    }),
    ConfigModule.forRoot({
      isGlobal: true,
      validationOptions,
      validationSchema: envVarsValidationSchema,
    }),
    AuthModule,
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
