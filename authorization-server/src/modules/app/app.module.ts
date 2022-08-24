import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
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
