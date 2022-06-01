import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { HttpLoggerMiddleware } from '../../middlewares/http-logger.middleware';
import { AuthModule } from '../auth';
import { LoggerModule } from '../logger';
import { envVarsValidationSchema } from './env-vars-validation-schema';

const validationOptions = {
  allowUnknown: true,
  abortEarly: false,
};

@Module({
  imports: [
    LoggerModule,
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
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(HttpLoggerMiddleware).forRoutes('*');
  }
}
