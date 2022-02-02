import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ConfigModule } from '@nestjs/config';
import * as Joi from 'joi';
import { HttpLoggerMiddleware } from './middlewares/http-logger.middleware';
import { AuthModule } from './auth/auth.module';

const validationOptions = {
  allowUnknown: true,
  abortEarly: false,
};

export const validationSchema = Joi.object({
  NODE_ENV: Joi.string()
    .valid('development', 'production', 'test')
    .default('development'),

  PORT: Joi.number().default(3000),
});

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      validationOptions,
      validationSchema,
    }),
    AuthModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(HttpLoggerMiddleware).forRoutes('*');
  }
}
