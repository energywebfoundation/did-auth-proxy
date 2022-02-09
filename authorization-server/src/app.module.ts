import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
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
  BIND: Joi.string().ip().default('127.0.0.1'),

  RPC_URL: Joi.string().uri().default('https://volta-rpc.energyweb.org/'),
  CACHE_SERVER_URL: Joi.string()
    .uri()
    .default('https://identitycache-dev.energyweb.org/v1'),
  CACHE_SERVER_LOGIN_PRVKEY: Joi.string()
    .regex(/^(0x)?[0-9a-f]+$/)
    .required(),

  REDIS_HOST: Joi.string().hostname().default('127.0.0.1'),
  REDIS_PORT: Joi.number().port().default(6379),
  REDIS_PASSWORD: Joi.string(),

  JWT_SECRET: Joi.string().required(),
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
  controllers: [],
  providers: [AppService],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(HttpLoggerMiddleware).forRoutes('*');
  }
}
