import {
  Global,
  MiddlewareConsumer,
  Module,
  NestModule,
  RequestMethod,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { AuthStrategy, CachedAuthStrategy, JwtStrategy } from './strategies';
import { RedisModule } from '../redis';
import { RefreshTokenRepository } from './refresh-token.repository';
import { JwtModule } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { RolesValidationService } from './roles-validation.service';
import { NonceService } from './nonce.service';
import { DisableBlockAuthRoutesMiddleware } from '../../middlewares/disable-block-auth-routes.middleware';
import { PinoLogger } from 'nestjs-pino';

@Global()
@Module({
  imports: [
    RedisModule,
    JwtModule.registerAsync({
      useFactory: (config: ConfigService) => ({
        secret: config.get<string>('JWT_SECRET'),
      }),
      inject: [ConfigService],
    }),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    {
      provide: AuthStrategy,
      useFactory: (config: ConfigService, logger: PinoLogger) => {
        const useCached = config.get<boolean>('USE_CACHED_AUTH_STRATEGY');
        if (useCached) {
          logger.info(
            'Registering CachedAuthStrategy (without blockchain RPC fallback)',
          );
          return new CachedAuthStrategy(logger, config);
        } else {
          logger.info(
            'Registering legacy AuthStrategy (with blockchain RPC fallback)',
          );
          return new AuthStrategy(logger, config);
        }
      },
      inject: [ConfigService, PinoLogger],
    },
    JwtStrategy,
    NonceService,
    RefreshTokenRepository,
    RolesValidationService,
  ],
})
export class AuthModule implements NestModule {
  constructor(
    private readonly config: ConfigService,
    private readonly logger: PinoLogger,
  ) {
    logger.setContext(AuthModule.name);
  }

  configure(consumer: MiddlewareConsumer) {
    if (!this.config.get<boolean>('BLOCKNUM_AUTH_ENABLED')) {
      this.logger.info('POST /auth/login disabled');

      consumer
        .apply(DisableBlockAuthRoutesMiddleware)
        .forRoutes({ path: '/auth/login', method: RequestMethod.POST });
    } else {
      this.logger.info('POST /auth/login enabled');
    }
  }
}
