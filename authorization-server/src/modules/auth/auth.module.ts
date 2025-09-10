import {
  Global,
  MiddlewareConsumer,
  Module,
  NestModule,
  RequestMethod,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { AuthStrategy, JwtStrategy } from './strategies';
import { RedisModule } from '../redis';
import { RefreshTokenRepository } from './refresh-token.repository';
import { JwtModule } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { RolesValidationService } from './roles-validation.service';
import { NonceService } from './nonce.service';
import { DisableBlockAuthRoutesMiddleware } from '../../middlewares/disable-block-auth-routes.middleware';
import { PinoLogger } from 'nestjs-pino';
import { providers } from 'ethers';
import { lru as createLru } from 'tiny-lru';
import { CACHED_JSONRPC } from './auth.const';

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
    AuthStrategy,
    JwtStrategy,
    NonceService,
    RefreshTokenRepository,
    RolesValidationService,
    {
      provide: CACHED_JSONRPC,
      inject: [ConfigService],
      useFactory: async (config: ConfigService) => {
        const rpcUrl = config.get<string>('RPC_URL');
        if (!rpcUrl) throw new Error('RPC_URL is not configured');

        const cache = createLru(50, 12_000, true); // 12s expired 'next block'
        const provider = new providers.StaticJsonRpcProvider(rpcUrl);

        // keep original send
        const originalSend = provider.send.bind(provider);

        // patch send with per-request cache
        provider.send = async (method: string, params: unknown[]) => {
          // Only cache these read-only methods
          const cacheableMethods = new Set([
            'eth_call',
            'eth_blockNumber',
            'eth_chainId',
          ]);

          if (!cacheableMethods.has(method)) {
            return originalSend(method, params);
          }

          const key = JSON.stringify([method, params]); // simpler key
          const entry = cache.get(key);

          if (entry !== undefined) {
            console.info(`[CACHE HIT] ${method}`);
            return entry;
          }

          console.info(`[CACHE MISS] ${method} ${key}`);
          const result = await originalSend(method, params);
          cache.set(key, result);
          return result;
        };

        (
          provider as providers.JsonRpcProvider & { clearCache: () => void }
        ).clearCache = () => cache.clear();

        return provider as providers.JsonRpcProvider & {
          clearCache: () => void;
        };
      },
    },
  ],
  exports: [CACHED_JSONRPC],
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
