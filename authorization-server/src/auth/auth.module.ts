import { Global, Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { AuthStrategy, JwtStrategy } from './strategies';
import { RedisModule } from '../redis/redis.module';
import { RefreshTokenRepository } from './refresh-token.repository';
import { JwtModule } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { LoggerModule } from '../logger/logger.module';
import { HomeAssistantTokenRepository } from './home-assistant-token.repository';

@Global()
@Module({
  imports: [
    RedisModule,
    LoggerModule,
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
    HomeAssistantTokenRepository,
    JwtStrategy,
    RefreshTokenRepository,
  ],
})
export class AuthModule {}
