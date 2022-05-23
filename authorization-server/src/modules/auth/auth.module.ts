import { Global, Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { AuthStrategy, JwtStrategy } from './strategies';
import { RedisModule } from '../redis';
import { RefreshTokenRepository } from './refresh-token.repository';
import { JwtModule } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { LoggerModule } from '../logger';
import { RolesValidationService } from './roles-validation.service';

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
    JwtStrategy,
    RefreshTokenRepository,
    RolesValidationService,
  ],
})
export class AuthModule {}
