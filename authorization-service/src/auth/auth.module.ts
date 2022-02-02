import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { AuthStrategy } from "./auth.strategy";

@Module({
  controllers: [AuthController],
  providers: [AuthService, AuthStrategy]
})
export class AuthModule {}
