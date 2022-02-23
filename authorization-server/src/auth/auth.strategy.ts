import { LoginStrategy } from 'passport-did-auth';
import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { LoggerService } from '../logger/logger.service';

@Injectable()
export class AuthStrategy extends PassportStrategy(LoginStrategy, 'login') {
  constructor(private readonly logger: LoggerService) {
    super({
      jwtSecret: process.env.JWT_SECRET,
      jwtSignOptions: { algorithm: 'HS256' },
      rpcUrl: process.env.RPC_URL,
      cacheServerUrl: process.env.CACHE_SERVER_URL,
      acceptedRoles: parseAcceptedRoles(process.env.ACCEPTED_ROLES),
      privateKey: process.env.CACHE_SERVER_LOGIN_PRVKEY,
    });

    this.logger.setContext(AuthStrategy.name);

    this.logger.log(
      `accepted roles: ${parseAcceptedRoles(
        process.env.ACCEPTED_ROLES,
      ).join()}`,
    );
  }
}

function parseAcceptedRoles(ACCEPTED_ROLES: string): string[] {
  return ACCEPTED_ROLES ? ACCEPTED_ROLES.split(',') : [];
}
