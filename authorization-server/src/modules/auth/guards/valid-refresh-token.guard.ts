import {
  CanActivate,
  ExecutionContext,
  Inject,
  NotImplementedException,
} from '@nestjs/common';
import { AuthService } from '../auth.service';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';

export class ValidRefreshTokenGuard implements CanActivate {
  constructor(
    @Inject(AuthService) private readonly authService: AuthService,
    @Inject(ConfigService) private readonly config: ConfigService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request: Request = context.switchToHttp().getRequest();
    const { body, cookies, method } = request;
    const AUTH_HEADER_ENABLED = this.config.get<boolean>('AUTH_HEADER_ENABLED');
    const AUTH_COOKIE_ENABLED = this.config.get<boolean>('AUTH_COOKIE_ENABLED');

    let refreshToken: string;

    if (method === 'POST') {
      if (AUTH_COOKIE_ENABLED && AUTH_HEADER_ENABLED) {
        refreshToken =
          body?.refreshToken ||
          (cookies || {})[this.config.get('AUTH_COOKIE_NAME_REFRESH_TOKEN')];
      } else if (AUTH_COOKIE_ENABLED) {
        refreshToken = (cookies || {})[
          this.config.get('AUTH_COOKIE_NAME_REFRESH_TOKEN')
        ];
      } else if (AUTH_HEADER_ENABLED) {
        refreshToken = body?.refreshToken;
      }
    } else if (method === 'GET') {
      throw new NotImplementedException();
    } else {
      throw new Error(
        `${ValidRefreshTokenGuard.name} executed with unexpected method: ${method}`,
      );
    }

    if (!refreshToken) {
      return false;
    }

    return await this.authService.validateRefreshToken(refreshToken);
  }
}
