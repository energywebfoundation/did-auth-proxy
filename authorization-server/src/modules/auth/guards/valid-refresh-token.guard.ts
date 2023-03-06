import {
  CanActivate,
  ExecutionContext,
  Inject,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthService } from '../auth.service';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';
import { RefreshDto } from '../dto';

export class ValidRefreshTokenGuard implements CanActivate {
  constructor(
    @Inject(AuthService) private readonly authService: AuthService,
    @Inject(ConfigService) private readonly config: ConfigService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();
    const { body, cookies, method, query } = request;

    let refreshToken: string | undefined;

    if (method === 'POST') {
      refreshToken = this.extractFromPostBodyOrCookies(body, cookies);
    } else if (method === 'GET') {
      refreshToken = this.extractFromQueryStringOrCookies(
        cookies,
        query as { refresh_token?: string },
      );
    } else {
      throw new Error(
        `${ValidRefreshTokenGuard.name} executed with unexpected method: ${method}`,
      );
    }

    if (!refreshToken) {
      throw new UnauthorizedException();
    }

    request.user = refreshToken;

    return await this.authService.validateRefreshToken(refreshToken);
  }

  extractFromPostBodyOrCookies(
    body?: RefreshDto,
    cookies?: Record<string, string>,
  ): string | undefined {
    let refreshToken: string | undefined;
    const AUTH_HEADER_ENABLED = this.config.get<boolean>('AUTH_HEADER_ENABLED');
    const AUTH_COOKIE_ENABLED = this.config.get<boolean>('AUTH_COOKIE_ENABLED');

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

    return refreshToken;
  }

  extractFromQueryStringOrCookies(
    cookies?: Record<string, string>,
    query?: { refresh_token?: string },
  ): string | undefined {
    let refreshToken: string | undefined;
    const AUTH_HEADER_ENABLED = this.config.get<boolean>('AUTH_HEADER_ENABLED');
    const AUTH_COOKIE_ENABLED = this.config.get<boolean>('AUTH_COOKIE_ENABLED');

    const refreshTokenFromQueryString: string | undefined =
      query && query['refresh_token'];

    if (AUTH_COOKIE_ENABLED && AUTH_HEADER_ENABLED) {
      refreshToken =
        refreshTokenFromQueryString ||
        (cookies || {})[this.config.get('AUTH_COOKIE_NAME_REFRESH_TOKEN')];
    } else if (AUTH_COOKIE_ENABLED) {
      refreshToken = (cookies || {})[
        this.config.get('AUTH_COOKIE_NAME_REFRESH_TOKEN')
      ];
    } else if (AUTH_HEADER_ENABLED) {
      refreshToken = refreshTokenFromQueryString;
    }

    return refreshToken;
  }
}
