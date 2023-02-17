import { CanActivate, ExecutionContext, Inject } from '@nestjs/common';
import { AuthService } from '../auth.service';
import { ConfigService } from '@nestjs/config';

export class ValidRefreshTokenGuard implements CanActivate {
  constructor(
    @Inject(AuthService) private readonly authService: AuthService,
    @Inject(ConfigService) private readonly config: ConfigService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const { body, cookies } = context.switchToHttp().getRequest();

    const refreshToken =
      body?.refreshToken ||
      (cookies || {})[this.config.get('AUTH_COOKIE_NAME_REFRESH_TOKEN')];

    if (!refreshToken) {
      return false;
    }

    return await this.authService.validateRefreshToken(refreshToken);
  }
}
