import { CanActivate, ExecutionContext, Inject } from '@nestjs/common';
import { AuthService } from '../auth.service';

export class ValidRefreshTokenGuard implements CanActivate {
  constructor(@Inject(AuthService) private readonly authService: AuthService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const { body } = context.switchToHttp().getRequest();
    if (!body?.refreshToken) {
      return false;
    }

    return await this.authService.validateRefreshToken(body.refreshToken);
  }
}
