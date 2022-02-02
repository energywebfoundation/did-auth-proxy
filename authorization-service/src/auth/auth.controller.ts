import { Controller, Logger, Post, Req, Res, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { Request, Response } from 'express';
import { LoginGuard } from './login.guard';

@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name, {
    timestamp: true,
  });

  constructor(private readonly authService: AuthService) {}

  @Post('login')
  @UseGuards(LoginGuard)
  async login(@Req() req: Request, @Res() res: Response) {
    this.logger.debug(`user has been logged in`);

    this.logger.debug(
      `access token: ${maskString(req.user as string, 20, 20)}`,
    );

    return res.send({
      access_token: req.user,
      type: 'Bearer',
      expires_in: null, // TODO: to be implemented
      refresh_token: null, // TODO: to be implemented
    });
  }
}

/**
 *
 * @param text string to be masked
 * @param unmaskedStart number of unmasked characters at the beginning of the string
 * @param unmaskedEnd number of unmasked characters at the end of the string
 */
function maskString(
  text: string,
  unmaskedStart: number,
  unmaskedEnd: number,
): string {
  return text.replace(
    new RegExp(`^(.{${unmaskedStart}})(.*)(.{${unmaskedEnd}})$`),
    (m, $1, $2, $3) => `${$1}${'*'.repeat($2.length)}${$3}`,
  );
}
