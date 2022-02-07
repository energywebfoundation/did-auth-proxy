import {
  Body,
  Controller,
  Get,
  Logger,
  Post,
  Req,
  UseGuards,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { Request } from 'express';
import { LoginGuard } from './login.guard';
import { decode as decodeJWT } from 'jsonwebtoken';
import { JwtAuthGuard } from './jwt.guard';
import { LoginResponseDataDto } from './dto/login-response-data.dto';
import { ApiBody, ApiOkResponse } from '@nestjs/swagger';
import { LoginDataDTO } from './dto/login-data.dto';

@Controller('auth')
@UsePipes(
  new ValidationPipe({
    whitelist: true,
  }),
)
export class AuthController {
  private readonly logger = new Logger(AuthController.name, {
    timestamp: true,
  });

  constructor(private readonly authService: AuthService) {}

  @Post('login')
  @UseGuards(LoginGuard)
  @ApiBody({ type: LoginDataDTO })
  @ApiOkResponse({ type: LoginResponseDataDto })
  async login(
    @Body() body: LoginDataDTO,
    @Req() req: Request,
  ): Promise<LoginResponseDataDto> {
    this.logger.debug(`user has been logged in`);
    this.logger.debug(
      `identity token received: ${maskString(body.identityToken, 20, 20)}`,
    );

    this.logger.debug(
      `identity token content: ${JSON.stringify(
        decodeJWT(body.identityToken),
      )}`,
    );

    const accessToken: string = req.user as string;

    this.logger.debug(
      `access token generated: ${maskString(accessToken, 20, 20)}`,
    );

    this.logger.debug(
      `access token content: ${JSON.stringify(decodeJWT(accessToken))}`,
    );

    return {
      access_token: accessToken,
      type: 'Bearer',
      expires_in: null, // TODO: to be implemented
      refresh_token: null, // TODO: to be implemented
    };
  }

  @Get('token-introspection')
  @UseGuards(JwtAuthGuard)
  async introspect(@Req() req: Request) {
    this.logger.debug(
      `successful access token introspection: ${JSON.stringify(req.user)}`,
    );
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
