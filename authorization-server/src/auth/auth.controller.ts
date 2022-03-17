import {
  Body,
  Controller,
  ForbiddenException,
  Get,
  Post,
  Req,
  Res,
  UseGuards,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { Request, Response } from 'express';
import { LoginGuard } from './login.guard';
import { decode as decodeJWT } from 'jsonwebtoken';
import { JwtAuthGuard } from './jwt.guard';
import { LoginResponseDto } from './dto/login-response.dto';
import {
  ApiBearerAuth,
  ApiBody,
  ApiCreatedResponse,
  ApiOkResponse,
  ApiOperation,
} from '@nestjs/swagger';
import { LoginDto } from './dto/login.dto';
import { ConfigService } from '@nestjs/config';
import { RefreshDto } from './dto/refresh.dto';
import {
  IAccessTokenPayload,
  IDidAccessTokenPayload,
  IRefreshTokenPayload,
} from './auth.interface';
import { LoggerService } from '../logger/logger.service';
import { LogoutDto } from './dto/logout.dto';

@Controller('auth')
@UsePipes(
  new ValidationPipe({
    whitelist: true,
  }),
)
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly configService: ConfigService,
    private readonly logger: LoggerService,
  ) {
    this.logger.setContext(AuthController.name);
  }

  @Get()
  @ApiOperation({
    description: 'Returns 200 response code with "OK"',
  })
  public async getStatus(): Promise<string> {
    return 'OK';
  }

  @Post('login')
  @UseGuards(LoginGuard)
  @ApiBody({ type: LoginDto })
  @ApiOkResponse({ type: LoginResponseDto })
  async login(
    @Body() body: LoginDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<LoginResponseDto> {
    this.logger.debug(`user has been logged in`);
    this.logger.debug(
      `identity token received: ${maskString(body.identityToken, 20, 20)}`,
    );

    this.logger.debug(
      `identity token content: ${JSON.stringify(
        decodeJWT(body.identityToken),
      )}`,
    );

    const didAccessTokenPayload = decodeJWT(
      req.user as string,
    ) as unknown as IDidAccessTokenPayload;

    this.logger.debug(
      `did access token payload: ${JSON.stringify(didAccessTokenPayload)}`,
    );

    const accessToken = await this.authService.generateAccessToken({
      did: didAccessTokenPayload.did,
      roles: didAccessTokenPayload.verifiedRoles.map((r) => r.namespace),
    });

    const refreshToken = await this.authService.generateRefreshToken({
      did: didAccessTokenPayload.did,
      roles: didAccessTokenPayload.verifiedRoles.map((r) => r.namespace),
    });

    if (this.configService.get<boolean>('AUTH_COOKIE_ENABLED')) {
      res.cookie(
        this.configService.get<string>('AUTH_COOKIE_NAME'),
        accessToken,
        {
          maxAge:
            (decodeJWT(accessToken) as IAccessTokenPayload).exp * 1000 -
            Date.now(),
          httpOnly: true,
          secure: this.configService.get<boolean>('AUTH_COOKIE_SECURE'),
          sameSite: 'strict', // setting this, because cookie is set to make it possible serve static content and html to a web browser
        },
      );
    }

    return new LoginResponseDto({ accessToken, refreshToken });
  }

  @Post('logout')
  @ApiBody({ type: LogoutDto })
  @ApiCreatedResponse()
  async logout(
    @Body() body: LogoutDto,
    @Res({ passthrough: true }) res: Response,
  ): Promise<void> {
    if (!(await this.authService.validateRefreshToken(body.refreshToken))) {
      throw new ForbiddenException('invalid refresh token');
    }

    const tokenDecoded = decodeJWT(body.refreshToken) as IRefreshTokenPayload;

    this.logger.debug(
      `logging out ${tokenDecoded.did}, refresh token id=${tokenDecoded.id}`,
    );

    if (body.allDevices) {
      await this.authService.invalidateAllRefreshTokens(tokenDecoded.did);
    } else {
      await this.authService.invalidateRefreshToken(
        tokenDecoded.did,
        tokenDecoded.id,
      );
    }

    if (this.configService.get<boolean>('AUTH_COOKIE_ENABLED')) {
      res.cookie(this.configService.get<string>('AUTH_COOKIE_NAME'), '', {
        expires: new Date(0),
      });
    }
  }

  @Get('token-introspection')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('access-token')
  async introspect(@Req() req: Request) {
    this.logger.debug(
      `successful access token introspection: ${JSON.stringify(req.user)}`,
    );
  }

  @Post('refresh-token')
  @ApiBody({ type: RefreshDto })
  @ApiOkResponse({ type: LoginResponseDto })
  async refresh(@Body() body: RefreshDto): Promise<LoginResponseDto> {
    const tokenIsValid = await this.authService.validateRefreshToken(
      body.refreshToken,
    );
    if (!tokenIsValid) {
      throw new ForbiddenException('invalid refresh token');
    }

    const { accessToken, refreshToken } = await this.authService.refreshTokens(
      body.refreshToken,
    );

    return new LoginResponseDto({ accessToken, refreshToken });
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
