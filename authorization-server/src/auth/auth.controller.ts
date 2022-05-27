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
import { JwtAuthGuard, LoginGuard, ValidRefreshTokenGuard } from './guards';
import { decode as decodeJWT } from 'jsonwebtoken';
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
import { isNil } from '@nestjs/common/utils/shared.utils';

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

    if (isNil(await this.authService.getHAToken(didAccessTokenPayload.did))) {
      const errorMessage = `no HA long live token found for ${didAccessTokenPayload.did}`;
      this.logger.warn(errorMessage);
      throw new ForbiddenException(errorMessage);
    }

    const { accessToken, refreshToken } = await this.authService.logIn({
      did: didAccessTokenPayload.did,
      roles: didAccessTokenPayload.verifiedRoles.map((r) => r.namespace),
    });

    if (this.authService.getAuthCookieSettings().enabled) {
      const { name, options } = this.authService.getAuthCookieSettings();
      res.cookie(name, accessToken, {
        ...options,
        maxAge:
          (decodeJWT(accessToken) as IAccessTokenPayload).exp * 1000 -
          Date.now(),
      });
    }

    return new LoginResponseDto({ accessToken, refreshToken });
  }

  @Post('logout')
  @UseGuards(ValidRefreshTokenGuard)
  @ApiBody({ type: LogoutDto })
  @ApiCreatedResponse()
  async logout(
    @Body() body: LogoutDto,
    @Res({ passthrough: true }) res: Response,
  ): Promise<void> {
    const tokenDecoded = decodeJWT(body.refreshToken) as IRefreshTokenPayload;

    await this.authService.logout({
      did: tokenDecoded.did,
      refreshTokenId: tokenDecoded.id,
      allDevices: body.allDevices,
    });

    res.cookie(this.authService.getAuthCookieSettings().name, '', {
      expires: new Date(0),
    });
  }

  @Get('token-introspection')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('access-token')
  async introspect(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    this.logger.debug(
      `successful access token introspection: ${JSON.stringify(req.user)}`,
    );

    const did = (req.user as IAccessTokenPayload).did;

    const longLiveAccessToken: string = await this.authService.getHAToken(did);

    if (isNil(longLiveAccessToken)) {
      this.logger.warn(`no HA long live token found for ${did}`);
    } else {
      res.setHeader('X-HA-Token', longLiveAccessToken);
    }
  }

  @Post('refresh-token')
  @UseGuards(ValidRefreshTokenGuard)
  @ApiBody({ type: RefreshDto })
  @ApiOkResponse({ type: LoginResponseDto })
  async refresh(
    @Body() body: RefreshDto,
    @Res({ passthrough: true }) res: Response,
  ): Promise<LoginResponseDto> {
    const { accessToken, refreshToken } = await this.authService.refreshTokens(
      body.refreshToken,
    );

    if (this.authService.getAuthCookieSettings().enabled) {
      const { name, options } = this.authService.getAuthCookieSettings();
      res.cookie(name, accessToken, {
        ...options,
        maxAge:
          (decodeJWT(accessToken) as IAccessTokenPayload).exp * 1000 -
          Date.now(),
      });
    }

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
