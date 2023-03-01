import {
  BadRequestException,
  Body,
  Controller,
  ForbiddenException,
  Get,
  Post,
  Query,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { Request, Response } from 'express';
import {
  JwtAuthGuard,
  LoginGuard,
  ValidRefreshTokenGuard,
  ValidUserRolesGuard,
} from './guards';
import { decode as decodeJWT } from 'jsonwebtoken';
import { LoginDto, LoginResponseDto, LogoutDto, RefreshDto } from './dto';
import {
  ApiBearerAuth,
  ApiBody,
  ApiCreatedResponse,
  ApiOkResponse,
  ApiOperation,
} from '@nestjs/swagger';
import { ConfigService } from '@nestjs/config';
import { IAccessTokenPayload, IRefreshTokenPayload } from './types';
import { PinoLogger } from 'nestjs-pino';
import { AuthorisedUser, RoleCredentialStatus } from 'passport-did-auth';
import { NonceService } from './nonce.service';
import { SiweInitResponseDto } from './dto/siwe-init-response.dto';
import { SiweVerifyRequestDto } from './dto/siwe-verify-request.dto';
import { SiweMessage } from 'siwe';

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
    private readonly logger: PinoLogger,
    private readonly nonceService: NonceService,
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
  @UseGuards(LoginGuard, ValidUserRolesGuard)
  @ApiBody({ type: LoginDto })
  @ApiOkResponse({ type: LoginResponseDto })
  async login(
    @Body() body: LoginDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<LoginResponseDto | undefined> {
    this.logger.debug(`user has been logged in`);
    this.logger.debug(
      `identity token received: ${maskString(body.identityToken, 20, 20)}`,
    );

    this.logger.debug(
      `identity token content: ${JSON.stringify(
        decodeJWT(body.identityToken),
      )}`,
    );

    return this.loginCommon(req, res);
  }

  /**
   * implements logic common for all login methods
   */
  async loginCommon(req: Request, res: Response): Promise<LoginResponseDto> {
    //decodeJWT does not throw an error if no token provided
    if (typeof req.user !== 'string') {
      throw new Error(`unexpected req.user value: ${req.user}`);
    }

    const didAccessTokenPayload = decodeJWT(
      req.user as string,
    ) as unknown as AuthorisedUser;

    this.logger.debug(
      `did access token payload: ${JSON.stringify(didAccessTokenPayload)}`,
    );

    const { accessToken, refreshToken } = await this.authService.logIn({
      did: didAccessTokenPayload.did,
      roles: didAccessTokenPayload.userRoles
        .filter((role) => role.status === RoleCredentialStatus.VALID)
        .map((role) => role.namespace),
    });

    if (this.configService.get<boolean>('AUTH_COOKIE_ENABLED')) {
      this.setAuthCookies({
        res,
        accessToken,
        refreshToken,
      });
    }

    if (this.configService.get<boolean>('AUTH_HEADER_ENABLED')) {
      return new LoginResponseDto({ accessToken, refreshToken });
    }
  }

  @Get('login/siwe/initiate')
  @ApiOkResponse({ type: SiweInitResponseDto })
  async siweLoginInit(): Promise<SiweInitResponseDto> {
    return new SiweInitResponseDto({
      nonce: await this.nonceService.generateNonce(),
    });
  }

  @Post('login/siwe/verify')
  @UseGuards(LoginGuard, ValidUserRolesGuard)
  @ApiOkResponse({ type: LoginResponseDto })
  async siweLoginVerify(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @Body() body: SiweVerifyRequestDto,
  ): Promise<LoginResponseDto> {
    const { message } = body;
    let nonce: string;

    try {
      const siweMessage = new SiweMessage(message);
      nonce = siweMessage.nonce;
    } catch (err) {
      this.logger.warn(
        `error parsing SIWE message field: ${err.message || err}`,
      );
      throw new BadRequestException('invalid SIWE message');
    }

    if (!(await this.nonceService.validateOnce(nonce))) {
      throw new UnauthorizedException(`invalid nonce: ${nonce}`);
    }

    return await this.loginCommon(req, res);
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

    this.unsetAuthCookies(res);
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
  @UseGuards(ValidRefreshTokenGuard)
  @ApiBody({ type: RefreshDto })
  @ApiOkResponse({ type: LoginResponseDto })
  // backwards compatibility
  async refreshWithPost(
    @Body() body: RefreshDto,
    @Res({ passthrough: true }) res: Response,
  ): Promise<LoginResponseDto | undefined> {
    return this.refreshCommon(body.refreshToken, res);
  }

  @Get('refresh_token')
  //compatible with the SSI-HUB implementation
  async refreshWithGet(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @Query('refresh_token') refreshTokenFromQueryString: string,
  ): Promise<LoginResponseDto | undefined> {
    let refreshToken: string;

    if (this.configService.get<boolean>('AUTH_COOKIE_ENABLED')) {
      refreshToken =
        refreshTokenFromQueryString ||
        (req.cookies || {})[
          this.configService.get('AUTH_COOKIE_NAME_REFRESH_TOKEN')
        ];
    } else {
      refreshToken = refreshTokenFromQueryString;
    }

    if (!refreshToken) {
      this.logger.warn(`no refresh token provided`);
      throw new UnauthorizedException();
    }

    const refreshTokenIsValid = await this.authService.validateRefreshToken(
      refreshToken,
    );

    if (!refreshTokenIsValid) {
      this.logger.warn(`invalid refresh token provided`);
      throw new ForbiddenException();
    }

    return await this.refreshCommon(refreshToken, res);
  }

  async refreshCommon(
    refreshToken: string,
    res: Response,
  ): Promise<LoginResponseDto | undefined> {
    const { accessToken, refreshToken: newRefreshToken } =
      await this.authService.refreshTokens(refreshToken);

    if (this.configService.get<boolean>('AUTH_COOKIE_ENABLED')) {
      this.setAuthCookies({
        res,
        accessToken,
        refreshToken: newRefreshToken,
      });
    }

    if (this.configService.get<boolean>('AUTH_HEADER_ENABLED')) {
      return new LoginResponseDto({
        accessToken,
        refreshToken: newRefreshToken,
      });
    }
  }

  private setAuthCookies({
    res,
    accessToken,
    refreshToken,
  }: {
    res: Response;
    accessToken: string;
    refreshToken: string;
  }) {
    const options = this.authService.getAuthCookiesOptions();

    res.cookie(
      this.configService.get<string>('AUTH_COOKIE_NAME_ACCESS_TOKEN'),
      accessToken,
      {
        ...options,
        maxAge:
          (decodeJWT(accessToken) as IAccessTokenPayload).exp * 1000 -
          Date.now(),
      },
    );

    res.cookie(
      this.configService.get<string>('AUTH_COOKIE_NAME_REFRESH_TOKEN'),
      refreshToken,
      {
        ...options,
        maxAge:
          (decodeJWT(refreshToken) as IAccessTokenPayload).exp * 1000 -
          Date.now(),
      },
    );
  }

  private unsetAuthCookies(res: Response) {
    [
      this.configService.get<string>('AUTH_COOKIE_NAME_ACCESS_TOKEN'),
      this.configService.get<string>('AUTH_COOKIE_NAME_REFRESH_TOKEN'),
    ].forEach((cookieName: string) => res.clearCookie(cookieName));
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
