import {
  Body,
  Controller,
  ForbiddenException,
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
import { ApiBearerAuth, ApiBody, ApiOkResponse } from '@nestjs/swagger';
import { LoginDataDTO } from './dto/login-data.dto';
import { ConfigService } from '@nestjs/config';
import { RefreshDto } from './dto/refresh.dto';

interface IDidAccessTokenPayload {
  did: string;
  verifiedRoles: { name: string; namespace: string }[];
}

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

  constructor(
    private readonly authService: AuthService,
    private readonly configService: ConfigService,
  ) {}

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

    const didAccessTokenPayload = decodeJWT(
      req.user as string,
    ) as unknown as IDidAccessTokenPayload;

    this.logger.debug(
      `did access token payload: ${JSON.stringify(didAccessTokenPayload)}`,
    );

    const accessTokenGenerationStart = Date.now();

    const accessToken = await this.authService.generateAccessToken({
      did: didAccessTokenPayload.did,
      roles: didAccessTokenPayload.verifiedRoles.map((r) => r.namespace),
    });

    const refreshToken = await this.authService.generateRefreshToken({
      did: didAccessTokenPayload.did,
      roles: didAccessTokenPayload.verifiedRoles.map((r) => r.namespace),
    });

    return {
      access_token: accessToken,
      type: 'Bearer',
      expires_in:
        this.configService.get<number>('JWT_ACCESS_TTL') -
        Math.ceil((Date.now() - accessTokenGenerationStart) / 1000),
      refresh_token: refreshToken,
    };
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
  @ApiOkResponse({ type: LoginResponseDataDto })
  async refresh(@Body() body: RefreshDto): Promise<LoginResponseDataDto> {
    const tokenIsValid = await this.authService.validateRefreshToken(
      body.refreshToken,
    );
    if (!tokenIsValid) {
      throw new ForbiddenException('invalid refresh token');
    }

    const accessTokenGenerationStart = Date.now();

    const { access_token, refresh_token } =
      await this.authService.refreshTokens(body.refreshToken);

    return {
      access_token,
      type: 'Bearer',
      expires_in:
        this.configService.get<number>('JWT_ACCESS_TTL') -
        Math.ceil((Date.now() - accessTokenGenerationStart) / 1000),
      refresh_token,
    };
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
