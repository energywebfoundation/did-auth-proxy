import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { v4 } from 'uuid';
import { RefreshTokenRepository } from './refresh-token.repository';
import {
  IGenerateAccessTokenPayload,
  IGenerateRefreshTokenPayload,
  IRefreshTokenPayload,
} from './auth.interface';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name, {
    timestamp: true,
  });


  constructor(
    private configService: ConfigService,
    private jwtService: JwtService,
    private refreshTokenRepository: RefreshTokenRepository,
  ) {}

  public async generateAccessToken(
    payload: IGenerateAccessTokenPayload,
  ): Promise<string> {
    return this.jwtService.sign(
      { id: v4(), ...payload },
      {
        expiresIn: this.configService.get<number>('JWT_ACCESS_TTL'),
      },
    );
  }

  public async generateRefreshToken(
    payload: IGenerateRefreshTokenPayload,
  ): Promise<string> {
    const token = this.jwtService.sign(
      { id: v4(), ...payload },
      {
        expiresIn: this.configService.get<number>('JWT_REFRESH_TTL'),
      },
    );

    await this.refreshTokenRepository.saveToken(token);

    return token;
  }

  public async validateRefreshToken(token: string): Promise<boolean> {
    let tokenDecoded: IRefreshTokenPayload;

    try {
      tokenDecoded = this.jwtService.verify(token);
    } catch (err) {
      this.logger.warn(`error when verifying token: ${err}`);
      return false;
    }

    const { id, did } = tokenDecoded;

    return !!(await this.refreshTokenRepository.getToken(did, id));
  }

  public async invalidateRefreshToken(did, id) {
    await this.refreshTokenRepository.deleteToken(did, id);
  }

  public async refreshTokens(
    token: string,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    const tokenDecoded = this.jwtService.verify(token) as IRefreshTokenPayload;

    const accessToken = await this.generateAccessToken({
      did: tokenDecoded.did,
      roles: tokenDecoded.roles,
    });

    const refreshToken = await this.generateRefreshToken({
      did: tokenDecoded.did,
      roles: tokenDecoded.roles,
    });

    await this.invalidateRefreshToken(tokenDecoded.did, tokenDecoded.id);

    return {
      accessToken,
      refreshToken,
    };
  }
}
