import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { v4 } from 'uuid';
import { RefreshTokenRepository } from './refresh-token.repository';
import {
  IGenerateAccessTokenPayload,
  IGenerateRefreshTokenPayload,
  IRefreshTokenPayload,
} from './auth.interface';
import { LoggerService } from '../logger/logger.service';
import { isNil } from '@nestjs/common/utils/shared.utils';

@Injectable()
export class AuthService {
  constructor(
    private configService: ConfigService,
    private jwtService: JwtService,
    private refreshTokenRepository: RefreshTokenRepository,
    private logger: LoggerService,
  ) {
    this.logger.setContext(AuthService.name);
  }

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

    this.logger.debug(`validating refresh token`);

    try {
      tokenDecoded = this.jwtService.verify(token);
    } catch (err) {
      this.logger.warn(`error when verifying token: ${err}`);
      return false;
    }

    const { id, did } = tokenDecoded;

    const tokenWhitelisted = await this.refreshTokenRepository.getToken(
      did,
      id,
    );

    if (isNil(tokenWhitelisted)) {
      this.logger.warn(`refresh token is not whitelisted`);
      return false;
    } else {
      return true;
    }
  }

  public async invalidateRefreshToken(did: string, id: string) {
    await this.refreshTokenRepository.deleteToken(did, id);
  }

  public async invalidateAllRefreshTokens(did: string) {
    await this.refreshTokenRepository.deleteAllTokens(did);
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
