import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { randomUUID } from 'crypto';
import { RefreshTokenRepository } from './refresh-token.repository';
import {
  IGenerateAccessTokenPayload,
  IGenerateRefreshTokenPayload,
  IRefreshTokenPayload,
} from './types';
import { isNil } from '@nestjs/common/utils/shared.utils';
import { CookieOptions } from 'express';
import { PinoLogger } from 'nestjs-pino';

@Injectable()
export class AuthService {
  constructor(
    private configService: ConfigService,
    private jwtService: JwtService,
    private refreshTokenRepository: RefreshTokenRepository,
    private logger: PinoLogger,
  ) {
    this.logger.setContext(AuthService.name);
  }

  public async generateAccessToken(
    payload: IGenerateAccessTokenPayload,
  ): Promise<string> {
    return this.jwtService.sign(
      { id: randomUUID(), ...payload },
      {
        expiresIn: this.configService.get<number>('JWT_ACCESS_TTL'),
      },
    );
  }

  public async generateRefreshToken(
    payload: IGenerateRefreshTokenPayload,
  ): Promise<string> {
    const token = this.jwtService.sign(
      { id: randomUUID(), ...payload },
      {
        expiresIn: this.configService.get<number>('JWT_REFRESH_TTL'),
      },
    );

    await this.refreshTokenRepository.saveToken(token);

    return token;
  }

  public getAuthCookiesSettings(): CookieOptions {
    return {
      httpOnly: true,
      secure: this.configService.get<boolean>('AUTH_COOKIE_SECURE'),
      sameSite:
        this.configService.get<'none' | 'lax' | 'strict'>(
          'AUTH_COOKIE_SAMESITE_POLICY',
        ) || 'strict',
    };
  }

  public async generateTokensPair({
    did,
    roles,
  }: {
    did: string;
    roles: string[];
  }): Promise<{
    accessToken: string;
    refreshToken: string;
  }> {
    const accessToken = await this.generateAccessToken({ did, roles });
    const refreshToken = await this.generateRefreshToken({ did, roles });

    return {
      accessToken,
      refreshToken,
    };
  }

  public async logIn({
    did,
    roles,
  }: {
    did: string;
    roles: string[];
  }): Promise<{
    accessToken: string;
    refreshToken: string;
  }> {
    return this.generateTokensPair({ did, roles });
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

    const { accessToken, refreshToken } = await this.generateTokensPair({
      did: tokenDecoded.did,
      roles: tokenDecoded.roles,
    });

    await this.invalidateRefreshToken(tokenDecoded.did, tokenDecoded.id);

    return {
      accessToken,
      refreshToken,
    };
  }

  public async logout({
    refreshTokenId,
    did,
    allDevices,
  }: {
    refreshTokenId?: string;
    did: string;
    allDevices: boolean;
  }) {
    if (!allDevices && isNil(refreshTokenId)) {
      throw new Error(
        `refreshTokenId needs to be provided when allDevices==false`,
      );
    }

    this.logger.debug(
      `logging out ${did}, ${
        refreshTokenId ? `refreshTokenId=${refreshTokenId}` : ''
      } ${allDevices ? ' on all devices' : ''}`,
    );

    if (allDevices) {
      await this.invalidateAllRefreshTokens(did);
    } else {
      await this.invalidateRefreshToken(did, refreshTokenId);
    }
  }
}
