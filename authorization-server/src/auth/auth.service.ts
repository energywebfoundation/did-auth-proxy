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

    try {
      tokenDecoded = this.jwtService.verify(token);
    } catch (err) {
      this.logger.warn(`error when verifying token: ${err}`);
      return false;
    }

    const { id, did } = tokenDecoded;

    return !!(await this.refreshTokenRepository.getToken(did, id));
  }

  public async invalidateRefreshToken(did: string, id: string) {
    await this.refreshTokenRepository.deleteToken(did, id);
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
}
