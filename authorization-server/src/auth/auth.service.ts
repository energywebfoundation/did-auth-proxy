import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { v4 } from 'uuid';
import { RefreshTokenRepository } from './refresh-token.repository';

interface IGenerateAccessTokenPayload {
  did: string;
  roles: string[];
}

interface IGenerateRefreshTokenPayload {
  did: string;
  roles: string[];
}

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
}
