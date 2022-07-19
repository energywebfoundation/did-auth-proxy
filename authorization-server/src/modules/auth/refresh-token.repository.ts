import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { RedisService } from '../redis';
import { IRefreshTokenPayload } from './types';
import { LoggerService } from '../logger';
import { Span } from 'nestjs-otel';

const KEY_PREFIX = 'refresh-token';

@Injectable()
export class RefreshTokenRepository {
  constructor(
    private jwtService: JwtService,
    private configService: ConfigService,
    private redis: RedisService,
    private logger: LoggerService,
  ) {
    this.logger.setContext(RefreshTokenRepository.name);
  }

  @Span()
  async saveToken(token: string): Promise<void> {
    const decoded = this.jwtService.verify(token) as IRefreshTokenPayload;
    const ttl = decoded.exp - Math.floor(Date.now() / 1000);
    const key = redisKey(KEY_PREFIX, decoded.did, decoded.id);

    this.logger.debug(`saving key: ${key}`);
    await this.redis.set(key, JSON.stringify(decoded), 'EX', ttl);
  }

  @Span()
  async getToken(did: string, id: string): Promise<string | null> {
    const key = redisKey(KEY_PREFIX, did, id);
    this.logger.debug(`getting key: ${key}`);
    const value = this.redis.get(key);
    if (!value) {
      this.logger.warn(`no value for key: ${key}`);
      return null;
    }
    return value;
  }

  @Span()
  async deleteToken(did: string, id: string): Promise<void> {
    const key = redisKey(KEY_PREFIX, did, id);
    this.logger.debug(`deleting key: ${key}`);
    await this.redis.del(key);
  }

  @Span()
  async deleteAllTokens(did: string): Promise<void> {
    const key = redisKey(KEY_PREFIX, did, '*');
    this.logger.debug(`deleting key: ${key}`);
    await this.redis.del(key);
  }
}

function redisKey(prefix: string, did: string, id: string) {
  return `${prefix}:${did}:${id}`;
}
