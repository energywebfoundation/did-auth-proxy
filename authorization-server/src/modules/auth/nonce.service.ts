import { Injectable } from '@nestjs/common';
import { RedisService } from '../redis';
import { ConfigService } from '@nestjs/config';
import { generateNonce } from 'siwe';
import { isNil } from '@nestjs/common/utils/shared.utils';

@Injectable()
export class NonceService {
  private readonly redisKeyPrefix = 'siwe-nonce:';

  constructor(private config: ConfigService, private redis: RedisService) {}

  async generateNonce(): Promise<string> {
    const nonce = generateNonce();

    this.redis.set(
      this.createRedisKey(nonce),
      JSON.stringify({ id: nonce }),
      'EX',
      this.config.get('SIWE_NONCE_TTL'),
    );

    return nonce;
  }

  /**
   * Keeps nonce whitelisted after validation
   */
  async validate(nonce: string): Promise<boolean> {
    const result = await this.redis.get(this.createRedisKey(nonce));
    return !isNil(result);
  }

  /**
   * Invalidates provided nonce in the same atomic step
   */
  async validateOnce(nonce: string): Promise<boolean> {
    const result = await this.redis.getdel(this.createRedisKey(nonce));
    return !isNil(result);
  }

  createRedisKey(nonce: string) {
    return `${this.redisKeyPrefix}${nonce}`;
  }
}
