import {
  HealthCheckError,
  HealthIndicator,
  HealthIndicatorResult,
} from '@nestjs/terminus';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { RedisService } from '../redis';

@Injectable()
export class RedisHealthIndicator extends HealthIndicator {
  constructor(
    private readonly config: ConfigService,
    private readonly redisService: RedisService,
  ) {
    super();
  }

  async checkStatus(key: string): Promise<HealthIndicatorResult> {
    if (this.redisService.status !== 'ready') {
      throw new HealthCheckError(
        'unexpected status',
        this.getStatus(key, false, {
          reason: this.redisService.status,
        }),
      );
    }
    return this.getStatus(key, true);
  }
}
