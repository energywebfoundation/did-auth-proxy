import { Injectable } from '@nestjs/common';
import {
  HealthCheckService as TerminusHealthCheckService,
  HealthIndicatorResult,
} from '@nestjs/terminus';
import { RpcHealthIndicator } from './rpc-health-indicator';
import { IpfsHealthIndicator } from './ipfs-health-indicator';
import { ConfigService } from '@nestjs/config';
import { RedisHealthIndicator } from './redis-health-indicator';

@Injectable()
export class HealthCheckService {
  private readonly healthChecks: (() => Promise<HealthIndicatorResult>)[];

  constructor(
    private readonly config: ConfigService,
    private readonly terminusHealthCheckService: TerminusHealthCheckService,
    private readonly rpc: RpcHealthIndicator,
    private readonly ipfs: IpfsHealthIndicator,
    private readonly redis: RedisHealthIndicator,
  ) {
    this.healthChecks = [
      ...(!config.get('DISABLE_HEALTHCHECK_RPC')
        ? [() => this.rpc.checkStatus('rpc')]
        : []),

      ...(!config.get('DISABLE_HEALTHCHECK_REDIS')
        ? [() => this.redis.checkStatus('redis')]
        : []),
    ];
  }

  async isUp() {
    return this.terminusHealthCheckService.check([]);
  }

  async isOperational() {
    return this.terminusHealthCheckService.check(this.healthChecks);
  }
}
