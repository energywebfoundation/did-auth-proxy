import { Injectable } from '@nestjs/common';
import {
  HealthCheckService as TerminusHealthCheckService,
  HealthIndicatorResult,
} from '@nestjs/terminus';
import { RpcHealthIndicator } from './rpc-health-indicator';
import { IpfsHealthIndicator } from './ipfs-health-indicator';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class HealthCheckService {
  private readonly healthChecks: (() => Promise<HealthIndicatorResult>)[];

  constructor(
    private readonly config: ConfigService,
    private readonly terminusHealthCheckService: TerminusHealthCheckService,
    private readonly rpc: RpcHealthIndicator,
    private readonly ipfs: IpfsHealthIndicator,
  ) {
    this.healthChecks = [
      ...(!config.get('DISABLE_HEALTHCHECK_RPC')
        ? [() => this.rpc.checkStatus('rpc')]
        : []),
      ...(!config.get('DISABLE_HEALTHCHECK_IPFS')
        ? [() => this.ipfs.checkStatus('ipfs')]
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
