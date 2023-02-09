import { Module } from '@nestjs/common';
import { HealthCheckService } from './health-check.service';
import { HealthCheckController } from './health-check.controller';
import { TerminusModule } from '@nestjs/terminus';
import { RpcHealthIndicator } from './rpc-health-indicator';
import { IpfsHealthIndicator } from './ipfs-health-indicator';
import { RedisHealthIndicator } from './redis-health-indicator';
import { RedisService } from '../redis';

@Module({
  imports: [TerminusModule],
  controllers: [HealthCheckController],
  providers: [
    HealthCheckService,
    RpcHealthIndicator,
    IpfsHealthIndicator,
    RedisHealthIndicator,
    RedisService,
  ],
})
export class HealthCheckModule {}
