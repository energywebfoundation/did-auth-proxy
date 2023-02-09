import { Module } from '@nestjs/common';
import { HealthCheckService } from './health-check.service';
import { HealthCheckController } from './health-check.controller';
import { TerminusModule } from '@nestjs/terminus';
import { RpcHealthIndicator } from './rpc-health-indicator';
import { IpfsHealthIndicator } from './ipfs-health-indicator';

@Module({
  imports: [TerminusModule],
  controllers: [HealthCheckController],
  providers: [HealthCheckService, RpcHealthIndicator, IpfsHealthIndicator],
})
export class HealthCheckModule {}
