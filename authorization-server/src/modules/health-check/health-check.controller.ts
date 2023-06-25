import { Controller, Get } from '@nestjs/common';
import { HealthCheck } from '@nestjs/terminus';
import { HealthCheckService } from './health-check.service';
import { ApiTags } from '@nestjs/swagger';

@Controller('healthcheck')
@ApiTags('Healthcheck')
export class HealthCheckController {
  constructor(protected readonly healthCheckService: HealthCheckService) {}

  @Get('up')
  @HealthCheck()
  up() {
    return this.healthCheckService.isUp();
  }

  @HealthCheck()
  @Get('operational')
  operational() {
    return this.healthCheckService.isOperational();
  }
}
