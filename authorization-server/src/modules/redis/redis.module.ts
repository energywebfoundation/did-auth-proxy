import { Module } from '@nestjs/common';
import { RedisService } from './redis.service';
import { LoggerModule } from '../logger';

@Module({
  imports: [LoggerModule],
  providers: [RedisService],
  exports: [RedisService],
})
export class RedisModule {}
