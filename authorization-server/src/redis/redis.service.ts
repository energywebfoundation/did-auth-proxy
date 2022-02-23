import {
  Injectable,
  Logger,
  OnApplicationShutdown,
  OnModuleInit,
} from '@nestjs/common';
import * as Redis from 'ioredis';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class RedisService
  extends Redis
  implements OnModuleInit, OnApplicationShutdown
{
  private readonly logger = new Logger(RedisService.name, {
    timestamp: true,
  });

  constructor(configService: ConfigService) {
    super({
      host: configService.get('REDIS_HOST'),
      port: configService.get('REDIS_PORT'),
      password: configService.get('REDIS_PASSWORD'),
      lazyConnect: true,
    });

    this.on('connect', () => this.logger.debug(`connecting`));
    this.on('ready', () => this.logger.log(`ready`));
    this.on('end', () => this.logger.log(`disconnected`));
    this.on('error', (err) => this.logger.error(`${err}`));
    this.on('reconnecting', () => this.logger.warn(`reconnecting`));
  }

  async onModuleInit() {
    try {
      await this.connect();
    } catch (err) {
      this.logger.error(`error initializing Redis connection: ${err}`);
    }
  }

  async onApplicationShutdown() {
    this.logger.debug('disconnecting');
    this.disconnect();
  }
}
