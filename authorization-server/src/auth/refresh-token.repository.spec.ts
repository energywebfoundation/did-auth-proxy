import { Test, TestingModule } from '@nestjs/testing';
import { RefreshTokenRepository } from './refresh-token.repository';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { RedisService } from '../redis/redis.service';

describe('RefreshTokenRepository', () => {
  let repository: RefreshTokenRepository;

  const mockConfigService = {
    get(key: string) {
      return {}[key];
    },
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RefreshTokenRepository,
        { provide: JwtService, useValue: {} },
        { provide: ConfigService, useValue: mockConfigService },
        { provide: RedisService, useValue: {} },
      ],
    }).compile();

    repository = module.get<RefreshTokenRepository>(RefreshTokenRepository);
  });

  it('should be defined', () => {
    expect(repository).toBeDefined();
  });
});
