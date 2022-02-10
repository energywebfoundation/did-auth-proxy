/*eslint-disable @typescript-eslint/no-empty-function*/
import { Test, TestingModule } from '@nestjs/testing';
import { RedisService } from './redis.service';
import { ConfigService } from '@nestjs/config';

describe('RedisService', () => {
  let service: RedisService;

  const mockConfigService = {
    get(key: string) {
      return {}[key];
    },
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RedisService,
        { provide: ConfigService, useValue: mockConfigService },
      ],
    }).compile();

    service = module.get<RedisService>(RedisService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  it('should connect on application start', async function () {
    const spy = jest
      .spyOn(service, 'connect')
      .mockImplementation(async () => {});
    await service.onModuleInit();

    expect(spy).toHaveBeenCalled();

    await service.onModuleDestroy(); // test teardown
    spy.mockClear().mockRestore();
  });

  it('should should disconnect on application shutdown', async function () {
    const spy = jest
      .spyOn(service, 'disconnect')
      .mockImplementation(async () => {});
    await service.onModuleDestroy();

    expect(spy).toHaveBeenCalled();
    spy.mockClear().mockRestore();
  });
});
