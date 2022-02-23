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

  describe('when application starting', function () {
    let spy: jest.SpyInstance;

    beforeEach(async function () {
      spy = jest.spyOn(service, 'connect').mockImplementation(async () => {});

      await service.onModuleInit();
    });

    afterEach(async function () {
      spy.mockClear().mockRestore();
    });

    it('should connect', async function () {
      expect(spy).toHaveBeenCalled();
    });
  });

  describe('when application stopping', function () {
    let spy: jest.SpyInstance;

    beforeEach(async function () {
      spy = jest
        .spyOn(service, 'disconnect')
        .mockImplementation(async () => {});

      await service.onApplicationShutdown();
    });

    afterEach(async function () {
      spy.mockClear().mockRestore();
    });

    it('should disconnect', async function () {
      expect(spy).toHaveBeenCalled();
    });
  });
});
