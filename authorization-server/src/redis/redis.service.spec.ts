/*eslint-disable @typescript-eslint/no-empty-function*/
import { Test, TestingModule } from '@nestjs/testing';
import { RedisService } from './redis.service';
import { ConfigService } from '@nestjs/config';

describe('RedisService', () => {
  let service: RedisService;

  const mockConfigService = {
    get(key: string): string | number | boolean | undefined {
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

  describe('onModuleInit()', function () {
    let spyConnect: jest.SpyInstance;

    describe('when able to connect to the Redis server', function () {
      beforeEach(async function () {
        spyConnect = jest
          .spyOn(service, 'connect')
          .mockImplementation(async () => {});
      });

      afterEach(async function () {
        spyConnect.mockClear().mockRestore();
      });

      describe('when called', function () {
        let exceptionThrown: Error;

        beforeEach(async function () {
          try {
            await service.onModuleInit();
          } catch (err) {
            exceptionThrown = err;
          }
        });

        it('should execute', async function () {
          expect(exceptionThrown).toBeUndefined();
        });

        it('should connect', async function () {
          expect(spyConnect).toHaveBeenCalled();
        });
      });
    });

    describe('when not able to connect to the Redis server', function () {
      let spy: jest.SpyInstance;

      beforeEach(async function () {
        spy = jest.spyOn(service, 'connect').mockImplementation(async () => {
          throw new Error('Connection is closed');
        });
      });

      afterEach(async function () {
        spy.mockClear().mockRestore();
      });

      describe('when FAIL_ON_REDIS_UNAVAILABLE=true', function () {
        let spyConfigService: jest.SpyInstance;

        beforeEach(async function () {
          spyConfigService = jest
            .spyOn(mockConfigService, 'get')
            .mockImplementation((key: string) => {
              return {
                FAIL_ON_REDIS_UNAVAILABLE: true,
              }[key];
            });
        });

        afterEach(async function () {
          spyConfigService.mockClear().mockRestore();
        });

        describe('when called', function () {
          let exceptionThrown: Error;

          beforeEach(async function () {
            try {
              await service.onModuleInit();
            } catch (err) {
              exceptionThrown = err;
            }
          });

          it('should throw an error', async function () {
            expect(exceptionThrown).toBeDefined();
          });
        });
      });

      describe('when FAIL_ON_REDIS_UNAVAILABLE=false', function () {
        let spyConfigService: jest.SpyInstance;

        beforeEach(async function () {
          spyConfigService = jest
            .spyOn(mockConfigService, 'get')
            .mockImplementation((key: string) => {
              return {
                FAIL_ON_REDIS_UNAVAILABLE: false,
              }[key];
            });
        });

        afterEach(async function () {
          spyConfigService.mockClear().mockRestore();
        });

        describe('when called', function () {
          let exceptionThrown: Error;

          beforeEach(async function () {
            try {
              await service.onModuleInit();
            } catch (err) {
              exceptionThrown = err;
            }
          });

          it('should execute', async function () {
            expect(exceptionThrown).toBeUndefined();
          });
        });
      });
    });
  });

  describe('onModuleDestroy()', function () {
    describe('when called', function () {
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
});
