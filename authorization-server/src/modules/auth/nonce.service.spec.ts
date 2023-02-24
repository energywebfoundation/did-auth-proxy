import { Test, TestingModule } from '@nestjs/testing';
import { NonceService } from './nonce.service';
import { RedisService } from '../redis';
import { ConfigService } from '@nestjs/config';

const mockRedisService = {
  set: jest.fn(),
  get: jest.fn(),
  getdel: jest.fn(),
};

const configBase: Record<string, boolean | string | number> = {
  SIWE_NONCE_TTL: 666,
};

const mockConfigService = {
  get: jest.fn(),
};

describe('NonceService', function () {
  let nonceService: NonceService;

  beforeEach(async function () {
    mockConfigService.get.mockImplementation((key: string) => configBase[key]);

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        NonceService,
        { provide: RedisService, useValue: mockRedisService },
        { provide: ConfigService, useValue: mockConfigService },
      ],
    }).compile();

    nonceService = module.get<NonceService>(NonceService);
  });

  afterEach(async function () {
    Object.values(mockConfigService).forEach((mockedFunction) =>
      mockedFunction.mockReset(),
    );

    Object.values(mockRedisService).forEach((mockedFunction) =>
      mockedFunction.mockReset(),
    );
  });

  it('should be defined', async function () {
    expect(nonceService).toBeDefined();
  });

  describe('generateNonce', function () {
    it('should be defined', async function () {
      expect(nonceService.generateNonce).toBeDefined();
    });

    describe('when executed', function () {
      let exception: Error;
      let result: string;

      beforeEach(async function () {
        try {
          result = await nonceService.generateNonce();
        } catch (err) {
          exception = err;
        }
      });

      it('should execute', async function () {
        expect(exception).toBeUndefined();
      });

      it('should return a string', async function () {
        expect(result).toBeDefined();
        expect(typeof result).toBe('string');
      });

      it('should whitelist nonce in redis service', async function () {
        expect(mockRedisService.set).toHaveBeenCalledWith(
          `siwe-nonce:${result}`,
          JSON.stringify({ id: result }),
          'EX',
          mockConfigService.get('SIWE_NONCE_TTL'),
        );
      });
    });
  });

  describe('validate', function () {
    it('should be defined', async function () {
      expect(nonceService.validate).toBeDefined();
    });

    describe('when executed', function () {
      let exception: Error;
      let result: boolean;

      beforeEach(async function () {
        mockRedisService.get.mockReturnValueOnce('');

        try {
          result = await nonceService.validate('a nonce');
        } catch (err) {
          exception = err;
        }
      });

      it('should execute', async function () {
        expect(exception).toBeUndefined();
      });

      it('should fetch nonce from the redis service', async function () {
        expect(mockRedisService.get).toHaveBeenCalledWith('siwe-nonce:a nonce');
      });

      describe('when nonce is whitelisted', function () {
        beforeEach(async function () {
          mockRedisService.get.mockReturnValueOnce('a nonce');

          try {
            result = await nonceService.validate('a nonce');
          } catch (err) {
            exception = err;
          }
        });

        it('should resolve to true', async function () {
          expect(result).toBe(true);
        });
      });

      describe('when nonce is not whitelisted', function () {
        beforeEach(async function () {
          mockRedisService.get.mockReturnValueOnce(null);

          try {
            result = await nonceService.validate('a nonce');
          } catch (err) {
            exception = err;
          }
        });

        it('should resolve to true', async function () {
          expect(result).toBe(false);
        });
      });
    });
  });

  describe('validateOnce', function () {
    it('should be defined', async function () {
      expect(nonceService.validateOnce).toBeDefined();
    });

    describe('when executed', function () {
      let exception: Error;
      let result: boolean;

      beforeEach(async function () {
        mockRedisService.get.mockReturnValueOnce('');

        try {
          result = await nonceService.validateOnce('a nonce');
        } catch (err) {
          exception = err;
        }
      });

      it('should execute', async function () {
        expect(exception).toBeUndefined();
      });

      it('should fetch nonce from the redis service', async function () {
        expect(mockRedisService.getdel).toHaveBeenCalledWith(
          'siwe-nonce:a nonce',
        );
      });

      describe('when nonce is whitelisted', function () {
        beforeEach(async function () {
          mockRedisService.getdel.mockReturnValueOnce('a nonce');

          try {
            result = await nonceService.validateOnce('a nonce');
          } catch (err) {
            exception = err;
          }
        });

        it('should resolve to true', async function () {
          expect(result).toBe(true);
        });
      });

      describe('when nonce is not whitelisted', function () {
        beforeEach(async function () {
          mockRedisService.getdel.mockReturnValueOnce(null);

          try {
            result = await nonceService.validateOnce('a nonce');
          } catch (err) {
            exception = err;
          }
        });

        it('should resolve to true', async function () {
          expect(result).toBe(false);
        });
      });
    });
  });
});
