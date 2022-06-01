/* eslint-disable @typescript-eslint/no-empty-function */
import { Test, TestingModule } from '@nestjs/testing';
import { RefreshTokenRepository } from './refresh-token.repository';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { RedisService } from '../redis';
import { JsonWebTokenError, sign, TokenExpiredError } from 'jsonwebtoken';
import { v4 } from 'uuid';
import { LoggerService } from '../logger';

describe('RefreshTokenRepository', () => {
  let repository: RefreshTokenRepository;
  let jwtService: JwtService;

  const mockConfigService = {
    get(key: string) {
      return {
        LOG_LEVELS: 'error,warn',
      }[key];
    },
  };
  const mockRedisService = {
    set() {},
    get() {},
    del() {},
  };

  const payload = {
    did: 'did:eth:0x82FcB31385EaBe261E4e6003b9F2Cb2af34e2654',
    id: '23292026-cb3e-432f-a0d0-fb61c34cb1ac',
    roles: [
      'role1.roles.app-test2.apps.artur.iam.ewc',
      'role2.roles.app-test2.apps.artur.iam.ewc',
    ],
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      imports: [
        JwtModule.register({
          secretOrPrivateKey: 'secretKeyValid',
          signOptions: {
            expiresIn: 3600,
          },
        }),
      ],
      providers: [
        RefreshTokenRepository,
        LoggerService,
        { provide: ConfigService, useValue: mockConfigService },
        { provide: RedisService, useValue: mockRedisService },
      ],
    }).compile();

    repository = module.get<RefreshTokenRepository>(RefreshTokenRepository);
    jwtService = module.get(JwtService);
  });

  it('should be defined', () => {
    expect(repository).toBeDefined();
  });

  describe('saveToken()', function () {
    describe('when called with valid token', function () {
      let spy: jest.SpyInstance;
      let token: string;

      beforeEach(async function () {
        token = jwtService.sign({ id: v4(), ...payload });

        spy = jest.spyOn(mockRedisService, 'set');

        await repository.saveToken(token);
      });

      afterEach(async function () {
        spy.mockClear().mockRestore();
      });

      it('should save a taken', async function () {
        expect(spy).toHaveBeenCalledWith(
          `refresh-token:${payload.did}:${payload.id}`,
          JSON.stringify(jwtService.decode(token)),
          'EX',
          3600,
        );
      });
    });

    describe('when called with expired token', function () {
      let spy: jest.SpyInstance;
      let token: string;
      let exceptionThrown: Error;

      beforeEach(async function () {
        token = jwtService.sign({ id: v4(), ...payload }, { expiresIn: 0 });

        spy = jest.spyOn(mockRedisService, 'set');

        exceptionThrown = null;

        try {
          await repository.saveToken(token);
        } catch (err) {
          exceptionThrown = err;
        }
      });

      afterEach(async function () {
        spy.mockClear().mockRestore();
      });

      it('should throw TokenExpiredError', async function () {
        expect(exceptionThrown).toBeInstanceOf(TokenExpiredError);
      });

      it('should throw exception before saving a token', async function () {
        expect(spy).not.toHaveBeenCalled();
      });
    });

    describe('when called with token signed with invalid key', function () {
      let spy: jest.SpyInstance;
      let token: string;
      let exceptionThrown: Error;

      beforeEach(async function () {
        token = sign({ id: v4(), ...payload }, 'invalid');

        spy = jest.spyOn(mockRedisService, 'set');

        exceptionThrown = null;

        try {
          await repository.saveToken(token);
        } catch (err) {
          exceptionThrown = err;
        }
      });

      afterEach(async function () {
        spy.mockClear().mockRestore();
      });

      it('should throw TokenExpiredError', async function () {
        expect(exceptionThrown).toBeInstanceOf(JsonWebTokenError);
      });

      it('should throw exception before saving a token', async function () {
        expect(spy).not.toHaveBeenCalled();
      });
    });
  });

  describe('getToken()', function () {
    describe('when called', function () {
      let spy: jest.SpyInstance;
      let result: string;

      beforeEach(async function () {
        spy = jest
          .spyOn(mockRedisService, 'get')
          .mockImplementation(() => 'token-fetched');

        result = await repository.getToken(payload.did, payload.id);
      });

      afterEach(async function () {
        spy.mockClear().mockRestore();
      });

      it('should fetch a token', async function () {
        expect(spy).toHaveBeenCalledWith(
          `refresh-token:${payload.did}:${payload.id}`,
        );
      });

      it('should return fetched token', async function () {
        expect(result).toBe('token-fetched');
      });
    });
  });

  describe('deleteToken()', function () {
    describe('when called', function () {
      let spy: jest.SpyInstance;

      beforeEach(async function () {
        spy = jest.spyOn(mockRedisService, 'del');

        await repository.deleteToken(payload.did, payload.id);
      });

      afterEach(async function () {
        spy.mockClear().mockRestore();
      });

      it('should delete token', async function () {
        expect(spy).toHaveBeenCalledWith(
          `refresh-token:${payload.did}:${payload.id}`,
        );
      });
    });
  });

  describe('deleteAllTokens()', function () {
    it('should be defined', async function () {
      expect(repository.deleteAllTokens).toBeDefined();
    });

    describe('when called', function () {
      let spy: jest.SpyInstance;

      beforeEach(async function () {
        spy = jest.spyOn(mockRedisService, 'del');

        await repository.deleteAllTokens(payload.did);
      });

      afterEach(async function () {
        spy.mockClear().mockRestore();
      });

      it('should delete all tokens for the given DID', async function () {
        expect(spy).toHaveBeenCalledWith(`refresh-token:${payload.did}:*`);
      });
    });
  });
});
