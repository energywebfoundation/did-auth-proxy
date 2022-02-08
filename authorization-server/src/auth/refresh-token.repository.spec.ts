/* eslint-disable @typescript-eslint/no-empty-function */
import { Test, TestingModule } from '@nestjs/testing';
import { RefreshTokenRepository } from './refresh-token.repository';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { RedisService } from '../redis/redis.service';
import { JsonWebTokenError, sign, TokenExpiredError } from 'jsonwebtoken';

describe('RefreshTokenRepository', () => {
  let repository: RefreshTokenRepository;
  let jwtService: JwtService;

  const mockConfigService = {
    get(key: string) {
      return {}[key];
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

  describe('RefreshTokenRepository.saveToken()', function () {
    it('should accept valid token', async () => {
      const token = jwtService.sign(payload);
      await repository.saveToken(token);
    });

    it('should save token', async function () {
      const spy = jest.spyOn(mockRedisService, 'set');
      const token = jwtService.sign(payload);
      await repository.saveToken(token);

      expect(spy).toHaveBeenCalled();
      expect(spy).lastCalledWith(
        `refresh-token:${payload.did}:${payload.id}`,
        JSON.stringify(jwtService.decode(token)),
        'EX',
        3600,
      );

      spy.mockClear();
    });

    it('should reject token singed with invalid key', async () => {
      const token = sign(payload, 'secretKeyInvalid');

      await expect(() => repository.saveToken(token)).rejects.toThrowError(
        JsonWebTokenError,
      );
    });

    it('should reject expired token', async function () {
      const token = sign(payload, 'secretKeyValid', { expiresIn: -1 });

      await expect(() => repository.saveToken(token)).rejects.toThrowError(
        TokenExpiredError,
      );
    });
  });

  describe('RefreshTokenRepository.getToken()', function () {
    it('should get token', async function () {
      const did = payload.did;
      const id = payload.id;
      const spy = jest.spyOn(mockRedisService, 'get');

      await repository.getToken(did, id);

      expect(spy).toHaveBeenCalled();
      expect(spy).lastCalledWith(`refresh-token:${did}:${id}`);

      spy.mockClear();
    });
  });

  describe('RefreshTokenRepository.deleteToken()', function () {
    it('should delete token', async function () {
      const did = payload.did;
      const id = payload.id;
      const spy = jest.spyOn(mockRedisService, 'del');

      await repository.deleteToken(did, id);

      expect(spy).toHaveBeenCalled();
      expect(spy).lastCalledWith(`refresh-token:${did}:${id}`);

      spy.mockClear();
    });
  });
});
