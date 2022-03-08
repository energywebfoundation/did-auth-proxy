/* eslint-disable @typescript-eslint/no-empty-function */
import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { ConfigService } from '@nestjs/config';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { RefreshTokenRepository } from './refresh-token.repository';
import { decode, JsonWebTokenError, sign } from 'jsonwebtoken';
import { IAccessTokenPayload, IRefreshTokenPayload } from './auth.interface';

describe('AuthService', () => {
  let service: AuthService;
  let jwtService: JwtService;
  let configService: ConfigService;

  const mockConfigService = {
    get(key: string) {
      return {
        JWT_ACCESS_TTL: 1,
        JWT_REFRESH_TTL: 2,
      }[key];
    },
  };

  const mockRefreshTokenRepository = {
    saveToken() {},
    getToken() {},
    deleteToken() {},
  };

  const payload = {
    did: 'did:eth:0x82FcB31385EaBe261E4e6003b9F2Cb2af34e2654',
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
        }),
      ],
      providers: [
        AuthService,
        { provide: ConfigService, useValue: mockConfigService },
        {
          provide: RefreshTokenRepository,
          useValue: mockRefreshTokenRepository,
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    configService = module.get<ConfigService>(ConfigService);
    jwtService = module.get<JwtService>(JwtService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('generateAccessToken()', function () {
    describe('when called', function () {
      let spySign: jest.SpyInstance;
      let issuedAt: number;
      let result: string, resultDecoded: IAccessTokenPayload;

      beforeEach(async function () {
        spySign = jest.spyOn(jwtService, 'sign');

        issuedAt = Math.floor(Date.now() / 1000);
        result = await service.generateAccessToken(payload);
        resultDecoded = decode(result) as IAccessTokenPayload;
      });

      afterEach(async function () {
        spySign.mockClear().mockRestore();
      });

      it('should return JWT token', async function () {
        expect(resultDecoded).toBeDefined();
      });

      it('should generate token payload with all expected fields', async function () {
        expect(Object.keys(resultDecoded).sort()).toEqual(
          ['did', 'id', 'roles', 'iat', 'exp'].sort(),
        );
      });

      it('should set correct TTL', async function () {
        expect(resultDecoded.exp - resultDecoded.iat).toEqual(
          configService.get('JWT_ACCESS_TTL'),
        );
      });

      it('should set correct iat', async function () {
        expect(resultDecoded.iat).toEqual(issuedAt);
      });

      it('should sign token with jwtService', async function () {
        expect(spySign).toHaveBeenCalledWith(
          { id: resultDecoded.id, ...payload },
          { expiresIn: configService.get('JWT_ACCESS_TTL') },
        );
      });
    });
  });

  describe('generateRefreshToken()', function () {
    describe('when called', function () {
      let spySign: jest.SpyInstance, spySave: jest.SpyInstance;
      let issuedAt: number;
      let result: string, resultDecoded: IRefreshTokenPayload;

      beforeEach(async function () {
        spySign = jest.spyOn(jwtService, 'sign');
        spySave = jest.spyOn(mockRefreshTokenRepository, 'saveToken');

        issuedAt = Math.floor(Date.now() / 1000);
        result = await service.generateRefreshToken(payload);
        resultDecoded = decode(result) as IRefreshTokenPayload;
      });

      afterEach(async function () {
        spySave.mockClear().mockRestore();
        spySign.mockClear().mockRestore();
      });

      it('should return JWT token', async function () {
        expect(resultDecoded).toBeDefined();
      });

      it('should generate token payload with all expected fields', async function () {
        expect(Object.keys(resultDecoded).sort()).toEqual(
          ['did', 'id', 'roles', 'iat', 'exp'].sort(),
        );
      });

      it('should set correct TTL', async function () {
        expect(resultDecoded.exp - resultDecoded.iat).toEqual(
          configService.get('JWT_REFRESH_TTL'),
        );
      });

      it('should set correct iat', async function () {
        expect(resultDecoded.iat).toEqual(issuedAt);
      });

      it('should sign token with jwtService', async function () {
        expect(spySign).toHaveBeenCalledWith(
          { id: resultDecoded.id, ...payload },
          { expiresIn: configService.get('JWT_REFRESH_TTL') },
        );
      });

      it('should save generated token in the repository', async function () {
        expect(spySave).toHaveBeenCalledWith(result);
      });
    });
  });

  describe('validateRefreshToken()', function () {
    describe('when called with valid whitelisted refresh token', function () {
      let refreshToken, refreshTokenDecoded: IRefreshTokenPayload;
      let result: boolean;
      let spy: jest.SpyInstance;

      beforeEach(async function () {
        refreshToken = jwtService.sign(payload);
        refreshTokenDecoded = decode(refreshToken) as IRefreshTokenPayload;

        spy = jest
          .spyOn(mockRefreshTokenRepository, 'getToken')
          .mockImplementation(async () => 'token-fetched-from-repository');

        result = await service.validateRefreshToken(refreshToken);
      });

      afterEach(() => {
        spy.mockClear().mockRestore();
      });

      it('should resolve to true', async function () {
        expect(result).toBe(true);
      });

      it('should check if token is whitelisted', async function () {
        expect(spy).toHaveBeenCalledWith(
          refreshTokenDecoded.did,
          refreshTokenDecoded.id,
        );
      });
    });

    describe('when called with malformed refresh token', function () {
      let result: boolean;

      beforeEach(async function () {
        result = await service.validateRefreshToken('invalid token');
      });

      it('should resolve to false', async function () {
        expect(result).toBe(false);
      });
    });

    describe('when called with expired refresh token', function () {
      let result: boolean, refreshToken;

      beforeEach(async function () {
        refreshToken = jwtService.sign(payload, { expiresIn: 0 });

        result = await service.validateRefreshToken(refreshToken);
      });

      it('should resolve to false', async function () {
        expect(result).toBe(false);
      });
    });

    describe('when called with invalidated refresh token', function () {
      let refreshToken: string, refreshTokenDecoded: IRefreshTokenPayload;
      let result: boolean;
      let spyVerify: jest.SpyInstance, spyGetToken: jest.SpyInstance;

      beforeEach(async function () {
        refreshToken = jwtService.sign({ id: '111', ...payload });
        refreshTokenDecoded = decode(refreshToken) as IRefreshTokenPayload;

        spyVerify = jest
          .spyOn(jwtService, 'verify')
          .mockImplementation(() => refreshTokenDecoded);
        spyGetToken = jest
          .spyOn(mockRefreshTokenRepository, 'getToken')
          .mockImplementation(() => null);

        result = await service.validateRefreshToken(refreshToken);
      });

      afterEach(function () {
        spyVerify.mockClear().mockRestore();
        spyGetToken.mockClear().mockRestore();
      });

      it('should resolve to false', async function () {
        expect(result).toBe(false);
      });

      it('should verify token', async function () {
        expect(spyVerify).toHaveBeenCalledWith(refreshToken);
      });

      it('should check if token is whitelisted', async function () {
        expect(spyGetToken).toHaveBeenCalledWith(
          refreshTokenDecoded.did,
          refreshTokenDecoded.id,
        );
      });
    });
  });

  describe('invalidateRefreshToken()', function () {
    describe('when called', function () {
      let spyDeleteToken: jest.SpyInstance;

      beforeEach(async function () {
        spyDeleteToken = jest.spyOn(mockRefreshTokenRepository, 'deleteToken');

        await service.invalidateRefreshToken('did', 'id');
      });

      afterEach(async function () {
        spyDeleteToken.mockClear().mockRestore();
      });

      it('should remove token entry from the repository', async function () {
        expect(spyDeleteToken).toHaveBeenCalledWith('did', 'id');
      });
    });
  });

  describe('refreshTokens()', function () {
    describe('when called with valid refresh token', function () {
      let spyGenerateAccessToken: jest.SpyInstance;
      let spyGenerateRefreshToken: jest.SpyInstance;
      let spyDeleteToken: jest.SpyInstance;
      let result: { accessToken: string; refreshToken: string };

      const oldRefreshTokenPayload = {
        id: '110dbf81-732c-4b6c-bba8-018463ea7506',
        did: 'did:ethr:0x82FcB31385EaBe261E4e6003b9F2Cb2af34e2654',
        roles: ['role1', 'role2'],
      };

      const oldRefreshToken = sign(oldRefreshTokenPayload, 'secretKeyValid');

      beforeEach(async () => {
        spyGenerateAccessToken = jest
          .spyOn(service, 'generateAccessToken')
          .mockImplementation(async () => 'new-access-token');

        spyGenerateRefreshToken = jest
          .spyOn(service, 'generateRefreshToken')
          .mockImplementation(async () => 'new-refresh-token');

        spyDeleteToken = jest.spyOn(mockRefreshTokenRepository, 'deleteToken');

        result = await service.refreshTokens(oldRefreshToken);
      });

      afterEach(() => {
        spyGenerateAccessToken.mockClear().mockRestore();
        spyGenerateRefreshToken.mockClear().mockRestore();
        spyDeleteToken.mockClear().mockRestore();
      });

      it('should generate a new access token', async function () {
        expect(spyGenerateAccessToken).toHaveBeenCalledWith({
          did: oldRefreshTokenPayload.did,
          roles: oldRefreshTokenPayload.roles,
        });
      });

      it('should generate a new refresh token', async function () {
        expect(spyGenerateRefreshToken).toHaveBeenCalledWith({
          did: oldRefreshTokenPayload.did,
          roles: oldRefreshTokenPayload.roles,
        });
      });

      it('should return a new access token', async function () {
        expect(result).toMatchObject({ accessToken: 'new-access-token' });
      });

      it('should return a new refresh token', async function () {
        expect(result).toMatchObject({ refreshToken: 'new-refresh-token' });
      });

      it('should invalidate old refresh token', async function () {
        expect(spyDeleteToken).toHaveBeenCalledWith(
          oldRefreshTokenPayload.did,
          oldRefreshTokenPayload.id,
        );
      });
    });

    describe('when called with malformed refresh token', function () {
      let exceptionThrown: Error;

      beforeEach(async () => {
        try {
          await service.refreshTokens('malformed-token');
        } catch (err) {
          exceptionThrown = err;
        }
      });

      it('should throw an exception', async function () {
        expect(exceptionThrown).toBeInstanceOf(JsonWebTokenError);
      });
    });
  });
});
