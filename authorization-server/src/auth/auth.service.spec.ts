/* eslint-disable @typescript-eslint/no-empty-function */
import { Test, TestingModule } from '@nestjs/testing';
import { AuthService, IRefreshTokenPayload } from './auth.service';
import { ConfigService } from '@nestjs/config';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { RefreshTokenRepository } from './refresh-token.repository';
import { decode, JsonWebTokenError, verify } from 'jsonwebtoken';

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
    it('should sign token with jwtService', async function () {
      const spy = jest.spyOn(jwtService, 'sign');

      const token = await service.generateAccessToken(payload);

      const tokenPayload = verify(token, 'secretKeyValid') as Record<
        string,
        any
      >;

      expect(spy).toBeCalledWith(
        { id: tokenPayload.id, ...payload },
        { expiresIn: configService.get('JWT_ACCESS_TTL') },
      );

      spy.mockClear();
    });
  });

  describe('generateRefreshToken()', function () {
    it('should sign token with jwtService', async function () {
      const spy = jest.spyOn(jwtService, 'sign');

      const token = await service.generateRefreshToken(payload);

      const tokenPayload = verify(token, 'secretKeyValid') as Record<
        string,
        any
      >;

      expect(spy).toBeCalledWith(
        { id: tokenPayload.id, ...payload },
        { expiresIn: configService.get('JWT_REFRESH_TTL') },
      );

      spy.mockClear();
    });

    it('should save generated token in a repository', async function () {
      const spy = jest.spyOn(mockRefreshTokenRepository, 'saveToken');

      const token = await service.generateRefreshToken(payload);

      expect(spy).toBeCalledWith(token);

      spy.mockClear();
    });
  });

  describe('validateRefreshToken()', function () {
    it('should resolve to true when valid refresh token provided', async function () {
      const refreshToken = await service.generateRefreshToken(payload);
      const refreshTokenDecoded = decode(refreshToken) as Record<string, any>;

      const spy = jest
        .spyOn(mockRefreshTokenRepository, 'getToken')
        .mockImplementation(async () => 'token-fetched-from-repository');

      expect(await service.validateRefreshToken(refreshToken)).toEqual(true);
      expect(spy).toHaveBeenCalledWith(
        refreshTokenDecoded.did,
        refreshTokenDecoded.id,
      );

      spy.mockClear().mockRestore();
    });

    it('should resolve to false when malformed refresh token provided', async function () {
      expect(await service.validateRefreshToken('invalid')).toEqual(false);
    });

    it('should resolve to false when expired refresh token provided', async function () {
      const refreshToken = await service.generateRefreshToken(payload);

      await new Promise((resolve) => setTimeout(resolve, 2010));

      expect(await service.validateRefreshToken(refreshToken)).toEqual(false);
    });
  });

  describe('invalidateRefreshToken()', function () {
    it('should remove token entry from the repository', async function () {
      const spy = jest.spyOn(mockRefreshTokenRepository, 'deleteToken');

      await service.invalidateRefreshToken('did', 'id');

      expect(spy).toHaveBeenCalledWith('did', 'id');

      spy.mockClear().mockRestore();
    });
  });

  describe('refreshTokens()', function () {
    it('should generate a new tokens pair when valid refresh token provided', async function () {
      const oldRefreshToken = await service.generateRefreshToken(payload);

      const spyGenerateAccessToken = jest
        .spyOn(service, 'generateAccessToken')
        .mockImplementation(async () => 'new-access-token');

      const spyGenerateRefreshToken = jest
        .spyOn(service, 'generateRefreshToken')
        .mockImplementation(async () => 'new-refresh-token');

      const { accessToken, refreshToken } = await service.refreshTokens(
        oldRefreshToken,
      );

      expect(spyGenerateAccessToken).toHaveBeenCalledWith({
        did: payload.did,
        roles: payload.roles,
      });

      expect(spyGenerateRefreshToken).toHaveBeenCalledWith({
        did: payload.did,
        roles: payload.roles,
      });

      expect(accessToken).toEqual('new-access-token');
      expect(refreshToken).toEqual('new-refresh-token');

      spyGenerateRefreshToken.mockClear().mockRestore();
      spyGenerateAccessToken.mockClear().mockRestore();
    });

    it('should store a new refresh token in the repository', async function () {
      const oldRefreshToken = await service.generateRefreshToken(payload);

      const spy = jest.spyOn(mockRefreshTokenRepository, 'saveToken');

      const { refreshToken } = await service.refreshTokens(oldRefreshToken);

      expect(spy).toBeCalledWith(refreshToken);

      spy.mockClear();
    });

    it('should invalidate an old refresh token', async function () {
      const refreshToken = await service.generateRefreshToken(payload);
      const refreshTokenDecoded = decode(refreshToken) as IRefreshTokenPayload;

      const spy = jest.spyOn(mockRefreshTokenRepository, 'deleteToken');

      await service.refreshTokens(refreshToken);

      expect(spy).toBeCalledWith(
        refreshTokenDecoded.did,
        refreshTokenDecoded.id,
      );

      spy.mockClear();
    });

    it('should throw an exception when malformed refresh token provided', async function () {
      await expect(() =>
        service.refreshTokens('malformed-token'),
      ).rejects.toThrow(JsonWebTokenError);
    });
  });
});
