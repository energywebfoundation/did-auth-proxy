/* eslint-disable @typescript-eslint/no-empty-function */
import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { ConfigService } from '@nestjs/config';
import { createRequest } from 'node-mocks-http';
import { sign as sign } from 'jsonwebtoken';
import { ForbiddenException } from '@nestjs/common';

describe('AuthController', () => {
  let controller: AuthController;

  const mockConfigService = {
    get(key: string) {
      return { JWT_ACCESS_TTL: 10 }[key];
    },
  };

  const mockAuthService = {
    generateAccessToken: () => {},
    generateRefreshToken: () => {},
    validateRefreshToken: () => {},
    refreshTokens: () => {},
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        { provide: AuthService, useValue: mockAuthService },
        { provide: ConfigService, useValue: mockConfigService },
      ],
    }).compile();

    controller = module.get<AuthController>(AuthController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('login()', function () {
    it('should generate tokens pair', async function () {
      const identityToken = 'foobar';
      const didAccessTokenPayload = {
        did: '',
        verifiedRoles: [{ name: '', namespace: '' }],
      };

      const request = createRequest({
        method: 'POST',
        path: '/auth/login',
        body: { identityToken },
      });

      const accessToken = sign({}, 'asecret', {
        expiresIn: mockConfigService.get('JWT_ACCESS_TTL'),
      });

      const spyGenerateAccessToken = jest
        .spyOn(mockAuthService, 'generateAccessToken')
        .mockImplementation(() => accessToken);

      const spyGenerateRefreshToken = jest
        .spyOn(mockAuthService, 'generateRefreshToken')
        .mockImplementation(() => 'signed-refresh-token-string');

      request.user = sign(didAccessTokenPayload, 'secretKeyValid');

      const result = await controller.login({ identityToken }, request);

      expect(spyGenerateAccessToken).toHaveBeenCalledWith({
        did: didAccessTokenPayload.did,
        roles: didAccessTokenPayload.verifiedRoles.map((r) => r.namespace),
      });
      expect(spyGenerateRefreshToken).toHaveBeenCalledWith({
        did: didAccessTokenPayload.did,
        roles: didAccessTokenPayload.verifiedRoles.map((r) => r.namespace),
      });

      const { expires_in, ...resultWithNoExpires } = result;

      expect(expires_in).toBeGreaterThanOrEqual(
        mockConfigService.get('JWT_ACCESS_TTL') - 1,
      );
      expect(expires_in).toBeLessThanOrEqual(
        mockConfigService.get('JWT_ACCESS_TTL'),
      );

      expect(resultWithNoExpires).toEqual({
        access_token: accessToken,
        refresh_token: 'signed-refresh-token-string',
        type: 'Bearer',
      });

      spyGenerateRefreshToken.mockClear().mockRestore();
      spyGenerateRefreshToken.mockClear().mockRestore();
    });
  });

  describe('introspect()', () => {
    it('should execute when request passes Guards', async function () {
      const request = createRequest({
        method: 'GET',
        path: '/auth/token-introspection',
      });

      request.user = {
        id: '1f7a3006-75a2-41ef-a12a-58144252fd2c',
        did: 'did:ethr:0x82FcB31385EaBe261E4e6003b9F2Cb2af34e2654',
        roles: ['role1.roles.app-test2.apps.artur.iam.ewc'],
        iat: Math.floor(Date.now() / 1000 - 1800),
        exp: Math.floor(Date.now() / 100 + 1800),
      };
      await controller.introspect(request);
    });
  });

  describe('refresh()', function () {
    it('should validate refreshToken', async function () {
      const spy = jest
        .spyOn(mockAuthService, 'validateRefreshToken')
        .mockImplementation(async () => true);

      const spyRefresh = jest
        .spyOn(mockAuthService, 'refreshTokens')
        .mockImplementation(async () => ({
          accessToken: sign({}, 'aSecret', {
            expiresIn: mockConfigService.get('JWT_ACCESS_TTL'),
          }),
          refreshToken: 'regenerated-refresh-token',
        }));

      await controller.refresh({ refreshToken: 'validToken' });

      expect(spy).toHaveBeenCalledWith('validToken');

      spy.mockClear().mockRestore();
      spyRefresh.mockClear().mockRestore();
    });

    it('should throw ForbiddenException when invalid access token provided', async function () {
      const spy = jest
        .spyOn(mockAuthService, 'validateRefreshToken')
        .mockImplementation(async () => false);

      await expect(() =>
        controller.refresh({ refreshToken: 'invalid' }),
      ).rejects.toThrowError(ForbiddenException);

      spy.mockClear().mockRestore();
    });

    it('should respond with a pair of new tokens', async function () {
      const accessToken: string = sign({}, 'aSecret', {
        expiresIn: mockConfigService.get('JWT_ACCESS_TTL'),
      });

      const spyValidate = jest
        .spyOn(mockAuthService, 'validateRefreshToken')
        .mockImplementation(async () => true);

      const spyRefresh = jest
        .spyOn(mockAuthService, 'refreshTokens')
        .mockImplementation(async () => ({
          accessToken: accessToken,
          refreshToken: 'regenerated-refresh-token',
        }));

      const { access_token, refresh_token, type, expires_in } =
        await controller.refresh({
          refreshToken: 'validToken',
        });

      expect({
        access_token,
        refresh_token,
        type,
      }).toEqual({
        access_token: accessToken,
        refresh_token: 'regenerated-refresh-token',
        type: 'Bearer',
      });

      const expectedTTL = mockConfigService.get('JWT_ACCESS_TTL');

      expect(expires_in).toBeGreaterThanOrEqual(expectedTTL - 1);
      expect(expires_in).toBeLessThanOrEqual(expectedTTL);

      expect(spyRefresh).toHaveBeenCalledWith('validToken');

      spyValidate.mockClear().mockRestore();
      spyRefresh.mockClear().mockRestore();
    });
  });
});
