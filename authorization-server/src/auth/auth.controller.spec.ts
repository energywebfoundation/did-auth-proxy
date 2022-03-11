/* eslint-disable @typescript-eslint/no-empty-function */
import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { ConfigService } from '@nestjs/config';
import { createRequest } from 'node-mocks-http';
import { sign as sign } from 'jsonwebtoken';
import { ForbiddenException } from '@nestjs/common';
import { LoginResponseDataDto } from './dto/login-response-data.dto';
import { LoggerService } from '../logger/logger.service';

describe('AuthController', () => {
  let controller: AuthController;

  const mockConfigService = {
    get: <T>(key: string): T => {
      return {
        LOG_LEVELS: 'error,warn',
        JWT_ACCESS_TTL: 10,
      }[key] as unknown as T;
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
        LoggerService,
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
    describe('when executed', () => {
      let spyGenerateRefreshToken: jest.SpyInstance;
      let spyGenerateAccessToken: jest.SpyInstance;
      let accessToken: string, refreshToken: string;
      let response: LoginResponseDataDto;

      const didAccessTokenPayload = {
        did: '',
        verifiedRoles: [{ name: '', namespace: '' }],
      };

      beforeEach(async () => {
        const identityToken = 'foobar';

        accessToken = sign({}, 'asecret', {
          expiresIn: mockConfigService.get<number>('JWT_ACCESS_TTL'),
        });
        refreshToken = `refresh-token-string-${Math.random()}`;

        const request = createRequest({
          method: 'POST',
          path: '/auth/login',
          body: { identityToken },
        });

        spyGenerateAccessToken = jest
          .spyOn(mockAuthService, 'generateAccessToken')
          .mockImplementation(() => accessToken);

        spyGenerateRefreshToken = jest
          .spyOn(mockAuthService, 'generateRefreshToken')
          .mockImplementation(() => refreshToken);

        request.user = sign(didAccessTokenPayload, 'secretKeyValid');

        response = await controller.login({ identityToken }, request);
      });

      afterEach(() => {
        spyGenerateRefreshToken.mockClear().mockRestore();
        spyGenerateRefreshToken.mockClear().mockRestore();
      });

      it('should respond with access token', async function () {
        expect(response).toMatchObject({ access_token: accessToken });
      });

      it('should respond with refresh token', async function () {
        expect(response).toMatchObject({ refresh_token: refreshToken });
      });

      it('should create access token with correct parameters', async function () {
        expect(spyGenerateAccessToken).toHaveBeenCalledWith({
          did: didAccessTokenPayload.did,
          roles: didAccessTokenPayload.verifiedRoles.map((r) => r.namespace),
        });
      });

      it('should create refresh token with correct parameters', async function () {
        expect(spyGenerateRefreshToken).toHaveBeenCalledWith({
          did: didAccessTokenPayload.did,
          roles: didAccessTokenPayload.verifiedRoles.map((r) => r.namespace),
        });
      });

      it('should respond with correct expires_in field value', async function () {
        expect(response.expires_in).toBeGreaterThanOrEqual(
          mockConfigService.get<number>('JWT_ACCESS_TTL') - 1,
        );

        expect(response.expires_in).toBeLessThanOrEqual(
          mockConfigService.get<number>('JWT_ACCESS_TTL'),
        );
      });

      it('should respond with correct type field value', async function () {
        expect(response).toMatchObject({ type: 'Bearer' });
      });
    });
  });

  describe('introspect()', () => {
    // eslint-disable-next-line jest/expect-expect
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
    describe('when called with valid refresh token', function () {
      let spyRefresh: jest.SpyInstance, spyValidate: jest.SpyInstance;
      let response: LoginResponseDataDto;
      let refreshToken: string, newRefreshToken: string, newAccessToken: string;

      beforeEach(async () => {
        refreshToken = `validRefreshToken-${Math.random()}`;

        newAccessToken = sign({}, 'aSecret', {
          expiresIn: mockConfigService.get<number>('JWT_ACCESS_TTL'),
        });

        newRefreshToken = `regenerated-refresh-token-${Math.random()}`;

        spyValidate = jest
          .spyOn(mockAuthService, 'validateRefreshToken')
          .mockImplementation(async () => true);

        spyRefresh = jest
          .spyOn(mockAuthService, 'refreshTokens')
          .mockImplementation(async () => ({
            accessToken: newAccessToken,
            refreshToken: newRefreshToken,
          }));

        response = await controller.refresh({ refreshToken });
      });

      it('should validate refresh token', async function () {
        expect(spyValidate).toHaveBeenCalledWith(refreshToken);
      });

      it('should regenerate tokens pair using provided refresh token', async function () {
        expect(spyRefresh).toHaveBeenCalledWith(refreshToken);
      });

      it('should respond with a new access token', async function () {
        expect(response).toMatchObject({ access_token: newAccessToken });
      });

      it('should respond with a new refresh token', async function () {
        expect(response).toMatchObject({ refresh_token: newRefreshToken });
      });

      it('should respond with correct expires_in field value', async function () {
        expect(response.expires_in).toBeGreaterThanOrEqual(
          mockConfigService.get<number>('JWT_ACCESS_TTL') - 1,
        );

        expect(response.expires_in).toBeLessThanOrEqual(
          mockConfigService.get<number>('JWT_ACCESS_TTL'),
        );
      });

      it('should respond with correct type field value', async function () {
        expect(response).toMatchObject({ type: 'Bearer' });
      });

      afterEach(() => {
        spyValidate.mockClear().mockRestore();
        spyRefresh.mockClear().mockRestore();
      });
    });

    describe('when called with invalid refresh token', function () {
      let spy: jest.SpyInstance, exceptionThrown: Error;

      beforeEach(async () => {
        spy = jest
          .spyOn(mockAuthService, 'validateRefreshToken')
          .mockImplementation(async () => false);

        try {
          await controller.refresh({ refreshToken: 'invalid' });
        } catch (err) {
          exceptionThrown = err;
        }
      });

      afterEach(() => {
        spy.mockClear().mockRestore();
      });

      it('should validate refresh token', async function () {
        expect(spy).toHaveBeenCalledWith('invalid');
      });

      it('should throw an exception', async function () {
        expect(exceptionThrown).toBeInstanceOf(ForbiddenException);
      });
    });
  });
});
