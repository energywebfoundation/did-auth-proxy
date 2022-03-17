/* eslint-disable @typescript-eslint/no-empty-function */
import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { ConfigService } from '@nestjs/config';
import { createRequest, createResponse, ResponseCookie } from 'node-mocks-http';
import { sign as sign } from 'jsonwebtoken';
import { ForbiddenException } from '@nestjs/common';
import { LoginResponseDto } from './dto/login-response.dto';
import { LoggerService } from '../logger/logger.service';

const envVarsBase: Record<string, unknown> = {
  LOG_LEVELS: 'error,warn',
  JWT_ACCESS_TTL: 10,
  JWT_REFRESH_TTL: 20,
  AUTH_COOKIE_NAME: 'Auth-tests',
};

describe('AuthController', () => {
  let controller: AuthController;

  const mockConfigService = {
    get: <T>(key: string): T => {
      return envVarsBase[key] as unknown as T;
    },
  };

  const mockAuthService = {
    generateAccessToken: () => {},
    generateRefreshToken: () => {},
    validateRefreshToken: () => {},
    invalidateRefreshToken: () => {},
    invalidateAllRefreshTokens: () => {},
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
      let response: LoginResponseDto;
      let responseCookies: Record<string, ResponseCookie>;

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

        const expRequest = createRequest({
          method: 'POST',
          path: '/auth/login',
          body: { identityToken },
        });

        const expResponse = createResponse();

        spyGenerateAccessToken = jest
          .spyOn(mockAuthService, 'generateAccessToken')
          .mockImplementation(() => accessToken);

        spyGenerateRefreshToken = jest
          .spyOn(mockAuthService, 'generateRefreshToken')
          .mockImplementation(() => refreshToken);

        expRequest.user = sign(didAccessTokenPayload, 'secretKeyValid');

        response = await controller.login(
          { identityToken },
          expRequest,
          expResponse,
        );

        responseCookies = expResponse.cookies;
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

      describe('when AUTH_COOKIE_ENABLED=true', function () {
        let cookieName: string;
        let mockConfigGet: jest.SpyInstance;

        beforeAll(async function () {
          cookieName = mockConfigService.get<string>('AUTH_COOKIE_NAME');
          mockConfigGet = jest
            .spyOn(mockConfigService, 'get')
            .mockImplementation(<T>(key: string): T => {
              return {
                ...envVarsBase,
                AUTH_COOKIE_ENABLED: true,
                AUTH_COOKIE_SECURE: true,
              }[key] as unknown as T;
            });
        });

        afterAll(async function () {
          mockConfigGet.mockClear().mockRestore();
        });

        it('should set cookie', async function () {
          expect(responseCookies[cookieName]).toBeDefined();
        });

        it('should set cookie with a correct value', async function () {
          expect(responseCookies[cookieName].value).toBe(accessToken);
        });

        it('should set http-only cookie', async function () {
          expect(responseCookies[cookieName].options.httpOnly).toBe(true);
        });

        it('should set cookie with "strict" SameSite policy', async function () {
          expect(responseCookies[cookieName].options.sameSite).toBe('strict');
        });

        it('should set cookie with a correct expiration time', async function () {
          expect(
            responseCookies[cookieName].options.maxAge / 1000,
          ).toBeGreaterThanOrEqual(
            mockConfigService.get<number>('JWT_ACCESS_TTL') - 1,
          );

          expect(
            responseCookies[cookieName].options.maxAge / 1000,
          ).toBeLessThanOrEqual(
            mockConfigService.get<number>('JWT_ACCESS_TTL'),
          );
        });

        describe('when AUTH_COOKIE_SECURE=true', function () {
          beforeAll(async function () {
            mockConfigGet = jest
              .spyOn(mockConfigService, 'get')
              .mockImplementation(<T>(key: string): T => {
                return {
                  ...envVarsBase,
                  AUTH_COOKIE_ENABLED: true,
                  AUTH_COOKIE_SECURE: true,
                }[key] as unknown as T;
              });
          });

          afterAll(async function () {
            mockConfigGet.mockClear().mockRestore();
          });

          it('should set secure cookie', async function () {
            expect(responseCookies[cookieName].options.secure).toBe(true);
          });
        });

        describe('when AUTH_COOKIE_SECURE=false', function () {
          beforeAll(async function () {
            mockConfigGet = jest
              .spyOn(mockConfigService, 'get')
              .mockImplementation(<T>(key: string): T => {
                return {
                  ...envVarsBase,
                  AUTH_COOKIE_ENABLED: true,
                  AUTH_COOKIE_SECURE: false,
                }[key] as unknown as T;
              });
          });

          afterAll(async function () {
            mockConfigGet.mockClear().mockRestore();
          });

          it('should set secure cookie', async function () {
            expect(responseCookies[cookieName].options.secure).toBe(false);
          });
        });
      });

      describe('when AUTH_COOKIE_ENABLED=false', function () {
        let mockConfigGet: jest.SpyInstance;

        beforeAll(async function () {
          mockConfigGet = jest
            .spyOn(mockConfigService, 'get')
            .mockImplementation(<T>(key: string): T => {
              return {
                ...envVarsBase,
                AUTH_COOKIE_ENABLED: false,
              }[key] as unknown as T;
            });
        });

        afterAll(async function () {
          mockConfigGet.mockClear().mockRestore();
        });

        it('should skip setting the cookie', async function () {
          const cookieName = mockConfigService.get<string>('AUTH_COOKIE_NAME');
          expect(responseCookies[cookieName]).toBeUndefined();
        });
      });
    });
  });

  describe('logout()', function () {
    it('should be defined', async function () {
      expect(controller.logout).toBeDefined();
    });

    describe('when called with a valid refresh token', function () {
      let mockValidateRefreshToken: jest.SpyInstance;
      let mockInvalidateRefreshToken: jest.SpyInstance;
      let mockInvalidateAllRefreshTokens: jest.SpyInstance;
      let refreshToken: string;
      let responseCookies: Record<string, ResponseCookie>;

      beforeEach(async function () {
        const expResponse = createResponse();
        mockValidateRefreshToken = jest
          .spyOn(mockAuthService, 'validateRefreshToken')
          .mockImplementation(() => true);
        mockInvalidateRefreshToken = jest.spyOn(
          mockAuthService,
          'invalidateRefreshToken',
        );
        mockInvalidateAllRefreshTokens = jest.spyOn(
          mockAuthService,
          'invalidateAllRefreshTokens',
        );

        refreshToken = sign(
          {
            did: 'some-did',
            id: 'some-id',
          },
          'asecret',
          {
            expiresIn: mockConfigService.get<number>('JWT_REFRESH_TTL'),
          },
        );

        await controller.logout(
          {
            refreshToken,
            allDevices: false,
          },
          expResponse,
        );

        responseCookies = expResponse.cookies;
      });

      afterEach(async function () {
        mockValidateRefreshToken.mockClear().mockRestore();
        mockInvalidateRefreshToken.mockClear().mockRestore();
        mockInvalidateAllRefreshTokens.mockClear().mockRestore();
      });

      it('should check validity of the refresh token', async function () {
        expect(mockValidateRefreshToken).toHaveBeenCalledWith(refreshToken);
      });

      it('should invalidate refresh token', async function () {
        expect(mockInvalidateRefreshToken).toHaveBeenCalledWith(
          'some-did',
          'some-id',
        );
      });

      it('should leave other refresh tokens intact', async function () {
        expect(mockInvalidateAllRefreshTokens).not.toHaveBeenCalled();
      });

      describe('when AUTH_COOKIE_ENABLED=true', function () {
        let mockConfigGet: jest.SpyInstance;

        beforeAll(async function () {
          mockConfigGet = jest
            .spyOn(mockConfigService, 'get')
            .mockImplementation(<T>(key: string): T => {
              return {
                ...envVarsBase,
                AUTH_COOKIE_ENABLED: true,
              }[key] as unknown as T;
            });
        });

        afterAll(async function () {
          mockConfigGet.mockClear().mockRestore();
        });

        it('should unset auth cookie', async function () {
          const cookie =
            responseCookies[mockConfigService.get<string>('AUTH_COOKIE_NAME')];

          expect(cookie).toBeDefined();
          expect(cookie.value).toBe('');
          expect(cookie.options.expires).toEqual(new Date(0));
        });
      });

      describe('when AUTH_COOKIE_ENABLED=false', function () {
        let mockConfigGet: jest.SpyInstance;

        beforeAll(async function () {
          mockConfigGet = jest
            .spyOn(mockConfigService, 'get')
            .mockImplementation(<T>(key: string): T => {
              return {
                ...envVarsBase,
                AUTH_COOKIE_ENABLED: false,
              }[key] as unknown as T;
            });
        });

        afterAll(async function () {
          mockConfigGet.mockClear().mockRestore();
        });

        it('should send no auth cookie', async function () {
          const cookie =
            responseCookies[mockConfigService.get<string>('AUTH_COOKIE_NAME')];

          expect(cookie).toBeUndefined();
        });
      });
    });

    describe('when called with a valid refresh token and allDevices=true', function () {
      let mockValidateRefreshToken: jest.SpyInstance;
      let mockInvalidateAllRefreshTokens: jest.SpyInstance;

      beforeEach(async function () {
        mockValidateRefreshToken = jest
          .spyOn(mockAuthService, 'validateRefreshToken')
          .mockImplementation(() => true);

        mockInvalidateAllRefreshTokens = jest.spyOn(
          mockAuthService,
          'invalidateAllRefreshTokens',
        );

        const refreshToken = sign(
          {
            did: 'some-did',
            id: 'some-id',
          },
          'asecret',
          {
            expiresIn: mockConfigService.get<number>('JWT_REFRESH_TTL'),
          },
        );

        await controller.logout(
          {
            refreshToken,
            allDevices: true,
          },
          createResponse(),
        );
      });

      afterEach(async function () {
        mockValidateRefreshToken.mockClear().mockRestore();
        mockInvalidateAllRefreshTokens.mockClear().mockRestore();
      });

      it('should delete all tokens for the did', async function () {
        expect(mockInvalidateAllRefreshTokens).toHaveBeenCalledWith('some-did');
      });
    });

    describe('when called with invalid refresh token', function () {
      let mockValidateRefreshToken: jest.SpyInstance;
      let refreshToken: string;
      let responseCookies: Record<string, ResponseCookie>;
      let exceptionThrown: Error;

      beforeEach(async function () {
        const expResponse = createResponse();
        mockValidateRefreshToken = jest
          .spyOn(mockAuthService, 'validateRefreshToken')
          .mockImplementation(() => false);

        refreshToken = 'invalid';

        try {
          await controller.logout(
            {
              refreshToken,
              allDevices: false,
            },
            expResponse,
          );
        } catch (err) {
          exceptionThrown = err;
        }

        responseCookies = expResponse.cookies;
      });

      afterEach(async function () {
        mockValidateRefreshToken.mockClear().mockRestore();
      });

      it('should thrown an exception', async function () {
        expect(exceptionThrown).toBeInstanceOf(Error);
      });

      it('should send no auth cookie', async function () {
        const cookie =
          responseCookies[mockConfigService.get<string>('AUTH_COOKIE_NAME')];

        expect(cookie).toBeUndefined();
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
      let response: LoginResponseDto;
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
