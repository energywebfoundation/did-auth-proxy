/* eslint-disable @typescript-eslint/no-empty-function */
import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { ConfigService } from '@nestjs/config';
import { createRequest, createResponse, ResponseCookie } from 'node-mocks-http';
import { JsonWebTokenError, sign as sign } from 'jsonwebtoken';
import { LoginResponseDto } from './dto/login-response.dto';
import { LoggerService } from '../logger/logger.service';
import { CookieOptions } from 'express';

describe('AuthController', () => {
  let controller: AuthController;

  const mockConfigService = {
    get: <T>(key: string): T => {
      return {
        LOG_LEVELS: 'error,warn',
        JWT_ACCESS_TTL: 10,
        JWT_REFRESH_TTL: 20,
      }[key] as unknown as T;
    },
  };

  const authCookieSettingsBase = {
    enabled: true,
    name: 'Auth',
    options: {
      secure: true,
      httpOnly: true,
      sameSite: 'strict',
    } as CookieOptions,
  };

  const mockAuthService = {
    logIn: () => {},
    validateRefreshToken: () => {},
    invalidateRefreshToken: () => {},
    invalidateAllRefreshTokens: () => {},
    refreshTokens: () => {},
    logout: () => {},
    getAuthCookieSettings: () => authCookieSettingsBase,
    getHAToken: (did: string) => `ha-long-live-token-for-${did}`,
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
      let spyLogIn: jest.SpyInstance;
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

        spyLogIn = jest
          .spyOn(mockAuthService, 'logIn')
          .mockImplementation(() => {
            return {
              accessToken,
              refreshToken,
            };
          });

        expRequest.user = sign(didAccessTokenPayload, 'secretKeyValid');

        response = await controller.login(
          { identityToken },
          expRequest,
          expResponse,
        );

        responseCookies = expResponse.cookies;
      });

      afterEach(() => {
        spyLogIn.mockClear().mockRestore();
      });

      it('should respond with access token', async function () {
        expect(response).toMatchObject({ access_token: accessToken });
      });

      it('should respond with refresh token', async function () {
        expect(response).toMatchObject({ refresh_token: refreshToken });
      });

      it('should create access token with correct parameters', async function () {
        expect(spyLogIn).toHaveBeenCalledWith({
          did: didAccessTokenPayload.did,
          roles: didAccessTokenPayload.verifiedRoles.map((r) => r.namespace),
        });
      });

      it('should create refresh token with correct parameters', async function () {
        expect(spyLogIn).toHaveBeenCalledWith({
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

      describe('when auth cookie enabled', function () {
        let cookieName: string;

        beforeAll(async function () {
          cookieName = mockAuthService.getAuthCookieSettings().name;
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
          it('should set secure cookie', async function () {
            expect(responseCookies[cookieName].options.secure).toBe(true);
          });
        });

        describe('when AUTH_COOKIE_SECURE=false', function () {
          let mockGetAuthCookieOptions: jest.SpyInstance;

          beforeAll(async function () {
            mockGetAuthCookieOptions = jest
              .spyOn(mockAuthService, 'getAuthCookieSettings')
              .mockImplementation(() => ({
                ...authCookieSettingsBase,
                options: {
                  ...authCookieSettingsBase,
                  secure: false,
                } as CookieOptions,
              }));
          });

          afterAll(async function () {
            mockGetAuthCookieOptions.mockClear().mockRestore();
          });

          it('should set secure cookie', async function () {
            expect(responseCookies[cookieName].options.secure).toBe(false);
          });
        });
      });

      describe('when auth cookie disabled', function () {
        let mockGetAuthCookieOptions: jest.SpyInstance;

        beforeAll(async function () {
          mockGetAuthCookieOptions = jest
            .spyOn(mockAuthService, 'getAuthCookieSettings')
            .mockImplementation(() => ({
              ...authCookieSettingsBase,
              enabled: false,
            }));
        });

        afterAll(async function () {
          mockGetAuthCookieOptions.mockClear().mockRestore();
        });

        it('should skip setting the cookie', async function () {
          const cookieName = mockAuthService.getAuthCookieSettings().name;
          expect(responseCookies[cookieName]).toBeUndefined();
        });
      });
    });
  });

  describe('logout()', function () {
    it('should be defined', async function () {
      expect(controller.logout).toBeDefined();
    });

    describe('when called', function () {
      let mockLogOut: jest.SpyInstance;
      let refreshToken: string;
      let responseCookies: Record<string, ResponseCookie>;

      beforeEach(async function () {
        const expResponse = createResponse();

        mockLogOut = jest.spyOn(mockAuthService, 'logout');

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
        mockLogOut.mockClear().mockRestore();
      });

      it('should log out the refresh token', async function () {
        expect(mockLogOut).toHaveBeenCalledWith({
          did: 'some-did',
          refreshTokenId: 'some-id',
          allDevices: false,
        });
      });

      it('should unset auth cookie', async function () {
        const cookie =
          responseCookies[mockAuthService.getAuthCookieSettings().name];

        expect(cookie).toBeDefined();
        expect(cookie.value).toBe('');
        expect(cookie.options.expires).toEqual(new Date(0));
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
          responseCookies[mockAuthService.getAuthCookieSettings().name];

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

      const response = createResponse();

      await controller.introspect(request, response);
    });
  });

  describe('refresh()', function () {
    describe('when called with valid refresh token', function () {
      let spyRefresh: jest.SpyInstance;
      let response: LoginResponseDto;
      let responseCookies: Record<string, ResponseCookie>;
      let refreshToken: string, newRefreshToken: string, newAccessToken: string;

      beforeEach(async () => {
        refreshToken = `validRefreshToken-${Math.random()}`;

        newAccessToken = sign({}, 'aSecret', {
          expiresIn: mockConfigService.get<number>('JWT_ACCESS_TTL'),
        });

        newRefreshToken = `regenerated-refresh-token-${Math.random()}`;

        spyRefresh = jest
          .spyOn(mockAuthService, 'refreshTokens')
          .mockImplementation(async () => ({
            accessToken: newAccessToken,
            refreshToken: newRefreshToken,
          }));

        const expResponse = createResponse();

        response = await controller.refresh({ refreshToken }, expResponse);

        responseCookies = expResponse.cookies;
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

      describe('when auth cookie enabled', function () {
        let cookieName: string;

        beforeAll(async function () {
          cookieName = mockAuthService.getAuthCookieSettings().name;
        });

        it('should set auth cookie', async function () {
          expect(responseCookies[cookieName]).toBeDefined();
        });

        it('should set cookie with a correct value', async function () {
          expect(responseCookies[cookieName].value).toBe(newAccessToken);
        });

        it('should set http-only cookie', async function () {
          expect(responseCookies[cookieName].options.httpOnly).toBe(true);
        });

        it('should set cookie with "strict" SameSite policy', async function () {
          expect(responseCookies[cookieName].options.sameSite).toBe('strict');
        });

        it('should set secure cookie', async function () {
          expect(responseCookies[cookieName].options.secure).toBe(true);
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
      });

      describe('when auth cookie is disabled', function () {
        let cookieName: string;
        let mockGetAuthCookieOptions: jest.SpyInstance;

        beforeAll(async function () {
          mockGetAuthCookieOptions = jest
            .spyOn(mockAuthService, 'getAuthCookieSettings')
            .mockImplementation(() => ({
              ...authCookieSettingsBase,
              enabled: false,
            }));

          cookieName = mockAuthService.getAuthCookieSettings().name;
        });

        afterAll(async function () {
          mockGetAuthCookieOptions.mockClear().mockRestore();
        });

        it('should not set auth cookie', async function () {
          expect(responseCookies[cookieName]).toBeUndefined();
        });
      });

      afterEach(() => {
        spyRefresh.mockClear().mockRestore();
      });
    });

    describe('when called with invalid refresh token', function () {
      let spy: jest.SpyInstance, exceptionThrown: Error;
      let responseCookies: { [key: string]: ResponseCookie };
      let authCookieName: string;

      beforeEach(async () => {
        spy = jest
          .spyOn(mockAuthService, 'refreshTokens')
          .mockImplementation(async () => {
            throw new JsonWebTokenError('invalid refresh token');
          });

        authCookieName = mockAuthService.getAuthCookieSettings().name;

        const expResponse = createResponse();

        try {
          await controller.refresh({ refreshToken: 'invalid' }, expResponse);
        } catch (err) {
          exceptionThrown = err;
        }

        responseCookies = expResponse.cookies;
      });

      afterEach(() => {
        spy.mockClear().mockRestore();
      });

      it('should throw an exception', async function () {
        expect(exceptionThrown).toBeInstanceOf(JsonWebTokenError);
      });

      it('should not set auth cookie', async function () {
        expect(responseCookies[authCookieName]).toBeUndefined();
      });
    });
  });
});
