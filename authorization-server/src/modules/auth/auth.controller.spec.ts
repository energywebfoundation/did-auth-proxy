/* eslint-disable @typescript-eslint/no-empty-function */
import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { ConfigService } from '@nestjs/config';
import { createRequest, createResponse, ResponseCookie } from 'node-mocks-http';
import { JsonWebTokenError, sign as sign } from 'jsonwebtoken';
import { LoginResponseDto } from './dto';
import { PinoLogger } from 'nestjs-pino';
import { CookieOptions } from 'express';
import { RolesValidationService } from './roles-validation.service';
import { AuthorisedUser, RoleCredentialStatus } from 'passport-did-auth';

describe('AuthController', () => {
  let controller: AuthController;

  const configBase: Record<string, boolean | number | string> = {
    LOG_LEVELS: 'error,warn',
    JWT_ACCESS_TTL: 10,
    JWT_REFRESH_TTL: 20,
    AUTH_COOKIE_NAME_ACCESS_TOKEN: 'token',
  };

  const mockConfigService = {
    get: jest.fn(),
  };

  const authCookieSettingsBase = {
    enabled: true,
    options: {
      secure: true,
      httpOnly: true,
      sameSite: 'strict',
    } as CookieOptions,
  };

  const mockAuthService = {
    logIn: jest.fn(),
    validateRefreshToken: jest.fn(),
    invalidateRefreshToken: jest.fn(),
    invalidateAllRefreshTokens: jest.fn(),
    refreshTokens: jest.fn(),
    logout: jest.fn(),
    getAuthCookiesSettings: jest.fn(),
  };

  const mockRolesValidationService = {
    didAccessTokenRolesAreValid: jest.fn().mockImplementation(async () => true),
  };

  beforeEach(async () => {
    mockAuthService.getAuthCookiesSettings.mockImplementation(() => {
      return authCookieSettingsBase;
    });

    mockConfigService.get.mockImplementation(<T>(key: string): T => {
      return configBase[key] as unknown as T;
    });

    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        { provide: PinoLogger, useValue: new PinoLogger({}) },
        { provide: AuthService, useValue: mockAuthService },
        { provide: ConfigService, useValue: mockConfigService },
        {
          provide: RolesValidationService,
          useValue: mockRolesValidationService,
        },
      ],
    }).compile();

    controller = module.get<AuthController>(AuthController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('login()', function () {
    describe('when executed', () => {
      let accessToken: string, refreshToken: string;
      let response: LoginResponseDto;
      let responseCookies: Record<string, ResponseCookie>;
      const identityToken = 'foobar';

      const didAccessTokenPayload: AuthorisedUser = {
        did: '12344567',
        userRoles: [
          {
            name: 'valid',
            namespace: 'valid.roles.test.apps.mhrsntrktest.iam.ewc',
            status: RoleCredentialStatus.VALID,
          },
          {
            name: 'revoked',
            namespace: 'revoked.roles.test.apps.mhrsntrktest.iam.ewc',
            status: RoleCredentialStatus.REVOKED,
          },
          {
            name: 'expired',
            namespace: 'expired.roles.test.apps.mhrsntrktest.iam.ewc',
            status: RoleCredentialStatus.EXPIRED,
          },
        ],
        authorisationStatus: true,
      };

      beforeEach(async () => {
        accessToken = sign({}, 'asecret', {
          expiresIn: mockConfigService.get('JWT_ACCESS_TTL'),
        });
        refreshToken = `refresh-token-string-${Math.random()}`;

        const expRequest = createRequest({
          method: 'POST',
          path: '/auth/login',
          body: { identityToken },
        });

        const expResponse = createResponse();

        mockAuthService.logIn.mockImplementation(() => {
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
        mockAuthService.logIn.mockClear().mockRestore();
        mockRolesValidationService.didAccessTokenRolesAreValid
          .mockClear()
          .mockRestore();
      });

      it('should respond with access token', async function () {
        expect(response).toMatchObject({ access_token: accessToken });
      });

      it('should respond with refresh token', async function () {
        expect(response).toMatchObject({ refresh_token: refreshToken });
      });

      it('should create access token with correct parameters', async function () {
        expect(mockAuthService.logIn).toHaveBeenCalledWith({
          did: didAccessTokenPayload.did,
          roles: didAccessTokenPayload.userRoles
            .filter((r) => r.status === RoleCredentialStatus.VALID)
            .map((r) => r.namespace),
        });
      });

      it('should create refresh token with correct parameters', async function () {
        expect(mockAuthService.logIn).toHaveBeenCalledWith({
          did: didAccessTokenPayload.did,
          roles: didAccessTokenPayload.userRoles
            .filter((r) => r.status === RoleCredentialStatus.VALID)
            .map((r) => r.namespace),
        });
      });

      it('should respond with correct expires_in field value', async function () {
        expect(response.expires_in).toBeGreaterThanOrEqual(
          mockConfigService.get('JWT_ACCESS_TTL') - 1,
        );

        expect(response.expires_in).toBeLessThanOrEqual(
          mockConfigService.get('JWT_ACCESS_TTL'),
        );
      });

      it('should respond with correct type field value', async function () {
        expect(response).toMatchObject({ type: 'Bearer' });
      });

      describe('when auth cookie enabled', function () {
        let cookieName: string;

        beforeAll(async function () {
          cookieName = mockConfigService.get('AUTH_COOKIE_NAME_ACCESS_TOKEN');
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
          ).toBeGreaterThanOrEqual(mockConfigService.get('JWT_ACCESS_TTL') - 1);

          expect(
            responseCookies[cookieName].options.maxAge / 1000,
          ).toBeLessThanOrEqual(mockConfigService.get('JWT_ACCESS_TTL'));
        });

        describe('when AUTH_COOKIE_SECURE=true', function () {
          it('should set secure cookie', async function () {
            expect(responseCookies[cookieName].options.secure).toBe(true);
          });
        });

        describe('when AUTH_COOKIE_SECURE=false', function () {
          beforeEach(async function () {
            mockAuthService.getAuthCookiesSettings.mockImplementation(() => {
              return {
                ...authCookieSettingsBase,
                options: {
                  ...authCookieSettingsBase,
                  secure: false,
                } as CookieOptions,
              };
            });

            const expRequest = createRequest({
              method: 'POST',
              path: '/auth/login',
              body: { identityToken },
            });

            const expResponse = createResponse();

            expRequest.user = sign(didAccessTokenPayload, 'secretKeyValid');

            response = await controller.login(
              { identityToken },
              expRequest,
              expResponse,
            );

            responseCookies = expResponse.cookies;
          });

          afterEach(async function () {
            mockAuthService.getAuthCookiesSettings.mockClear().mockRestore();
          });

          it('should set secure cookie', async function () {
            expect(responseCookies[cookieName].options.secure).toBe(false);
          });
        });
      });

      describe('when auth cookie disabled', function () {
        beforeEach(async function () {
          mockAuthService.getAuthCookiesSettings.mockImplementation(() => ({
            ...authCookieSettingsBase,
            enabled: false,
          }));

          const expRequest = createRequest({
            method: 'POST',
            path: '/auth/login',
            body: { identityToken },
          });

          const expResponse = createResponse();

          expRequest.user = sign(didAccessTokenPayload, 'secretKeyValid');

          response = await controller.login(
            { identityToken },
            expRequest,
            expResponse,
          );

          responseCookies = expResponse.cookies;
        });

        afterEach(async function () {
          mockAuthService.getAuthCookiesSettings.mockClear().mockRestore();
        });

        it('should skip setting the cookie', async function () {
          const cookieName = mockConfigService.get(
            'AUTH_COOKIE_NAME_ACCESS_TOKEN',
          );
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
      let refreshToken: string;
      let responseCookies: Record<string, ResponseCookie>;

      beforeEach(async function () {
        const expResponse = createResponse();

        refreshToken = sign(
          {
            did: 'some-did',
            id: 'some-id',
          },
          'asecret',
          {
            expiresIn: mockConfigService.get('JWT_REFRESH_TTL'),
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

      it('should log out the refresh token', async function () {
        expect(mockAuthService.logout).toHaveBeenCalledWith({
          did: 'some-did',
          refreshTokenId: 'some-id',
          allDevices: false,
        });
      });

      it('should unset auth cookie', async function () {
        const cookie =
          responseCookies[
            mockConfigService.get('AUTH_COOKIE_NAME_ACCESS_TOKEN')
          ];

        expect(cookie).toBeDefined();
        expect(cookie.value).toBe('');
        expect(cookie.options.expires).toEqual(new Date(0));
      });
    });

    describe('when called with invalid refresh token', function () {
      let refreshToken: string;
      let responseCookies: Record<string, ResponseCookie>;
      let exceptionThrown: Error;

      beforeEach(async function () {
        const expResponse = createResponse();
        mockAuthService.validateRefreshToken.mockImplementation(() => false);

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
        mockAuthService.validateRefreshToken.mockClear().mockRestore();
      });

      it('should thrown an exception', async function () {
        expect(exceptionThrown).toBeInstanceOf(Error);
      });

      it('should send no auth cookie', async function () {
        const cookie =
          responseCookies[
            mockConfigService.get('AUTH_COOKIE_NAME_ACCESS_TOKEN')
          ];

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
      let response: LoginResponseDto;
      let responseCookies: Record<string, ResponseCookie>;
      let refreshToken: string, newRefreshToken: string, newAccessToken: string;

      beforeEach(async () => {
        refreshToken = `validRefreshToken-${Math.random()}`;

        newAccessToken = sign({}, 'aSecret', {
          expiresIn: mockConfigService.get('JWT_ACCESS_TTL'),
        });

        newRefreshToken = `regenerated-refresh-token-${Math.random()}`;

        mockAuthService.refreshTokens.mockImplementation(() => ({
          accessToken: newAccessToken,
          refreshToken: newRefreshToken,
        }));

        const expResponse = createResponse();

        response = await controller.refresh({ refreshToken }, expResponse);

        responseCookies = expResponse.cookies;
      });

      afterEach(async function () {
        mockAuthService.refreshTokens.mockReset();
      });

      it('should regenerate tokens pair using provided refresh token', async function () {
        expect(mockAuthService.refreshTokens).toHaveBeenCalledWith(
          refreshToken,
        );
      });

      it('should respond with a new access token', async function () {
        expect(response).toMatchObject({ access_token: newAccessToken });
      });

      it('should respond with a new refresh token', async function () {
        expect(response).toMatchObject({ refresh_token: newRefreshToken });
      });

      it('should respond with correct expires_in field value', async function () {
        expect(response.expires_in).toBeGreaterThanOrEqual(
          mockConfigService.get('JWT_ACCESS_TTL') - 1,
        );

        expect(response.expires_in).toBeLessThanOrEqual(
          mockConfigService.get('JWT_ACCESS_TTL'),
        );
      });

      it('should respond with correct type field value', async function () {
        expect(response).toMatchObject({ type: 'Bearer' });
      });

      describe('when auth cookie enabled', function () {
        let cookieName: string;

        beforeAll(async function () {
          cookieName = mockConfigService.get('AUTH_COOKIE_NAME_ACCESS_TOKEN');
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
          ).toBeGreaterThanOrEqual(mockConfigService.get('JWT_ACCESS_TTL') - 1);

          expect(
            responseCookies[cookieName].options.maxAge / 1000,
          ).toBeLessThanOrEqual(mockConfigService.get('JWT_ACCESS_TTL'));
        });
      });

      describe('when auth cookie is disabled', function () {
        let cookieName: string;

        beforeEach(async function () {
          mockAuthService.getAuthCookiesSettings.mockImplementation(() => ({
            ...authCookieSettingsBase,
            enabled: false,
          }));

          cookieName = mockConfigService.get('AUTH_COOKIE_NAME_ACCESS_TOKEN');

          const expResponse = createResponse();

          response = await controller.refresh({ refreshToken }, expResponse);

          responseCookies = expResponse.cookies;
        });

        afterEach(async function () {
          mockAuthService.getAuthCookiesSettings.mockClear().mockRestore();
        });

        it('should not set auth cookie', async function () {
          expect(responseCookies[cookieName]).toBeUndefined();
        });
      });
    });

    describe('when called with invalid refresh token', function () {
      let exceptionThrown: Error;
      let responseCookies: { [key: string]: ResponseCookie };
      let authCookieName: string;

      beforeEach(async () => {
        mockAuthService.refreshTokens.mockImplementation(async () => {
          throw new JsonWebTokenError('invalid refresh token');
        });

        authCookieName = mockConfigService.get('AUTH_COOKIE_NAME_ACCESS_TOKEN');

        const expResponse = createResponse();

        try {
          await controller.refresh({ refreshToken: 'invalid' }, expResponse);
        } catch (err) {
          exceptionThrown = err;
        }

        responseCookies = expResponse.cookies;
      });

      afterEach(() => {
        mockAuthService.refreshTokens.mockClear().mockRestore();
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
