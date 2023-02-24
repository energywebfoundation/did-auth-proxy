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
import { NonceService } from './nonce.service';

function mockLoginRequestResponse(
  identityToken: string,
  didAccessTokenPayload: AuthorisedUser,
) {
  const mockRequest = createRequest({
    method: 'POST',
    path: '/auth/login',
    body: { identityToken },
  });

  mockRequest.user = sign(didAccessTokenPayload, 'secretKeyValid');

  const mockResponse = createResponse();

  return { mockRequest, mockResponse };
}

describe('AuthController', () => {
  let controller: AuthController;

  const configBase: Record<string, boolean | number | string> = {
    LOG_LEVELS: 'error,warn',
    JWT_ACCESS_TTL: 10,
    JWT_REFRESH_TTL: 20,
    AUTH_HEADER_ENABLED: true,
    AUTH_COOKIE_ENABLED: false,
    AUTH_COOKIE_NAME_ACCESS_TOKEN: 'accessToken',
    AUTH_COOKIE_NAME_REFRESH_TOKEN: 'refreshToken',
  };

  const mockConfigService = {
    get: jest.fn(),
  };

  const authCookieSettingsBase = {
    secure: true,
    httpOnly: true,
    sameSite: 'strict',
  } as CookieOptions;

  const mockAuthService = {
    logIn: jest.fn(),
    validateRefreshToken: jest.fn(),
    invalidateRefreshToken: jest.fn(),
    invalidateAllRefreshTokens: jest.fn(),
    refreshTokens: jest.fn(),
    logout: jest.fn(),
    getAuthCookiesOptions: jest.fn(),
  };

  const mockNonceService = {};

  const mockRolesValidationService = {
    didAccessTokenRolesAreValid: jest.fn(),
  };

  beforeEach(async () => {
    mockAuthService.getAuthCookiesOptions.mockImplementation(() => {
      return authCookieSettingsBase;
    });

    mockConfigService.get.mockImplementation(<T>(key: string): T => {
      return configBase[key] as unknown as T;
    });

    mockRolesValidationService.didAccessTokenRolesAreValid.mockImplementation(
      async () => true,
    );

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
        { provide: NonceService, useValue: mockNonceService },
      ],
    }).compile();

    controller = module.get<AuthController>(AuthController);
  });

  afterEach(async function () {
    Object.values(mockConfigService).forEach(
      (mockedFunction: jest.MockedFunction<(...args: unknown[]) => unknown>) =>
        mockedFunction.mockReset(),
    );

    Object.values(mockAuthService).forEach(
      (mockedFunction: jest.MockedFunction<(...args: unknown[]) => unknown>) =>
        mockedFunction.mockReset(),
    );

    Object.values(mockRolesValidationService).forEach(
      (mockedFunction: jest.MockedFunction<(...args: unknown[]) => unknown>) =>
        mockedFunction.mockReset(),
    );

    Object.values(mockNonceService).forEach(
      (mockedFunction: jest.MockedFunction<(...args: unknown[]) => unknown>) =>
        mockedFunction.mockReset(),
    );
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('login()', function () {
    let accessToken: string;
    let refreshToken: string;
    let response: LoginResponseDto | undefined;
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

      refreshToken = sign({}, 'asecret', {
        expiresIn: mockConfigService.get('JWT_REFRESH_TTL'),
      });

      mockAuthService.logIn.mockImplementation(() => {
        return {
          accessToken,
          refreshToken,
        };
      });

      const { mockRequest, mockResponse } = mockLoginRequestResponse(
        identityToken,
        didAccessTokenPayload,
      );

      response = await controller.login(
        { identityToken },
        mockRequest,
        mockResponse,
      );

      responseCookies = mockResponse.cookies;
    });

    describe('when executed', function () {
      it('should generate tokens with a correct did', async function () {
        expect(mockAuthService.logIn).toHaveBeenCalledWith(
          expect.objectContaining({ did: didAccessTokenPayload.did }),
        );
      });

      it('should generate tokens with correct roles', async function () {
        expect(mockAuthService.logIn).toHaveBeenCalledWith(
          expect.objectContaining({
            roles: ['valid.roles.test.apps.mhrsntrktest.iam.ewc'],
          }),
        );
      });

      describe('with AUTH_COOKIE_ENABLED==true', function () {
        beforeEach(async function () {
          mockConfigService.get.mockImplementation(<T>(key: string): T => {
            return {
              ...configBase,
              AUTH_HEADER_ENABLED: false,
              AUTH_COOKIE_ENABLED: true,
            }[key] as unknown as T;
          });

          const { mockRequest, mockResponse } = mockLoginRequestResponse(
            identityToken,
            didAccessTokenPayload,
          );

          mockAuthService.getAuthCookiesOptions.mockReturnValueOnce({
            foo: 'bar',
          });

          await controller.login({ identityToken }, mockRequest, mockResponse);

          responseCookies = mockResponse.cookies;
        });

        it('should apply cookie options', async function () {
          expect(
            responseCookies[
              mockConfigService.get('AUTH_COOKIE_NAME_ACCESS_TOKEN')
            ].options,
          ).toEqual(expect.objectContaining({ foo: 'bar' }));

          expect(
            responseCookies[
              mockConfigService.get('AUTH_COOKIE_NAME_REFRESH_TOKEN')
            ].options,
          ).toEqual(expect.objectContaining({ foo: 'bar' }));
        });

        it('should set correct cookies expiration time', async function () {
          const accessTokenCookieExpTime =
            responseCookies[
              mockConfigService.get('AUTH_COOKIE_NAME_ACCESS_TOKEN')
            ].options.maxAge / 1000;

          const refreshTokenCookieExpTime =
            responseCookies[
              mockConfigService.get('AUTH_COOKIE_NAME_REFRESH_TOKEN')
            ].options.maxAge / 1000;

          expect(
            Math.abs(
              accessTokenCookieExpTime -
                mockConfigService.get('JWT_ACCESS_TTL'),
            ),
          ).toBeLessThan(1);

          expect(
            Math.abs(
              refreshTokenCookieExpTime -
                mockConfigService.get('JWT_REFRESH_TTL'),
            ),
          ).toBeLessThan(1);
        });
      });

      describe('with AUTH_HEADER_ENABLED==true && AUTH_COOKIE_ENABLED==false', function () {
        beforeEach(async function () {
          mockConfigService.get.mockImplementation(<T>(key: string): T => {
            return {
              ...configBase,
              AUTH_HEADER_ENABLED: true,
              AUTH_COOKIE_ENABLED: false,
            }[key] as unknown as T;
          });

          const { mockRequest, mockResponse } = mockLoginRequestResponse(
            identityToken,
            didAccessTokenPayload,
          );

          response = await controller.login(
            { identityToken },
            mockRequest,
            mockResponse,
          );

          responseCookies = mockResponse.cookies;
        });

        it('should respond with tokens in response body only', async function () {
          expect(response.access_token).toEqual(accessToken);
          expect(response.refresh_token).toEqual(refreshToken);

          expect(
            responseCookies[
              mockConfigService.get('AUTH_COOKIE_NAME_ACCESS_TOKEN')
            ],
          ).toBeUndefined();

          expect(
            responseCookies[
              mockConfigService.get('AUTH_COOKIE_NAME_REFRESH_TOKEN')
            ],
          ).toBeUndefined();
        });
      });

      describe('with AUTH_HEADER_ENABLED==true && AUTH_COOKIE_ENABLED==true', function () {
        beforeEach(async function () {
          mockConfigService.get.mockImplementation(<T>(key: string): T => {
            return {
              ...configBase,
              AUTH_HEADER_ENABLED: true,
              AUTH_COOKIE_ENABLED: true,
            }[key] as unknown as T;
          });

          const { mockRequest, mockResponse } = mockLoginRequestResponse(
            identityToken,
            didAccessTokenPayload,
          );

          response = await controller.login(
            { identityToken },
            mockRequest,
            mockResponse,
          );

          responseCookies = mockResponse.cookies;
        });

        it('should respond with tokens in response body and cookies', async function () {
          expect(response.access_token).toEqual(accessToken);
          expect(response.refresh_token).toEqual(refreshToken);

          expect(
            responseCookies[
              mockConfigService.get('AUTH_COOKIE_NAME_ACCESS_TOKEN')
            ],
          ).toBeDefined();

          expect(
            responseCookies[
              mockConfigService.get('AUTH_COOKIE_NAME_ACCESS_TOKEN')
            ].value,
          ).toEqual(accessToken);

          expect(
            responseCookies[
              mockConfigService.get('AUTH_COOKIE_NAME_REFRESH_TOKEN')
            ],
          ).toBeDefined();

          expect(
            responseCookies[
              mockConfigService.get('AUTH_COOKIE_NAME_REFRESH_TOKEN')
            ].value,
          ).toEqual(refreshToken);
        });
      });

      describe('with AUTH_HEADER_ENABLED==false && AUTH_COOKIE_ENABLED==true', function () {
        beforeEach(async function () {
          mockConfigService.get.mockImplementation(<T>(key: string): T => {
            return {
              ...configBase,
              AUTH_HEADER_ENABLED: false,
              AUTH_COOKIE_ENABLED: true,
            }[key] as unknown as T;
          });

          const { mockRequest, mockResponse } = mockLoginRequestResponse(
            identityToken,
            didAccessTokenPayload,
          );

          response = await controller.login(
            { identityToken },
            mockRequest,
            mockResponse,
          );

          responseCookies = mockResponse.cookies;
        });

        it('should respond with tokens in response body and cookies', async function () {
          expect(response).toBeUndefined();

          expect(
            responseCookies[
              mockConfigService.get('AUTH_COOKIE_NAME_ACCESS_TOKEN')
            ],
          ).toBeDefined();

          expect(
            responseCookies[
              mockConfigService.get('AUTH_COOKIE_NAME_ACCESS_TOKEN')
            ].value,
          ).toEqual(accessToken);

          expect(
            responseCookies[
              mockConfigService.get('AUTH_COOKIE_NAME_REFRESH_TOKEN')
            ],
          ).toBeDefined();

          expect(
            responseCookies[
              mockConfigService.get('AUTH_COOKIE_NAME_REFRESH_TOKEN')
            ].value,
          ).toEqual(refreshToken);
        });
      });

      describe('with AUTH_HEADER_ENABLED==false && AUTH_COOKIE_ENABLED==false', function () {
        beforeEach(async function () {
          mockConfigService.get.mockImplementation(<T>(key: string): T => {
            return {
              ...configBase,
              AUTH_HEADER_ENABLED: false,
              AUTH_COOKIE_ENABLED: false,
            }[key] as unknown as T;
          });

          const { mockRequest, mockResponse } = mockLoginRequestResponse(
            identityToken,
            didAccessTokenPayload,
          );

          response = await controller.login(
            { identityToken },
            mockRequest,
            mockResponse,
          );

          responseCookies = mockResponse.cookies;
        });

        it('should respond with tokens not in response body nor cookies', async function () {
          expect(response).toBeUndefined();

          expect(
            responseCookies[
              mockConfigService.get('AUTH_COOKIE_NAME_ACCESS_TOKEN')
            ],
          ).toBeUndefined();

          expect(
            responseCookies[
              mockConfigService.get('AUTH_COOKIE_NAME_REFRESH_TOKEN')
            ],
          ).toBeUndefined();
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

      it('should unset access token cookie', async function () {
        const cookie =
          responseCookies[
            mockConfigService.get('AUTH_COOKIE_NAME_ACCESS_TOKEN')
          ];

        expect(cookie).toBeDefined();
        expect(cookie.value).toBe('');
        expect(cookie.options.expires).toEqual(new Date(1));
      });

      it('should unset refresh token cookie', async function () {
        const cookie =
          responseCookies[
            mockConfigService.get('AUTH_COOKIE_NAME_REFRESH_TOKEN')
          ];

        expect(cookie).toBeDefined();
        expect(cookie.value).toBe('');
        expect(cookie.options.expires).toEqual(new Date(1));
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
    describe('when executed', function () {
      let response: LoginResponseDto | undefined;
      let responseCookies: Record<string, ResponseCookie>;
      let refreshToken: string, newRefreshToken: string, newAccessToken: string;

      beforeEach(async () => {
        refreshToken = sign({ random: Math.random() }, 'aSecret', {
          expiresIn: mockConfigService.get('JWT_REFRESH_TTL'),
        });

        newAccessToken = sign({}, 'aSecret', {
          expiresIn: mockConfigService.get('JWT_ACCESS_TTL'),
        });

        newRefreshToken = sign({ random: Math.random() }, 'aSecret', {
          expiresIn: mockConfigService.get('JWT_REFRESH_TTL'),
        });

        mockAuthService.refreshTokens.mockImplementation(() => ({
          accessToken: newAccessToken,
          refreshToken: newRefreshToken,
        }));

        const expResponse = createResponse();
        response = await controller.refresh({ refreshToken }, expResponse);
        responseCookies = expResponse.cookies;
      });

      it('should use provided refresh token to regenerate tokens', async function () {
        expect(mockAuthService.refreshTokens).toHaveBeenCalledWith(
          refreshToken,
        );
      });

      describe('with AUTH_COOKIE_ENABLED==true', function () {
        beforeEach(async function () {
          mockConfigService.get.mockImplementation(<T>(key: string): T => {
            return {
              ...configBase,
              AUTH_HEADER_ENABLED: false,
              AUTH_COOKIE_ENABLED: true,
            }[key] as unknown as T;
          });

          const expResponse = createResponse();

          response = await controller.refresh({ refreshToken }, expResponse);

          responseCookies = expResponse.cookies;
        });

        it('should apply cookie options', async function () {
          expect(
            responseCookies[
              mockConfigService.get('AUTH_COOKIE_NAME_ACCESS_TOKEN')
            ].options,
          ).toEqual(expect.objectContaining(authCookieSettingsBase));

          expect(
            responseCookies[
              mockConfigService.get('AUTH_COOKIE_NAME_REFRESH_TOKEN')
            ].options,
          ).toEqual(expect.objectContaining(authCookieSettingsBase));
        });

        it('should set correct cookies expiration time', async function () {
          const accessTokenCookieExpTime =
            responseCookies[
              mockConfigService.get('AUTH_COOKIE_NAME_ACCESS_TOKEN')
            ].options.maxAge / 1000;

          const refreshTokenCookieExpTime =
            responseCookies[
              mockConfigService.get('AUTH_COOKIE_NAME_REFRESH_TOKEN')
            ].options.maxAge / 1000;

          expect(
            Math.abs(
              accessTokenCookieExpTime -
                mockConfigService.get('JWT_ACCESS_TTL'),
            ),
          ).toBeLessThan(1);

          expect(
            Math.abs(
              refreshTokenCookieExpTime -
                mockConfigService.get('JWT_REFRESH_TTL'),
            ),
          ).toBeLessThan(1);
        });
      });

      describe('with AUTH_HEADER_ENABLED==true && AUTH_COOKIE_ENABLED==false', function () {
        beforeEach(async function () {
          mockConfigService.get.mockImplementation(<T>(key: string): T => {
            return {
              ...configBase,
              AUTH_HEADER_ENABLED: true,
              AUTH_COOKIE_ENABLED: false,
            }[key] as unknown as T;
          });

          const expResponse = createResponse();
          response = await controller.refresh({ refreshToken }, expResponse);
          responseCookies = expResponse.cookies;
        });

        it('should respond with tokens in response body only', async function () {
          expect(response.access_token).toEqual(newAccessToken);
          expect(response.refresh_token).toEqual(newRefreshToken);

          expect(
            responseCookies[
              mockConfigService.get('AUTH_COOKIE_NAME_ACCESS_TOKEN')
            ],
          ).toBeUndefined();

          expect(
            responseCookies[
              mockConfigService.get('AUTH_COOKIE_NAME_REFRESH_TOKEN')
            ],
          ).toBeUndefined();
        });
      });

      describe('with AUTH_HEADER_ENABLED==true && AUTH_COOKIE_ENABLED==true', function () {
        beforeEach(async function () {
          mockConfigService.get.mockImplementation(<T>(key: string): T => {
            return {
              ...configBase,
              AUTH_HEADER_ENABLED: true,
              AUTH_COOKIE_ENABLED: true,
            }[key] as unknown as T;
          });

          const expResponse = createResponse();
          response = await controller.refresh({ refreshToken }, expResponse);
          responseCookies = expResponse.cookies;
        });

        it('should respond with tokens in response body and cookies', async function () {
          expect(response.access_token).toEqual(newAccessToken);
          expect(response.refresh_token).toEqual(newRefreshToken);

          expect(
            responseCookies[
              mockConfigService.get('AUTH_COOKIE_NAME_ACCESS_TOKEN')
            ],
          ).toBeDefined();

          expect(
            responseCookies[
              mockConfigService.get('AUTH_COOKIE_NAME_ACCESS_TOKEN')
            ].value,
          ).toEqual(newAccessToken);

          expect(
            responseCookies[
              mockConfigService.get('AUTH_COOKIE_NAME_REFRESH_TOKEN')
            ],
          ).toBeDefined();

          expect(
            responseCookies[
              mockConfigService.get('AUTH_COOKIE_NAME_REFRESH_TOKEN')
            ].value,
          ).toEqual(newRefreshToken);
        });
      });

      describe('with AUTH_HEADER_ENABLED==false && AUTH_COOKIE_ENABLED==true', function () {
        beforeEach(async function () {
          mockConfigService.get.mockImplementation(<T>(key: string): T => {
            return {
              ...configBase,
              AUTH_HEADER_ENABLED: false,
              AUTH_COOKIE_ENABLED: true,
            }[key] as unknown as T;
          });

          const expResponse = createResponse();
          response = await controller.refresh({ refreshToken }, expResponse);
          responseCookies = expResponse.cookies;
        });

        it('should respond with tokens in response body and cookies', async function () {
          expect(response).toBeUndefined();

          expect(
            responseCookies[
              mockConfigService.get('AUTH_COOKIE_NAME_ACCESS_TOKEN')
            ],
          ).toBeDefined();

          expect(
            responseCookies[
              mockConfigService.get('AUTH_COOKIE_NAME_ACCESS_TOKEN')
            ].value,
          ).toEqual(newAccessToken);

          expect(
            responseCookies[
              mockConfigService.get('AUTH_COOKIE_NAME_REFRESH_TOKEN')
            ],
          ).toBeDefined();

          expect(
            responseCookies[
              mockConfigService.get('AUTH_COOKIE_NAME_REFRESH_TOKEN')
            ].value,
          ).toEqual(newRefreshToken);
        });
      });

      describe('with AUTH_HEADER_ENABLED==false && AUTH_COOKIE_ENABLED==false', function () {
        beforeEach(async function () {
          mockConfigService.get.mockImplementation(<T>(key: string): T => {
            return {
              ...configBase,
              AUTH_HEADER_ENABLED: false,
              AUTH_COOKIE_ENABLED: false,
            }[key] as unknown as T;
          });

          const expResponse = createResponse();
          response = await controller.refresh({ refreshToken }, expResponse);
          responseCookies = expResponse.cookies;
        });

        it('should respond with tokens not in response body nor cookies', async function () {
          expect(response).toBeUndefined();

          expect(
            responseCookies[
              mockConfigService.get('AUTH_COOKIE_NAME_ACCESS_TOKEN')
            ],
          ).toBeUndefined();

          expect(
            responseCookies[
              mockConfigService.get('AUTH_COOKIE_NAME_REFRESH_TOKEN')
            ],
          ).toBeUndefined();
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

      it('should throw an exception', async function () {
        expect(exceptionThrown).toBeInstanceOf(JsonWebTokenError);
      });

      it('should not set auth cookie', async function () {
        expect(responseCookies[authCookieName]).toBeUndefined();
      });
    });
  });
});
