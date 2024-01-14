/* eslint-disable @typescript-eslint/no-empty-function */
import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { ConfigService } from '@nestjs/config';
import { createRequest, createResponse, ResponseCookie } from 'node-mocks-http';
import { JsonWebTokenError, sign as sign } from 'jsonwebtoken';
import { LoginResponseDto } from './dto';
import { PinoLogger } from 'nestjs-pino';
import { CookieOptions, Request, Response } from 'express';
import { RolesValidationService } from './roles-validation.service';
import { AuthorisedUser, RoleCredentialStatus } from 'passport-did-auth';
import { NonceService } from './nonce.service';
import { SiweInitResponseDto } from './dto/siwe-init-response.dto';
import { ParsedQs } from 'qs';
import { SiweVerifyRequestDto } from './dto/siwe-verify-request.dto';
import { BadRequestException, UnauthorizedException } from '@nestjs/common';

function mockLoginRequestResponse(didAccessTokenPayload: AuthorisedUser) {
  const mockRequest = createRequest();

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
    sameSite: 'lax',
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

  const mockNonceService = {
    generateNonce: jest.fn(),
    validateOnce: jest.fn(),
  };

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

  describe('loginCommon()', function () {
    let accessToken: string;
    let refreshToken: string;
    let response: LoginResponseDto | undefined;
    let responseCookies: Record<string, ResponseCookie>;

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
        didAccessTokenPayload,
      );

      response = await controller.loginCommon(mockRequest, mockResponse);

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
            didAccessTokenPayload,
          );

          mockAuthService.getAuthCookiesOptions.mockReturnValueOnce({
            foo: 'bar',
          });

          await controller.loginCommon(mockRequest, mockResponse);

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
            didAccessTokenPayload,
          );

          response = await controller.loginCommon(mockRequest, mockResponse);

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
            didAccessTokenPayload,
          );

          response = await controller.loginCommon(mockRequest, mockResponse);

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
            didAccessTokenPayload,
          );

          response = await controller.loginCommon(mockRequest, mockResponse);

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
            didAccessTokenPayload,
          );

          response = await controller.loginCommon(mockRequest, mockResponse);

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

  describe('login()', function () {
    it('should be defined', async function () {
      expect(controller.login).toBeDefined();
    });

    describe('when called', function () {
      let exception: Error;
      let result: LoginResponseDto | undefined;
      let spyOnLoginCommon: jest.SpyInstance;
      let mockRequest: Request<
        { [key: string]: string },
        unknown,
        unknown,
        ParsedQs,
        Record<string, unknown>
      >;
      let mockResponse: Response<unknown, Record<string, unknown>>;

      const didAccessTokenPayload: AuthorisedUser = {
        did: '987654321',
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

      beforeEach(async function () {
        spyOnLoginCommon = jest
          .spyOn(controller, 'loginCommon')
          .mockResolvedValueOnce({
            access_token: 'access_token',
            refresh_token: 'refresh_token',
            type: 'Bearer',
            expires_in: 120,
          } as LoginResponseDto);

        ({ mockRequest, mockResponse } = mockLoginRequestResponse(
          didAccessTokenPayload,
        ));

        try {
          result = await controller.login(
            { identityToken: 'foobar' },
            mockRequest,
            mockResponse,
          );
        } catch (err) {
          exception = err;
        }
      });

      it('should execute', async function () {
        expect(exception).toBeUndefined();
        expect(result).toBeDefined();
      });

      it('should perform login with the `loginCommon` method', async function () {
        expect(spyOnLoginCommon).toHaveBeenCalledWith(
          mockRequest,
          mockResponse,
        );
      });

      it('should return results of the `loginCommon` method execution', async function () {
        expect(result).toEqual({
          access_token: 'access_token',
          expires_in: 120,
          refresh_token: 'refresh_token',
          type: 'Bearer',
        });
      });
    });
  });

  describe('siweLoginInit()', function () {
    it('should be defined', async function () {
      expect(controller.siweLoginInit).toBeDefined();
    });

    describe('when executed', function () {
      let exception: Error;
      let result: SiweInitResponseDto;

      beforeEach(async function () {
        mockNonceService.generateNonce.mockReturnValueOnce('a new nonce');

        try {
          result = await controller.siweLoginInit();
        } catch (err) {
          exception = err;
        }
      });

      it('should execute', async function () {
        expect(exception).toBeUndefined();
      });

      it('should generate a new nonce', async function () {
        expect(mockNonceService.generateNonce).toHaveBeenCalled();
        expect(result).toEqual({ nonce: 'a new nonce' });
      });
    });
  });

  describe('siweLoginVerify()', function () {
    let exception: Error;
    let result: LoginResponseDto | undefined;
    let spyOnLoginCommon: jest.SpyInstance;
    let mockRequest: Request<
      { [key: string]: string },
      unknown,
      unknown,
      ParsedQs,
      Record<string, unknown>
    >;
    let mockResponse: Response<unknown, Record<string, unknown>>;
    const didAccessTokenPayload: AuthorisedUser = {
      did: '98765432134534',
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

    it('should be defined', async function () {
      expect(controller.siweLoginVerify).toBeDefined();
    });

    describe('when called with valid message and signature', function () {
      beforeEach(async function () {
        spyOnLoginCommon = jest
          .spyOn(controller, 'loginCommon')
          .mockResolvedValueOnce({
            access_token: 'access_token',
            refresh_token: 'refresh_token',
            type: 'Bearer',
            expires_in: 120,
          } as LoginResponseDto);

        ({ mockRequest, mockResponse } = mockLoginRequestResponse(
          didAccessTokenPayload,
        ));

        mockNonceService.validateOnce.mockResolvedValueOnce(true);

        try {
          result = await controller.siweLoginVerify(mockRequest, mockResponse, {
            message:
              'localhost:3000 wants you to sign in with your Ethereum account:\n0xe7b6644d6D327B60B33dF7CfE022fB270504C910\n\n\nURI: http://localhost:3000/\nVersion: 1\nChain ID: 73799\nNonce: r3Cx6CXrOtueNEA3X\nIssued At: 2023-02-27T17:07:45.399Z',
            signature:
              '0x2759f7e19e8408425990054fd51a10aad061dfdcaf90e24db03919c924b77be66ba8bf7f74cba9b025ced5a0792d1eaa35db80f3115666e67f1277b88b84da7a1b',
          } as SiweVerifyRequestDto);
        } catch (err) {
          exception = err;
        }
      });

      it('should execute', async function () {
        expect(exception).toBeUndefined();
      });

      it('should perform login with the `loginCommon` method', async function () {
        expect(spyOnLoginCommon).toHaveBeenCalledWith(
          mockRequest,
          mockResponse,
        );
      });

      it('should return results of the `loginCommon` method execution', async function () {
        expect(result).toEqual({
          access_token: 'access_token',
          expires_in: 120,
          refresh_token: 'refresh_token',
          type: 'Bearer',
        });
      });
    });

    describe('when called with invalid message', function () {
      beforeEach(async function () {
        result = undefined;

        spyOnLoginCommon = jest
          .spyOn<
            AuthController,
            keyof AuthController
          >(controller, 'loginCommon')
          .mockResolvedValueOnce({
            access_token: 'access_token',
            refresh_token: 'refresh_token',
            type: 'Bearer',
            expires_in: 120,
          } as LoginResponseDto);

        ({ mockRequest, mockResponse } = mockLoginRequestResponse(
          didAccessTokenPayload,
        ));

        mockNonceService.validateOnce.mockResolvedValueOnce(true);

        try {
          result = await controller.siweLoginVerify(mockRequest, mockResponse, {
            message: 'invalid message',
            signature:
              '0x2759f7e19e8408425990054fd51a10aad061dfdcaf90e24db03919c924b77be66ba8bf7f74cba9b025ced5a0792d1eaa35db80f3115666e67f1277b88b84da7a1b',
          } as SiweVerifyRequestDto);
        } catch (err) {
          exception = err;
        }
      });

      it('should throw BadRequestException', async function () {
        expect(exception).toBeInstanceOf(BadRequestException);
      });

      it('should skip performing login with the `loginCommon` method', async function () {
        expect(spyOnLoginCommon).not.toHaveBeenCalled();
      });

      it('should return undefined', async function () {
        expect(result).toBeUndefined();
      });
    });

    describe('when called with invalid nonce', function () {
      beforeEach(async function () {
        result = undefined;

        spyOnLoginCommon = jest
          .spyOn<
            AuthController,
            keyof AuthController
          >(controller, 'loginCommon')
          .mockResolvedValueOnce({
            access_token: 'access_token',
            refresh_token: 'refresh_token',
            type: 'Bearer',
            expires_in: 120,
          } as LoginResponseDto);

        ({ mockRequest, mockResponse } = mockLoginRequestResponse(
          didAccessTokenPayload,
        ));

        mockNonceService.validateOnce.mockResolvedValueOnce(false);

        try {
          result = await controller.siweLoginVerify(mockRequest, mockResponse, {
            message:
              'localhost:3000 wants you to sign in with your Ethereum account:\n0xe7b6644d6D327B60B33dF7CfE022fB270504C910\n\n\nURI: http://localhost:3000/\nVersion: 1\nChain ID: 73799\nNonce: r3Cx6CXrOtueNEA3X\nIssued At: 2023-02-27T17:07:45.399Z',
            signature:
              '0x2759f7e19e8408425990054fd51a10aad061dfdcaf90e24db03919c924b77be66ba8bf7f74cba9b025ced5a0792d1eaa35db80f3115666e67f1277b88b84da7a1b',
          } as SiweVerifyRequestDto);
        } catch (err) {
          exception = err;
        }
      });

      it('should throw UnauthorizedException', async function () {
        expect(exception).toBeInstanceOf(UnauthorizedException);
      });

      it('should skip performing login with the `loginCommon` method', async function () {
        expect(spyOnLoginCommon).not.toHaveBeenCalled();
      });

      it('should return undefined', async function () {
        expect(result).toBeUndefined();
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

        const request = createRequest({
          user: refreshToken,
        });

        await controller.logout(
          {
            refreshToken,
            allDevices: false,
          },
          expResponse,
          request,
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
        expect(cookie.options.sameSite).toBe(authCookieSettingsBase.sameSite);
        expect(cookie.options.secure).toBe(authCookieSettingsBase.secure);
      });

      it('should unset refresh token cookie', async function () {
        const cookie =
          responseCookies[
            mockConfigService.get('AUTH_COOKIE_NAME_REFRESH_TOKEN')
          ];

        expect(cookie).toBeDefined();
        expect(cookie.value).toBe('');
        expect(cookie.options.expires).toEqual(new Date(1));
        expect(cookie.options.sameSite).toBe(authCookieSettingsBase.sameSite);
        expect(cookie.options.secure).toBe(authCookieSettingsBase.secure);
      });
    });

    describe('when called with invalid refresh token', function () {
      let refreshToken: string;
      let responseCookies: Record<string, ResponseCookie>;
      let exceptionThrown: Error;

      beforeEach(async function () {
        const expResponse = createResponse();
        const request = createRequest();
        mockAuthService.validateRefreshToken.mockImplementation(() => false);

        refreshToken = 'invalid';

        try {
          await controller.logout(
            {
              refreshToken,
              allDevices: false,
            },
            expResponse,
            request,
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

  describe('refreshCommon()', function () {
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
        response = await controller.refreshCommon(refreshToken, expResponse);
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

          response = await controller.refreshCommon(refreshToken, expResponse);

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
          response = await controller.refreshCommon(refreshToken, expResponse);
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
          response = await controller.refreshCommon(refreshToken, expResponse);
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
          response = await controller.refreshCommon(refreshToken, expResponse);
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
          response = await controller.refreshCommon(refreshToken, expResponse);
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
          await controller.refreshCommon('invalid', expResponse);
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

  describe('refreshWithPost()', function () {
    let spy: jest.SpyInstance;
    let refreshToken: string;
    let mockReqest: Request;
    let mockResponse: Response;
    let result: LoginResponseDto | undefined;
    let exception: Error;

    beforeEach(async function () {
      spy = jest.spyOn(controller, 'refreshCommon').mockResolvedValueOnce({
        access_token: 'access_token',
        refresh_token: 'refresh_token',
        type: 'Bearer',
        expires_in: 120,
      } as LoginResponseDto);

      refreshToken = sign({ random: Math.random() }, 'aSecret', {
        expiresIn: mockConfigService.get('JWT_REFRESH_TTL'),
      });

      mockReqest = createRequest({
        user: refreshToken,
      });
      mockResponse = createResponse();

      try {
        result = await controller.refreshWithPost(mockReqest, mockResponse);
      } catch (err) {
        exception = err;
      }
    });

    it('should execute', async function () {
      expect(exception).toBeUndefined();
    });

    it('should call refreshCommon()', async function () {
      expect(spy).toHaveBeenCalledWith(refreshToken, mockResponse);
    });

    it('should return refreshCommon() return value', async function () {
      expect(result).toEqual({
        access_token: 'access_token',
        expires_in: 120,
        refresh_token: 'refresh_token',
        type: 'Bearer',
      });
    });
  });

  describe('refreshWithGet()', function () {
    let spyRefreshCommon: jest.SpyInstance;
    let refreshToken: string;
    let mockReqest: Request;
    let mockResponse: Response;
    let result: LoginResponseDto | undefined;
    let exception: Error;

    beforeEach(async function () {
      spyRefreshCommon = jest
        .spyOn(controller, 'refreshCommon')
        .mockResolvedValueOnce({
          access_token: 'access_token',
          refresh_token: 'refresh_token',
          type: 'Bearer',
          expires_in: 120,
        } as LoginResponseDto);

      refreshToken = sign({ random: Math.random() }, 'aSecret', {
        expiresIn: mockConfigService.get('JWT_REFRESH_TTL'),
      });

      mockReqest = createRequest({
        user: refreshToken,
      });
      mockResponse = createResponse();

      try {
        result = await controller.refreshWithGet(mockReqest, mockResponse);
      } catch (err) {
        exception = err;
      }
    });

    it('should execute', async function () {
      expect(exception).toBeUndefined();
    });

    it('should call refreshCommon()', async function () {
      expect(spyRefreshCommon).toHaveBeenCalledWith(refreshToken, mockResponse);
    });

    it('should return refreshCommon() return value', async function () {
      expect(result).toEqual({
        access_token: 'access_token',
        expires_in: 120,
        refresh_token: 'refresh_token',
        type: 'Bearer',
      });
    });
  });
});
