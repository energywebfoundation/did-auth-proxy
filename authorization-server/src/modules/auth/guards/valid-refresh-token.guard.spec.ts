/* eslint-disable @typescript-eslint/no-empty-function */
import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from '../auth.service';
import { JwtModule } from '@nestjs/jwt';
import { ValidRefreshTokenGuard } from './valid-refresh-token.guard';
import { createMock } from '@golevelup/ts-jest';
import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

describe('ValidRefreshTokenGuard', () => {
  let validRefreshTokenGuard: ValidRefreshTokenGuard;

  const mockAuthService = {
    validateRefreshToken: jest.fn(),
  };

  const configBase: Record<string, number | string | boolean> = {
    AUTH_COOKIE_ENABLED: false,
    AUTH_HEADER_ENABLED: false,
    AUTH_COOKIE_NAME_ACCESS_TOKEN: 'accessToken',
    AUTH_COOKIE_NAME_REFRESH_TOKEN: 'refreshToken',
  };

  const mockConfigService = {
    get: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      imports: [
        JwtModule.register({
          secretOrPrivateKey: 'secretKeyValid',
        }),
      ],
      providers: [
        { provide: AuthService, useValue: mockAuthService },
        { provide: ConfigService, useValue: mockConfigService },
      ],
    }).compile();

    validRefreshTokenGuard = new ValidRefreshTokenGuard(
      module.get<AuthService>(AuthService),
      module.get<ConfigService>(ConfigService),
    );
  });

  afterEach(async function () {
    Object.values(mockAuthService).forEach((mockedFunction) => {
      mockedFunction.mockReset();
    });

    Object.values(mockConfigService).forEach((mockedFunction) => {
      mockedFunction.mockReset();
    });
  });

  it('should be defined', () => {
    expect(validRefreshTokenGuard).toBeDefined();
  });

  describe('canActivate()', function () {
    let result: boolean;
    let method: 'GET' | 'POST';
    let exception: Error;
    let mockExtractFromPostBodyOrCookies: jest.SpyInstance;
    let mockExtractFromQueryOrCookies: jest.SpyInstance;

    beforeEach(async function () {
      result = undefined;
      exception = undefined;
      method = undefined;
      mockExtractFromPostBodyOrCookies = undefined;
      mockExtractFromQueryOrCookies = undefined;
    });

    describe('when method is POST', function () {
      beforeEach(async function () {
        method = 'POST';

        const mockExecutionContext = createMock<ExecutionContext>({
          switchToHttp: jest.fn().mockReturnValue({
            getRequest: jest.fn().mockReturnValue({
              method,
              body: {
                foo: 'bar',
              },
              cookies: {
                some: 'cookie',
              },
            }),
          }),
        });

        mockExtractFromPostBodyOrCookies = jest
          .spyOn(validRefreshTokenGuard, 'extractFromPostBodyOrCookies')
          .mockReturnValueOnce('extracted token');

        mockAuthService.validateRefreshToken.mockReturnValueOnce(
          'result of token validation',
        );

        try {
          result =
            await validRefreshTokenGuard.canActivate(mockExecutionContext);
        } catch (err) {
          exception = err;
        }
      });

      it('should execute', async function () {
        expect(exception).toBeUndefined();
      });

      it('should extract token from post body or cookie', async function () {
        expect(mockExtractFromPostBodyOrCookies).toHaveBeenCalledWith(
          { foo: 'bar' },
          { some: 'cookie' },
        );
        expect(mockExtractFromPostBodyOrCookies).toHaveBeenCalledTimes(1);
      });

      it('should validate extracted token', async function () {
        expect(mockAuthService.validateRefreshToken).toHaveBeenCalledWith(
          'extracted token',
        );
        expect(mockAuthService.validateRefreshToken).toHaveBeenCalledTimes(1);
      });

      it('should return result of validation', async function () {
        expect(result).toBe('result of token validation');
      });

      describe('when no token provided', function () {
        beforeEach(async function () {
          jest
            .spyOn(validRefreshTokenGuard, 'extractFromPostBodyOrCookies')
            .mockReturnValueOnce(null);

          const mockExecutionContext = createMock<ExecutionContext>({
            switchToHttp: jest.fn().mockReturnValue({
              getRequest: jest.fn().mockReturnValue({ method }),
            }),
          });

          try {
            result =
              await validRefreshTokenGuard.canActivate(mockExecutionContext);
          } catch (err) {
            exception = err;
          }
        });

        it('should throw `UnauthorizedException`', async function () {
          expect(exception).toBeInstanceOf(UnauthorizedException);
        });
      });
    });

    describe('when method is GET', function () {
      beforeEach(async function () {
        method = 'GET';

        const mockExecutionContext = createMock<ExecutionContext>({
          switchToHttp: jest.fn().mockReturnValue({
            getRequest: jest.fn().mockReturnValue({
              method,
              body: {
                foo: 'bar',
              },
              cookies: {
                some: 'cookie',
              },
              query: {
                some: 'query string value',
              },
            }),
          }),
        });

        mockExtractFromQueryOrCookies = jest
          .spyOn(validRefreshTokenGuard, 'extractFromQueryStringOrCookies')
          .mockReturnValueOnce('token extracted from qs or cookie');

        mockAuthService.validateRefreshToken.mockReturnValueOnce(
          'result of token validation',
        );

        try {
          result =
            await validRefreshTokenGuard.canActivate(mockExecutionContext);
        } catch (err) {
          exception = err;
        }
      });

      it('should execute', async function () {
        expect(exception).toBeUndefined();
      });

      it('should extract token from query string or cookie', async function () {
        expect(mockExtractFromQueryOrCookies).toHaveBeenCalledWith(
          { some: 'cookie' },
          { some: 'query string value' },
        );
        expect(mockExtractFromQueryOrCookies).toHaveBeenCalledTimes(1);
      });

      it('should return result of validation', async function () {
        expect(result).toBe('result of token validation');
      });

      describe('when no token provided', function () {
        beforeEach(async function () {
          jest
            .spyOn(validRefreshTokenGuard, 'extractFromQueryStringOrCookies')
            .mockReturnValueOnce(null);

          const mockExecutionContext = createMock<ExecutionContext>({
            switchToHttp: jest.fn().mockReturnValue({
              getRequest: jest.fn().mockReturnValue({ method }),
            }),
          });

          try {
            result =
              await validRefreshTokenGuard.canActivate(mockExecutionContext);
          } catch (err) {
            exception = err;
          }
        });

        it('should throw `UnauthorizedException`', async function () {
          expect(exception).toBeInstanceOf(UnauthorizedException);
        });
      });
    });

    describe.each(['HEAD', 'OPTIONS', 'PATCH', 'PUT', 'DELETE'])(
      'when method is %s',
      function (method) {
        beforeEach(async function () {
          const mockExecutionContext = createMock<ExecutionContext>({
            switchToHttp: jest.fn().mockReturnValue({
              getRequest: jest.fn().mockReturnValue({
                method,
                body: {
                  foo: 'bar',
                },
                cookies: {
                  some: 'cookie',
                },
              }),
            }),
          });

          mockExtractFromPostBodyOrCookies = jest
            .spyOn(validRefreshTokenGuard, 'extractFromPostBodyOrCookies')
            .mockReturnValueOnce('extracted token');

          mockAuthService.validateRefreshToken.mockReturnValueOnce(
            'result of token validation',
          );

          try {
            result =
              await validRefreshTokenGuard.canActivate(mockExecutionContext);
          } catch (err) {
            exception = err;
          }
        });

        it('should throw Error', async function () {
          expect(result).toBeUndefined();
          expect(exception).toBeInstanceOf(Error);
        });
      },
    );
  });

  describe('extractFromPostBodyOrCookies()', function () {
    let result: string | undefined;
    let exception: Error | undefined;

    describe('when AUTH_COOKIE_ENABLED==false && AUTH_HEADER_ENABLED=false', function () {
      beforeEach(async function () {
        mockConfigService.get.mockImplementation((key: string) => {
          return {
            ...configBase,
            AUTH_COOKIE_ENABLED: false,
            AUTH_HEADER_ENABLED: false,
          }[key];
        });
      });

      describe('when called with no tokens', function () {
        beforeEach(async function () {
          try {
            result = validRefreshTokenGuard.extractFromPostBodyOrCookies();
          } catch (err) {
            exception = err;
          }
        });

        it('should execute', async function () {
          expect(exception).toBeUndefined();
        });

        it('should return no token', async function () {
          expect(result).toBeUndefined();
        });
      });

      describe('when called with valid token in cookie only', function () {
        beforeEach(async function () {
          try {
            result = validRefreshTokenGuard.extractFromPostBodyOrCookies(
              undefined,
              {
                [mockConfigService.get('AUTH_COOKIE_NAME_REFRESH_TOKEN')]:
                  'cookie refresh token',
              },
            );
          } catch (err) {
            exception = err;
          }
        });

        it('should execute', async function () {
          expect(exception).toBeUndefined();
        });

        it('should return no token', async function () {
          expect(result).toBeUndefined();
        });
      });

      describe('when called with valid token in body only', function () {
        beforeEach(async function () {
          try {
            result = validRefreshTokenGuard.extractFromPostBodyOrCookies({
              refreshToken: 'body refresh token',
            });
          } catch (err) {
            exception = err;
          }
        });

        it('should execute', async function () {
          expect(exception).toBeUndefined();
        });

        it('should return no token', async function () {
          expect(result).toBeUndefined();
        });
      });

      describe('when called with valid token in body and cookie', function () {
        describe('when called with valid token in body only', function () {
          beforeEach(async function () {
            try {
              result = validRefreshTokenGuard.extractFromPostBodyOrCookies(
                {
                  refreshToken: 'body refresh token',
                },
                {
                  [mockConfigService.get('AUTH_COOKIE_NAME_REFRESH_TOKEN')]:
                    'cookie refresh token',
                },
              );
            } catch (err) {
              exception = err;
            }
          });

          it('should execute', async function () {
            expect(exception).toBeUndefined();
          });

          it('should return no token', async function () {
            expect(result).toBeUndefined();
          });
        });
      });
    });

    describe('when AUTH_COOKIE_ENABLED==true && AUTH_HEADER_ENABLED=false', function () {
      beforeEach(async function () {
        mockConfigService.get.mockImplementation((key: string) => {
          return {
            ...configBase,
            AUTH_COOKIE_ENABLED: true,
            AUTH_HEADER_ENABLED: false,
          }[key];
        });
      });

      describe('when called with no tokens', function () {
        beforeEach(async function () {
          try {
            result = validRefreshTokenGuard.extractFromPostBodyOrCookies();
          } catch (err) {
            exception = err;
          }
        });

        it('should execute', async function () {
          expect(exception).toBeUndefined();
        });

        it('should return no token', async function () {
          expect(result).toBeUndefined();
        });
      });

      describe('when called with valid token in cookie only', function () {
        beforeEach(async function () {
          try {
            result = validRefreshTokenGuard.extractFromPostBodyOrCookies(
              undefined,
              {
                [mockConfigService.get('AUTH_COOKIE_NAME_REFRESH_TOKEN')]:
                  'cookie refresh token',
              },
            );
          } catch (err) {
            exception = err;
          }
        });

        it('should execute', async function () {
          expect(exception).toBeUndefined();
        });

        it('should return cookie refresh token', async function () {
          expect(result).toBe('cookie refresh token');
        });
      });

      describe('when called with valid token in body only', function () {
        beforeEach(async function () {
          try {
            result = validRefreshTokenGuard.extractFromPostBodyOrCookies({
              refreshToken: 'body refresh token',
            });
          } catch (err) {
            exception = err;
          }
        });

        it('should execute', async function () {
          expect(exception).toBeUndefined();
        });

        it('should return no token', async function () {
          expect(result).toBeUndefined();
        });
      });

      describe('when called with valid token in body and cookie', function () {
        describe('when called with valid token in body only', function () {
          beforeEach(async function () {
            try {
              result = validRefreshTokenGuard.extractFromPostBodyOrCookies(
                {
                  refreshToken: 'body refresh token',
                },
                {
                  [mockConfigService.get('AUTH_COOKIE_NAME_REFRESH_TOKEN')]:
                    'cookie refresh token',
                },
              );
            } catch (err) {
              exception = err;
            }
          });

          it('should execute', async function () {
            expect(exception).toBeUndefined();
          });

          it('should return cookie refresh token', async function () {
            expect(result).toBe('cookie refresh token');
          });
        });
      });
    });

    describe('when AUTH_COOKIE_ENABLED==false && AUTH_HEADER_ENABLED=true', function () {
      beforeEach(async function () {
        mockConfigService.get.mockImplementation((key: string) => {
          return {
            ...configBase,
            AUTH_COOKIE_ENABLED: false,
            AUTH_HEADER_ENABLED: true,
          }[key];
        });
      });

      describe('when called with no tokens', function () {
        beforeEach(async function () {
          try {
            result = validRefreshTokenGuard.extractFromPostBodyOrCookies();
          } catch (err) {
            exception = err;
          }
        });

        it('should execute', async function () {
          expect(exception).toBeUndefined();
        });

        it('should return no token', async function () {
          expect(result).toBeUndefined();
        });
      });

      describe('when called with valid token in cookie only', function () {
        beforeEach(async function () {
          try {
            result = validRefreshTokenGuard.extractFromPostBodyOrCookies(
              undefined,
              {
                [mockConfigService.get('AUTH_COOKIE_NAME_REFRESH_TOKEN')]:
                  'cookie refresh token',
              },
            );
          } catch (err) {
            exception = err;
          }
        });

        it('should execute', async function () {
          expect(exception).toBeUndefined();
        });

        it('should return no token', async function () {
          expect(result).toBeUndefined();
        });
      });

      describe('when called with valid token in body only', function () {
        beforeEach(async function () {
          try {
            result = validRefreshTokenGuard.extractFromPostBodyOrCookies({
              refreshToken: 'body refresh token',
            });
          } catch (err) {
            exception = err;
          }
        });

        it('should execute', async function () {
          expect(exception).toBeUndefined();
        });

        it('should return body refresh token', async function () {
          expect(result).toBe('body refresh token');
        });
      });

      describe('when called with valid token in body and cookie', function () {
        describe('when called with valid token in body only', function () {
          beforeEach(async function () {
            try {
              result = validRefreshTokenGuard.extractFromPostBodyOrCookies(
                {
                  refreshToken: 'body refresh token',
                },
                {
                  [mockConfigService.get('AUTH_COOKIE_NAME_REFRESH_TOKEN')]:
                    'cookie refresh token',
                },
              );
            } catch (err) {
              exception = err;
            }
          });

          it('should execute', async function () {
            expect(exception).toBeUndefined();
          });

          it('should return body refresh token', async function () {
            expect(result).toBe('body refresh token');
          });
        });
      });
    });

    describe('when AUTH_COOKIE_ENABLED==true && AUTH_HEADER_ENABLED=true', function () {
      beforeEach(async function () {
        mockConfigService.get.mockImplementation((key: string) => {
          return {
            ...configBase,
            AUTH_COOKIE_ENABLED: true,
            AUTH_HEADER_ENABLED: true,
          }[key];
        });
      });

      describe('when called with no tokens', function () {
        beforeEach(async function () {
          try {
            result = validRefreshTokenGuard.extractFromPostBodyOrCookies();
          } catch (err) {
            exception = err;
          }
        });

        it('should execute', async function () {
          expect(exception).toBeUndefined();
        });

        it('should return no token', async function () {
          expect(result).toBeUndefined();
        });
      });

      describe('when called with valid token in cookie only', function () {
        beforeEach(async function () {
          try {
            result = validRefreshTokenGuard.extractFromPostBodyOrCookies(
              undefined,
              {
                [mockConfigService.get('AUTH_COOKIE_NAME_REFRESH_TOKEN')]:
                  'cookie refresh token',
              },
            );
          } catch (err) {
            exception = err;
          }
        });

        it('should execute', async function () {
          expect(exception).toBeUndefined();
        });

        it('should return cookie refresh token', async function () {
          expect(result).toBe('cookie refresh token');
        });
      });

      describe('when called with valid token in body only', function () {
        beforeEach(async function () {
          try {
            result = validRefreshTokenGuard.extractFromPostBodyOrCookies({
              refreshToken: 'body refresh token',
            });
          } catch (err) {
            exception = err;
          }
        });

        it('should execute', async function () {
          expect(exception).toBeUndefined();
        });

        it('should return body refresh token', async function () {
          expect(result).toBe('body refresh token');
        });
      });

      describe('when called with valid token in body and cookie', function () {
        describe('when called with valid token in body only', function () {
          beforeEach(async function () {
            try {
              result = validRefreshTokenGuard.extractFromPostBodyOrCookies(
                {
                  refreshToken: 'body refresh token',
                },
                {
                  [mockConfigService.get('AUTH_COOKIE_NAME_REFRESH_TOKEN')]:
                    'cookie refresh token',
                },
              );
            } catch (err) {
              exception = err;
            }
          });

          it('should execute', async function () {
            expect(exception).toBeUndefined();
          });

          it('should return body refresh token', async function () {
            expect(result).toBe('body refresh token');
          });
        });
      });
    });
  });

  describe('extractFromQueryStringOrCookies()', function () {
    let result: string | undefined;
    let exception: Error | undefined;

    describe('when AUTH_COOKIE_ENABLED==false && AUTH_HEADER_ENABLED=false', function () {
      beforeEach(async function () {
        mockConfigService.get.mockImplementation((key: string) => {
          return {
            ...configBase,
            AUTH_COOKIE_ENABLED: false,
            AUTH_HEADER_ENABLED: false,
          }[key];
        });
      });

      describe('when called with no tokens', function () {
        beforeEach(async function () {
          try {
            result = validRefreshTokenGuard.extractFromQueryStringOrCookies();
          } catch (err) {
            exception = err;
          }
        });

        it('should execute', async function () {
          expect(exception).toBeUndefined();
        });

        it('should return no token', async function () {
          expect(result).toBeUndefined();
        });
      });

      describe('when called with token in cookie only', function () {
        beforeEach(async function () {
          try {
            result = validRefreshTokenGuard.extractFromQueryStringOrCookies({
              [mockConfigService.get('AUTH_COOKIE_NAME_REFRESH_TOKEN')]:
                'cookie refresh token',
            });
          } catch (err) {
            exception = err;
          }
        });

        it('should execute', async function () {
          expect(exception).toBeUndefined();
        });

        it('should return no token', async function () {
          expect(result).toBeUndefined();
        });
      });

      describe('when called with token in query string only', function () {
        beforeEach(async function () {
          try {
            result = validRefreshTokenGuard.extractFromQueryStringOrCookies(
              undefined,
              {
                refresh_token: 'query string refresh token',
              },
            );
          } catch (err) {
            exception = err;
          }
        });

        it('should execute', async function () {
          expect(exception).toBeUndefined();
        });

        it('should return no token', async function () {
          expect(result).toBeUndefined();
        });
      });

      describe('when called with token in query string and cookies', function () {
        beforeEach(async function () {
          try {
            result = validRefreshTokenGuard.extractFromQueryStringOrCookies(
              {
                [mockConfigService.get('AUTH_COOKIE_NAME_REFRESH_TOKEN')]:
                  'cookie refresh token',
              },
              {
                refresh_token: 'query string refresh token',
              },
            );
          } catch (err) {
            exception = err;
          }
        });

        it('should execute', async function () {
          expect(exception).toBeUndefined();
        });

        it('should return no token', async function () {
          expect(result).toBeUndefined();
        });
      });
    });

    describe('when AUTH_COOKIE_ENABLED==true && AUTH_HEADER_ENABLED=false', function () {
      beforeEach(async function () {
        mockConfigService.get.mockImplementation((key: string) => {
          return {
            ...configBase,
            AUTH_COOKIE_ENABLED: true,
            AUTH_HEADER_ENABLED: false,
          }[key];
        });
      });

      describe('when called with no tokens', function () {
        beforeEach(async function () {
          try {
            result = validRefreshTokenGuard.extractFromQueryStringOrCookies();
          } catch (err) {
            exception = err;
          }
        });

        it('should execute', async function () {
          expect(exception).toBeUndefined();
        });

        it('should return no token', async function () {
          expect(result).toBeUndefined();
        });
      });

      describe('when called with token in cookie only', function () {
        beforeEach(async function () {
          try {
            result = validRefreshTokenGuard.extractFromQueryStringOrCookies({
              [mockConfigService.get('AUTH_COOKIE_NAME_REFRESH_TOKEN')]:
                'cookie refresh token',
            });
          } catch (err) {
            exception = err;
          }
        });

        it('should execute', async function () {
          expect(exception).toBeUndefined();
        });

        it('should return cookie refresh token', async function () {
          expect(result).toBe('cookie refresh token');
        });
      });

      describe('when called with token in query string only', function () {
        beforeEach(async function () {
          try {
            result = validRefreshTokenGuard.extractFromQueryStringOrCookies(
              undefined,
              {
                refresh_token: 'query string refresh token',
              },
            );
          } catch (err) {
            exception = err;
          }
        });

        it('should execute', async function () {
          expect(exception).toBeUndefined();
        });

        it('should return no token', async function () {
          expect(result).toBeUndefined();
        });
      });

      describe('when called with token in query string and cookies', function () {
        beforeEach(async function () {
          try {
            result = validRefreshTokenGuard.extractFromQueryStringOrCookies(
              {
                [mockConfigService.get('AUTH_COOKIE_NAME_REFRESH_TOKEN')]:
                  'cookie refresh token',
              },
              {
                refresh_token: 'query string refresh token',
              },
            );
          } catch (err) {
            exception = err;
          }
        });

        it('should execute', async function () {
          expect(exception).toBeUndefined();
        });

        it('should return no token', async function () {
          expect(result).toBe('cookie refresh token');
        });
      });
    });

    describe('when AUTH_COOKIE_ENABLED==false && AUTH_HEADER_ENABLED=true', function () {
      beforeEach(async function () {
        mockConfigService.get.mockImplementation((key: string) => {
          return {
            ...configBase,
            AUTH_COOKIE_ENABLED: false,
            AUTH_HEADER_ENABLED: true,
          }[key];
        });
      });

      describe('when called with no tokens', function () {
        beforeEach(async function () {
          try {
            result = validRefreshTokenGuard.extractFromQueryStringOrCookies();
          } catch (err) {
            exception = err;
          }
        });

        it('should execute', async function () {
          expect(exception).toBeUndefined();
        });

        it('should return no token', async function () {
          expect(result).toBeUndefined();
        });
      });

      describe('when called with token in cookie only', function () {
        beforeEach(async function () {
          try {
            result = validRefreshTokenGuard.extractFromQueryStringOrCookies({
              [mockConfigService.get('AUTH_COOKIE_NAME_REFRESH_TOKEN')]:
                'cookie refresh token',
            });
          } catch (err) {
            exception = err;
          }
        });

        it('should execute', async function () {
          expect(exception).toBeUndefined();
        });

        it('should return no token', async function () {
          expect(result).toBeUndefined();
        });
      });

      describe('when called with token in query string only', function () {
        beforeEach(async function () {
          try {
            result = validRefreshTokenGuard.extractFromQueryStringOrCookies(
              undefined,
              {
                refresh_token: 'query string refresh token',
              },
            );
          } catch (err) {
            exception = err;
          }
        });

        it('should execute', async function () {
          expect(exception).toBeUndefined();
        });

        it('should return no token', async function () {
          expect(result).toBe('query string refresh token');
        });
      });

      describe('when called with token in query string and cookies', function () {
        beforeEach(async function () {
          try {
            result = validRefreshTokenGuard.extractFromQueryStringOrCookies(
              {
                [mockConfigService.get('AUTH_COOKIE_NAME_REFRESH_TOKEN')]:
                  'cookie refresh token',
              },
              {
                refresh_token: 'query string refresh token',
              },
            );
          } catch (err) {
            exception = err;
          }
        });

        it('should execute', async function () {
          expect(exception).toBeUndefined();
        });

        it('should return no token', async function () {
          expect(result).toBe('query string refresh token');
        });
      });
    });

    describe('when AUTH_COOKIE_ENABLED==true && AUTH_HEADER_ENABLED=true', function () {
      beforeEach(async function () {
        mockConfigService.get.mockImplementation((key: string) => {
          return {
            ...configBase,
            AUTH_COOKIE_ENABLED: true,
            AUTH_HEADER_ENABLED: true,
          }[key];
        });
      });

      describe('when called with no tokens', function () {
        beforeEach(async function () {
          try {
            result = validRefreshTokenGuard.extractFromQueryStringOrCookies();
          } catch (err) {
            exception = err;
          }
        });

        it('should execute', async function () {
          expect(exception).toBeUndefined();
        });

        it('should return no token', async function () {
          expect(result).toBeUndefined();
        });
      });

      describe('when called with token in cookie only', function () {
        beforeEach(async function () {
          try {
            result = validRefreshTokenGuard.extractFromQueryStringOrCookies({
              [mockConfigService.get('AUTH_COOKIE_NAME_REFRESH_TOKEN')]:
                'cookie refresh token',
            });
          } catch (err) {
            exception = err;
          }
        });

        it('should execute', async function () {
          expect(exception).toBeUndefined();
        });

        it('should return no token', async function () {
          expect(result).toBe('cookie refresh token');
        });
      });

      describe('when called with token in query string only', function () {
        beforeEach(async function () {
          try {
            result = validRefreshTokenGuard.extractFromQueryStringOrCookies(
              undefined,
              {
                refresh_token: 'query string refresh token',
              },
            );
          } catch (err) {
            exception = err;
          }
        });

        it('should execute', async function () {
          expect(exception).toBeUndefined();
        });

        it('should return no token', async function () {
          expect(result).toBe('query string refresh token');
        });
      });

      describe('when called with token in query string and cookies', function () {
        beforeEach(async function () {
          try {
            result = validRefreshTokenGuard.extractFromQueryStringOrCookies(
              {
                [mockConfigService.get('AUTH_COOKIE_NAME_REFRESH_TOKEN')]:
                  'cookie refresh token',
              },
              {
                refresh_token: 'query string refresh token',
              },
            );
          } catch (err) {
            exception = err;
          }
        });

        it('should execute', async function () {
          expect(exception).toBeUndefined();
        });

        it('should return no token', async function () {
          expect(result).toBe('query string refresh token');
        });
      });
    });
  });
});
