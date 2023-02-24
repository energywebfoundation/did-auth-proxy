/* eslint-disable @typescript-eslint/no-empty-function */
import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from '../auth.service';
import { JwtModule } from '@nestjs/jwt';
import { ValidRefreshTokenGuard } from './valid-refresh-token.guard';
import { createMock } from '@golevelup/ts-jest';
import { ExecutionContext } from '@nestjs/common';
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
          const mockExecutionContext = createMock<ExecutionContext>({
            switchToHttp: jest.fn().mockReturnValue({
              getRequest: jest.fn().mockReturnValue({}),
            }),
          });

          result = await validRefreshTokenGuard.canActivate(
            mockExecutionContext,
          );
        });

        it('should resolve to false', async function () {
          expect(result).toBe(false);
        });

        it('should validate no token', async function () {
          expect(mockAuthService.validateRefreshToken).not.toHaveBeenCalled();
        });
      });

      describe('when called with valid token in cookie only', function () {
        beforeEach(async function () {
          mockAuthService.validateRefreshToken.mockImplementationOnce(
            async () => true,
          );

          const mockExecutionContext = createMock<ExecutionContext>({
            switchToHttp: jest.fn().mockReturnValue({
              getRequest: jest.fn().mockReturnValue({
                cookies: { refreshToken: 'cookie refresh token' },
              }),
            }),
          });

          result = await validRefreshTokenGuard.canActivate(
            mockExecutionContext,
          );
        });

        it('should resolve to false', async function () {
          expect(result).toBe(false);
        });

        it('should validate no token', async function () {
          expect(mockAuthService.validateRefreshToken).not.toHaveBeenCalled();
        });
      });

      describe('when called with valid token in body only', function () {
        beforeEach(async function () {
          mockAuthService.validateRefreshToken.mockImplementationOnce(
            async () => true,
          );

          const mockExecutionContext = createMock<ExecutionContext>({
            switchToHttp: jest.fn().mockReturnValue({
              getRequest: jest.fn().mockReturnValue({
                body: { refreshToken: 'body refresh token' },
              }),
            }),
          });

          result = await validRefreshTokenGuard.canActivate(
            mockExecutionContext,
          );
        });

        it('should resolve to false', async function () {
          expect(result).toBe(false);
        });

        it('should validate no token', async function () {
          expect(mockAuthService.validateRefreshToken).not.toHaveBeenCalled();
        });
      });

      describe('when called with valid token in body and cooki', function () {
        beforeEach(async function () {
          mockAuthService.validateRefreshToken.mockImplementationOnce(
            async () => true,
          );

          const mockExecutionContext = createMock<ExecutionContext>({
            switchToHttp: jest.fn().mockReturnValue({
              getRequest: jest.fn().mockReturnValue({
                cookies: { refreshToken: 'cookie refresh token' },
                body: { refreshToken: 'body refresh token' },
              }),
            }),
          });

          result = await validRefreshTokenGuard.canActivate(
            mockExecutionContext,
          );
        });

        it('should resolve to false', async function () {
          expect(result).toBe(false);
        });

        it('should validate no token', async function () {
          expect(mockAuthService.validateRefreshToken).not.toHaveBeenCalled();
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
          const mockExecutionContext = createMock<ExecutionContext>({
            switchToHttp: jest.fn().mockReturnValue({
              getRequest: jest.fn().mockReturnValue({}),
            }),
          });

          result = await validRefreshTokenGuard.canActivate(
            mockExecutionContext,
          );
        });

        it('should resolve to false', async function () {
          expect(result).toBe(false);
        });

        it('should validate no token', async function () {
          expect(mockAuthService.validateRefreshToken).not.toHaveBeenCalled();
        });
      });

      describe('when called with valid token in cookie only', function () {
        beforeEach(async function () {
          mockAuthService.validateRefreshToken.mockImplementationOnce(
            async () => true,
          );

          const mockExecutionContext = createMock<ExecutionContext>({
            switchToHttp: jest.fn().mockReturnValue({
              getRequest: jest.fn().mockReturnValue({
                cookies: { refreshToken: 'cookie refresh token' },
              }),
            }),
          });

          result = await validRefreshTokenGuard.canActivate(
            mockExecutionContext,
          );
        });

        it('should resolve to true', async function () {
          expect(result).toBe(true);
        });

        it('should validate cookie token', async function () {
          expect(mockAuthService.validateRefreshToken).toHaveBeenCalledWith(
            'cookie refresh token',
          );
        });
      });

      describe('when called with valid token in body only', function () {
        beforeEach(async function () {
          mockAuthService.validateRefreshToken.mockImplementationOnce(
            async () => true,
          );

          const mockExecutionContext = createMock<ExecutionContext>({
            switchToHttp: jest.fn().mockReturnValue({
              getRequest: jest.fn().mockReturnValue({
                body: { refreshToken: 'body refresh token' },
              }),
            }),
          });

          result = await validRefreshTokenGuard.canActivate(
            mockExecutionContext,
          );
        });

        it('should resolve to false', async function () {
          expect(result).toBe(false);
        });

        it('should validate no token', async function () {
          expect(mockAuthService.validateRefreshToken).not.toHaveBeenCalled();
        });
      });

      describe('when called with valid token in body and cookie', function () {
        beforeEach(async function () {
          mockAuthService.validateRefreshToken.mockImplementationOnce(
            async () => true,
          );

          const mockExecutionContext = createMock<ExecutionContext>({
            switchToHttp: jest.fn().mockReturnValue({
              getRequest: jest.fn().mockReturnValue({
                cookies: { refreshToken: 'cookie refresh token' },
                body: { refreshToken: 'body refresh token' },
              }),
            }),
          });

          result = await validRefreshTokenGuard.canActivate(
            mockExecutionContext,
          );
        });

        it('should resolve to true', async function () {
          expect(result).toBe(true);
        });

        it('should validate cookie token', async function () {
          expect(mockAuthService.validateRefreshToken).toHaveBeenCalledWith(
            'cookie refresh token',
          );
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
          const mockExecutionContext = createMock<ExecutionContext>({
            switchToHttp: jest.fn().mockReturnValue({
              getRequest: jest.fn().mockReturnValue({}),
            }),
          });

          result = await validRefreshTokenGuard.canActivate(
            mockExecutionContext,
          );
        });

        it('should resolve to false', async function () {
          expect(result).toBe(false);
        });

        it('should validate no token', async function () {
          expect(mockAuthService.validateRefreshToken).not.toHaveBeenCalled();
        });
      });

      describe('when called with valid token in cookie only', function () {
        beforeEach(async function () {
          mockAuthService.validateRefreshToken.mockImplementationOnce(
            async () => true,
          );

          const mockExecutionContext = createMock<ExecutionContext>({
            switchToHttp: jest.fn().mockReturnValue({
              getRequest: jest.fn().mockReturnValue({
                cookies: { refreshToken: 'cookie refresh token' },
              }),
            }),
          });

          result = await validRefreshTokenGuard.canActivate(
            mockExecutionContext,
          );
        });

        it('should resolve to false', async function () {
          expect(result).toBe(false);
        });

        it('should validate no token', async function () {
          expect(mockAuthService.validateRefreshToken).not.toHaveBeenCalled();
        });
      });

      describe('when called with valid token in body only', function () {
        beforeEach(async function () {
          mockAuthService.validateRefreshToken.mockImplementationOnce(
            async () => true,
          );

          const mockExecutionContext = createMock<ExecutionContext>({
            switchToHttp: jest.fn().mockReturnValue({
              getRequest: jest.fn().mockReturnValue({
                body: { refreshToken: 'body refresh token' },
              }),
            }),
          });

          result = await validRefreshTokenGuard.canActivate(
            mockExecutionContext,
          );
        });

        it('should resolve to true', async function () {
          expect(result).toBe(true);
        });

        it('should validate body token', async function () {
          expect(mockAuthService.validateRefreshToken).toHaveBeenCalledWith(
            'body refresh token',
          );
        });
      });

      describe('when called with valid token in body and cookie', function () {
        beforeEach(async function () {
          mockAuthService.validateRefreshToken.mockImplementationOnce(
            async () => true,
          );

          const mockExecutionContext = createMock<ExecutionContext>({
            switchToHttp: jest.fn().mockReturnValue({
              getRequest: jest.fn().mockReturnValue({
                cookies: { refreshToken: 'cookie refresh token' },
                body: { refreshToken: 'body refresh token' },
              }),
            }),
          });

          result = await validRefreshTokenGuard.canActivate(
            mockExecutionContext,
          );
        });

        it('should resolve to true', async function () {
          expect(result).toBe(true);
        });

        it('should validate body token', async function () {
          expect(mockAuthService.validateRefreshToken).toHaveBeenCalledWith(
            'body refresh token',
          );
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
          const mockExecutionContext = createMock<ExecutionContext>({
            switchToHttp: jest.fn().mockReturnValue({
              getRequest: jest.fn().mockReturnValue({}),
            }),
          });

          result = await validRefreshTokenGuard.canActivate(
            mockExecutionContext,
          );
        });

        it('should resolve to false', async function () {
          expect(result).toBe(false);
        });

        it('should validate no token', async function () {
          expect(mockAuthService.validateRefreshToken).not.toHaveBeenCalled();
        });
      });

      describe('when called with valid token in cookie only', function () {
        beforeEach(async function () {
          mockAuthService.validateRefreshToken.mockImplementationOnce(
            async () => true,
          );

          const mockExecutionContext = createMock<ExecutionContext>({
            switchToHttp: jest.fn().mockReturnValue({
              getRequest: jest.fn().mockReturnValue({
                cookies: { refreshToken: 'cookie refresh token' },
              }),
            }),
          });

          result = await validRefreshTokenGuard.canActivate(
            mockExecutionContext,
          );
        });

        it('should resolve to true', async function () {
          expect(result).toBe(true);
        });

        it('should validate cookie token', async function () {
          expect(mockAuthService.validateRefreshToken).toHaveBeenCalledWith(
            'cookie refresh token',
          );
        });
      });

      describe('when called with valid token in body only', function () {
        beforeEach(async function () {
          mockAuthService.validateRefreshToken.mockImplementationOnce(
            async () => true,
          );

          const mockExecutionContext = createMock<ExecutionContext>({
            switchToHttp: jest.fn().mockReturnValue({
              getRequest: jest.fn().mockReturnValue({
                body: { refreshToken: 'body refresh token' },
              }),
            }),
          });

          result = await validRefreshTokenGuard.canActivate(
            mockExecutionContext,
          );
        });

        it('should resolve to true', async function () {
          expect(result).toBe(true);
        });

        it('should validate body token', async function () {
          expect(mockAuthService.validateRefreshToken).toHaveBeenCalledWith(
            'body refresh token',
          );
        });
      });

      describe('when called with valid token in body and cookie', function () {
        beforeEach(async function () {
          mockAuthService.validateRefreshToken.mockImplementationOnce(
            async () => true,
          );

          const mockExecutionContext = createMock<ExecutionContext>({
            switchToHttp: jest.fn().mockReturnValue({
              getRequest: jest.fn().mockReturnValue({
                cookies: { refreshToken: 'cookie refresh token' },
                body: { refreshToken: 'body refresh token' },
              }),
            }),
          });

          result = await validRefreshTokenGuard.canActivate(
            mockExecutionContext,
          );
        });

        it('should resolve to true', async function () {
          expect(result).toBe(true);
        });

        it('should validate body token', async function () {
          expect(mockAuthService.validateRefreshToken).toHaveBeenCalledWith(
            'body refresh token',
          );
        });
      });
    });
  });
});
