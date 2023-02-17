/* eslint-disable @typescript-eslint/no-empty-function */
import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from '../auth.service';
import { JwtModule } from '@nestjs/jwt';
import { ValidRefreshTokenGuard } from './valid-refresh-token.guard';
import { createMock } from '@golevelup/ts-jest';
import { ExecutionContext } from '@nestjs/common';

describe('ValidRefreshTokenGuard', () => {
  let validRefreshTokenGuard: ValidRefreshTokenGuard;

  const mockAuthService = {
    validateRefreshToken: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      imports: [
        JwtModule.register({
          secretOrPrivateKey: 'secretKeyValid',
        }),
      ],
      providers: [{ provide: AuthService, useValue: mockAuthService }],
    }).compile();

    validRefreshTokenGuard = new ValidRefreshTokenGuard(
      module.get<AuthService>(AuthService),
    );
  });

  afterEach(async function () {
    Object.values(mockAuthService).forEach((mockedFunction) => {
      mockedFunction.mockReset();
    });
  });

  it('should be defined', () => {
    expect(validRefreshTokenGuard).toBeDefined();
  });

  describe('canActivate()', function () {
    describe('when called without refreshToken field', function () {
      let result: boolean;

      beforeEach(async function () {
        const mockExecutionContext = createMock<ExecutionContext>({
          switchToHttp: jest.fn().mockReturnValue({
            getRequest: jest.fn().mockReturnValue({
              body: { foo: 'bar' },
            }),
          }),
        });

        result = await validRefreshTokenGuard.canActivate(mockExecutionContext);
      });

      it('should resolve to false', async function () {
        expect(result).toBe(false);
      });

      it('should not try to validate non-existent token', async function () {
        expect(mockAuthService.validateRefreshToken).not.toHaveBeenCalled();
      });
    });

    describe('when called with refreshToken field containing valid token', function () {
      let result: boolean;

      beforeEach(async function () {
        const mockExecutionContext = createMock<ExecutionContext>({
          switchToHttp: jest.fn().mockReturnValue({
            getRequest: jest.fn().mockReturnValue({
              body: { refreshToken: 'a refresh token' },
            }),
          }),
        });

        mockAuthService.validateRefreshToken.mockImplementation(
          async () => true,
        );

        result = await validRefreshTokenGuard.canActivate(mockExecutionContext);
      });

      it('should validate refreshToken', async function () {
        expect(mockAuthService.validateRefreshToken).toHaveBeenCalledWith(
          'a refresh token',
        );
      });

      it('should resolve to true', async function () {
        expect(result).toBe(true);
      });
    });

    describe('when called with refreshToken field containing invalid token', function () {
      let result: boolean;

      beforeEach(async function () {
        const mockExecutionContext = createMock<ExecutionContext>({
          switchToHttp: jest.fn().mockReturnValue({
            getRequest: jest.fn().mockReturnValue({
              body: { refreshToken: 'a refresh token' },
            }),
          }),
        });

        mockAuthService.validateRefreshToken.mockImplementation(
          async () => false,
        );

        result = await validRefreshTokenGuard.canActivate(mockExecutionContext);
      });

      it('should validate refreshToken', async function () {
        expect(mockAuthService.validateRefreshToken).toHaveBeenCalledWith(
          'a refresh token',
        );
      });

      it('should resolve to true', async function () {
        expect(result).toBe(false);
      });
    });
  });
});
