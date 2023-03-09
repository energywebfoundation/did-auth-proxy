import { AuthModule } from './auth.module';
import { ConfigService } from '@nestjs/config';
import { MiddlewareConsumer, RequestMethod } from '@nestjs/common';
import { DisableBlockAuthRoutesMiddleware } from '../../middlewares/disable-block-auth-routes.middleware';
import { PinoLogger } from 'nestjs-pino';

describe('AuthModule.configure()', function () {
  let module: AuthModule;

  const configMock = { get: jest.fn() };
  const loggerMock = { info: jest.fn(), setContext: jest.fn() };

  describe('when BLOCKNUM_AUTH_ENABLED===false', function () {
    let exception: Error;
    let mockMiddlewareConsumer: { apply: jest.Mock; forRoutes: jest.Mock };

    beforeEach(async function () {
      configMock.get.mockImplementation((key: string) => {
        return { BLOCKNUM_AUTH_ENABLED: false }[key];
      });

      module = new AuthModule(
        configMock as unknown as ConfigService,
        loggerMock as unknown as PinoLogger,
      );

      mockMiddlewareConsumer = {
        apply: jest.fn().mockImplementation(() => mockMiddlewareConsumer),
        forRoutes: jest.fn(),
      };

      try {
        module.configure(mockMiddlewareConsumer as MiddlewareConsumer);
      } catch (err) {
        exception = err;
      }
    });

    afterEach(async function () {
      Object.values(mockMiddlewareConsumer).forEach((mockedFunction) => {
        mockedFunction.mockReset();
      });

      Object.values(loggerMock).forEach((mockedFunction) => {
        mockedFunction.mockReset();
      });
    });

    it('should execute', async function () {
      expect(exception).toBeUndefined();
    });

    it('should apply the middleware for `POST /auth/login`', async function () {
      expect(mockMiddlewareConsumer.apply).toHaveBeenCalledWith(
        DisableBlockAuthRoutesMiddleware,
      );

      expect(mockMiddlewareConsumer.forRoutes).toHaveBeenCalledWith({
        path: '/auth/login',
        method: RequestMethod.POST,
      });
    });

    it('should write info log message', async function () {
      expect(loggerMock.info).toHaveBeenCalledWith(
        'POST /auth/logger disabled',
      );
    });
  });

  describe('when BLOCKNUM_AUTH_ENABLED===true', function () {
    let exception: Error;
    let mockMiddlewareConsumer: { apply: jest.Mock; forRoutes: jest.Mock };

    beforeEach(async function () {
      configMock.get.mockImplementation((key: string) => {
        return { BLOCKNUM_AUTH_ENABLED: true }[key];
      });

      module = new AuthModule(
        configMock as unknown as ConfigService,
        loggerMock as unknown as PinoLogger,
      );

      mockMiddlewareConsumer = {
        apply: jest.fn().mockImplementation(() => mockMiddlewareConsumer),
        forRoutes: jest.fn(),
      };

      try {
        module.configure(mockMiddlewareConsumer as MiddlewareConsumer);
      } catch (err) {
        exception = err;
      }
    });

    afterEach(async function () {
      Object.values(mockMiddlewareConsumer).forEach((mockedFunction) => {
        mockedFunction.mockReset();
      });

      Object.values(loggerMock).forEach((mockedFunction) => {
        mockedFunction.mockReset();
      });
    });

    it('should execute', async function () {
      expect(exception).toBeUndefined();
    });

    it('should apply no middleware', async function () {
      expect(mockMiddlewareConsumer.apply).not.toHaveBeenCalled();

      expect(mockMiddlewareConsumer.forRoutes).not.toHaveBeenCalled();
    });

    it('should write info log message', async function () {
      expect(loggerMock.info).toHaveBeenCalledWith('POST /auth/logger enabled');
    });
  });
});
