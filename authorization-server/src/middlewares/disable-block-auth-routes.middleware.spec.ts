import { DisableBlockAuthRoutesMiddleware } from './disable-block-auth-routes.middleware';
import { PinoLogger } from 'nestjs-pino';
import { createRequest, createResponse } from 'node-mocks-http';
import { NextFunction, Request, Response } from 'express';

const mockLogger = { warn: jest.fn(), setContext: jest.fn() };

describe('DisableBlockAuthRoutesMiddleware', function () {
  let disableBlockAuthRoutesMiddleware: DisableBlockAuthRoutesMiddleware;

  beforeEach(async function () {
    disableBlockAuthRoutesMiddleware = new DisableBlockAuthRoutesMiddleware(
      mockLogger as unknown as PinoLogger,
    );
  });

  it('should be defined', async function () {
    expect(disableBlockAuthRoutesMiddleware).toBeDefined();
  });

  describe('use() when called', function () {
    describe('when called for `/auth/login` path', function () {
      let exception: Error;
      let requestMock: Request;
      let responseMock: Response;
      let next: NextFunction;

      beforeEach(async function () {
        requestMock = createRequest({
          method: 'POST',
          originalUrl: '/auth/login',
        });

        responseMock = createResponse();
        responseMock.status = jest.fn().mockImplementation(() => responseMock);
        responseMock.send = jest.fn().mockImplementation(() => responseMock);

        next = jest.fn();

        try {
          disableBlockAuthRoutesMiddleware.use(requestMock, responseMock, next);
        } catch (err) {
          exception = err;
        }
      });

      afterEach(async function () {
        Object.values(mockLogger).forEach((mockedFunction) => {
          mockedFunction.mockReset();
        });
      });

      it('should execute', async function () {
        expect(exception).toBeUndefined();
      });

      it('should not call the next', async function () {
        expect(next).not.toHaveBeenCalled();
      });

      it('should set response 404 status code', async function () {
        expect(responseMock.status).toHaveBeenCalledWith(404);
      });

      it('should send a response', async function () {
        expect(responseMock.send).toHaveBeenCalledWith({
          message:
            'Authentication at this endpoint is disabled. Other authentication protocols may be available',
        });
      });

      it('should write a warn message', async function () {
        expect(mockLogger.warn).toHaveBeenCalledWith(
          'unexpected POST /auth/login request',
        );
      });
    });
  });
});
