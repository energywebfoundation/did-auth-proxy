import { DefaultRequestBodyMiddleware } from './default-request-body.middleware';
import { createRequest, createResponse } from 'node-mocks-http';
import { NextFunction, Request, Response } from 'express';

describe('DefaultRequestBodyMiddleware', function () {
  let defaultRequestBodyMiddleware: DefaultRequestBodyMiddleware;

  beforeEach(async function () {
    defaultRequestBodyMiddleware = new DefaultRequestBodyMiddleware();
  });

  it('should be defined', async function () {
    expect(defaultRequestBodyMiddleware).toBeDefined();
  });

  describe('use() when called', function () {
    let requestMock: Request;
    let responseMock: Response;
    let next: NextFunction;

    beforeEach(async function () {
      requestMock = createRequest({ method: 'POST', url: '/auth/login' });
      responseMock = createResponse();
      next = jest.fn();
    });

    describe('for a request without a body', function () {
      beforeEach(async function () {
        requestMock.body = undefined;

        defaultRequestBodyMiddleware.use(requestMock, responseMock, next);
      });

      it('should set the body to an empty object', async function () {
        expect(requestMock.body).toEqual({});
      });

      it('should call the next', async function () {
        expect(next).toHaveBeenCalledTimes(1);
      });
    });

    describe('for a request with a body', function () {
      const body = { identityToken: 'foobar' };

      beforeEach(async function () {
        requestMock.body = body;

        defaultRequestBodyMiddleware.use(requestMock, responseMock, next);
      });

      it('should keep the body unchanged', async function () {
        expect(requestMock.body).toBe(body);
      });

      it('should call the next', async function () {
        expect(next).toHaveBeenCalledTimes(1);
      });
    });
  });
});
