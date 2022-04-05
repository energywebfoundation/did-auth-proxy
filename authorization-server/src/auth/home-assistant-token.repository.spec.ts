/* eslint-disable @typescript-eslint/no-empty-function */
import { Test, TestingModule } from '@nestjs/testing';
import { HomeAssistantTokenRepository } from './home-assistant-token.repository';
import { LoggerService } from '../logger/logger.service';
import { ConfigService } from '@nestjs/config';
import * as fs from 'fs/promises';
import { resolve } from 'path';

jest.mock('fs/promises');

const mockFs = jest.mocked(fs, true);

describe('HomeAssistantTokenRepository', function () {
  let repository: HomeAssistantTokenRepository;
  let loggerService: LoggerService;

  const mockConfigService = {
    get(key: string) {
      return {
        HOME_ASSISTANT_TOKENS_FILE: 'tokens.json',
      }[key];
    },
  };

  beforeEach(async function () {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        HomeAssistantTokenRepository,
        {
          provide: LoggerService,
          useValue: new LoggerService(),
        },
        { provide: ConfigService, useValue: mockConfigService },
      ],
    }).compile();

    repository = module.get<HomeAssistantTokenRepository>(
      HomeAssistantTokenRepository,
    );

    loggerService = module.get<LoggerService>(LoggerService);
  });

  it('should be defined', function () {
    expect(repository).toBeDefined();
  });

  describe('loadDataFromFile()', function () {
    let spyReadFile: jest.SpyInstance;

    it('should be defined', async function () {
      expect(repository.loadDataFromFile).toBeDefined();
    });

    afterEach(async function () {
      spyReadFile?.mockClear().mockRestore();
    });

    describe('when called with valid tokens file', function () {
      beforeEach(async function () {
        spyReadFile = jest.spyOn(mockFs, 'readFile').mockImplementation(() => {
          return Promise.resolve(
            JSON.stringify([
              { did: 'did:example:123456789abcdefghi', token: 'token' },
            ]),
          );
        });

        await repository.loadDataFromFile();
      });

      it('should read tokens file', async function () {
        expect(spyReadFile).toHaveBeenCalledWith(
          resolve('tokens.json'),
          'utf8',
        );
      });
    });

    describe('when called with non-parseable tokens file', function () {
      let exceptionThrown: Error;
      let tokensFilePath: string;
      let spyLogError: jest.SpyInstance;

      beforeEach(async function () {
        tokensFilePath = resolve('tokens.json');

        spyReadFile = jest.spyOn(mockFs, 'readFile').mockImplementation(() => {
          return Promise.resolve('foobar');
        });

        spyLogError = jest
          .spyOn(loggerService, 'error')
          .mockImplementation(() => {});

        try {
          await repository.loadDataFromFile();
        } catch (e) {
          exceptionThrown = e;
        }
      });

      afterEach(async function () {
        spyLogError?.mockClear().mockRestore();
      });

      it('should throw an exception', async function () {
        expect(exceptionThrown).toBeDefined();
        expect(exceptionThrown.message).toBe(
          `error parsing data from ${tokensFilePath}`,
        );
      });

      it('should log error message', async function () {
        expect(spyLogError).toHaveBeenCalledWith(
          `error parsing data from ${tokensFilePath}`,
        );
      });
    });

    describe('when called with non-array tokens file data', function () {
      let exceptionThrown: Error;
      let tokensFilePath: string;
      let spyLogError: jest.SpyInstance;

      beforeEach(async function () {
        tokensFilePath = resolve('tokens.json');

        spyReadFile = jest.spyOn(mockFs, 'readFile').mockImplementation(() => {
          return Promise.resolve(
            JSON.stringify({
              did: 'did:example:123456789abcdefghi',
              token: 'token',
            }),
          );
        });

        spyLogError = jest
          .spyOn(loggerService, 'error')
          .mockImplementation(() => {});

        try {
          await repository.loadDataFromFile();
        } catch (e) {
          exceptionThrown = e;
        }
      });

      afterEach(async function () {
        spyLogError?.mockClear().mockRestore();
      });

      it('should throw an exception', async function () {
        expect(exceptionThrown).toBeDefined();
        expect(exceptionThrown.message).toBe(
          `data from ${tokensFilePath} is not an array`,
        );
      });

      it('should log error message', async function () {
        expect(spyLogError).toHaveBeenCalledWith(
          `data from ${tokensFilePath} is not an array`,
        );
      });
    });

    describe('when called with tokens file data not containing did field', function () {
      let exceptionThrown: Error;
      let tokensFilePath: string;
      let spyLogError: jest.SpyInstance;

      beforeEach(async function () {
        tokensFilePath = resolve('tokens.json');

        spyReadFile = jest.spyOn(mockFs, 'readFile').mockImplementation(() => {
          return Promise.resolve(
            JSON.stringify([
              {
                did: 'did:example:123456789abcdefghi',
                token: 'token',
              },
              {
                token: 'token',
              },
            ]),
          );
        });

        spyLogError = jest
          .spyOn(loggerService, 'error')
          .mockImplementation(() => {});

        try {
          await repository.loadDataFromFile();
        } catch (e) {
          exceptionThrown = e;
        }
      });

      afterEach(async function () {
        spyLogError?.mockClear().mockRestore();
      });

      it('should throw an exception', async function () {
        expect(exceptionThrown).toBeDefined();
        expect(exceptionThrown.message).toBe(
          `invalid token record in ${tokensFilePath}`,
        );
      });

      it('should log error message', async function () {
        expect(spyLogError).toHaveBeenCalledWith(
          expect.stringMatching(/^invalid token data record: {/),
        );
      });
    });

    describe('when called with tokens file data not containing token field', function () {
      let exceptionThrown: Error;
      let tokensFilePath: string;
      let spyLogError: jest.SpyInstance;

      beforeEach(async function () {
        tokensFilePath = resolve('tokens.json');

        spyReadFile = jest.spyOn(mockFs, 'readFile').mockImplementation(() => {
          return Promise.resolve(
            JSON.stringify([
              {
                did: 'did:example:123456789abcdefghi',
                token: 'token',
              },
              {
                did: 'did:example:123456789abcdefghi',
              },
            ]),
          );
        });

        spyLogError = jest
          .spyOn(loggerService, 'error')
          .mockImplementation(() => {});

        try {
          await repository.loadDataFromFile();
        } catch (e) {
          exceptionThrown = e;
        }
      });

      afterEach(async function () {
        spyLogError?.mockClear().mockRestore();
      });

      it('should throw an exception', async function () {
        expect(exceptionThrown).toBeDefined();
        expect(exceptionThrown.message).toBe(
          `invalid token record in ${tokensFilePath}`,
        );
      });

      it('should log error message', async function () {
        expect(spyLogError).toHaveBeenCalledWith(
          expect.stringMatching(/^invalid token data record: {/),
        );
      });
    });
  });

  describe('onModuleInit()', function () {
    it('should be defined', async function () {
      expect(repository.onModuleInit).toBeDefined();
    });

    describe('when called', function () {
      it('should call loadTokens() method', async function () {
        const spy = jest
          .spyOn(repository, 'loadDataFromFile')
          .mockImplementation(async () => {});

        await repository.onModuleInit();

        expect(spy).toHaveBeenCalled();

        spy.mockClear().mockRestore();
      });
    });
  });

  describe('getToken()', function () {
    it('should be defined', async function () {
      expect(repository.getToken).toBeDefined();
    });

    describe('when called for existing token', function () {
      let spy: jest.SpyInstance;

      beforeEach(async function () {
        spy = jest.spyOn(mockFs, 'readFile').mockImplementation(() => {
          return Promise.resolve(
            JSON.stringify([
              {
                did: 'did:example:123456789abcdefghi',
                token: 'token',
              },
            ]),
          );
        });

        await repository.onModuleInit();
      });

      afterEach(async function () {
        spy?.mockClear().mockRestore();
      });

      it('should return the token', async function () {
        expect(
          await repository.getToken('did:example:123456789abcdefghi'),
        ).toBe('token');
      });
    });

    describe('when called for non-existing token', function () {
      let spyLogError: jest.SpyInstance;
      let result: string;

      beforeEach(async function () {
        spyLogError = jest
          .spyOn(loggerService, 'warn')
          .mockImplementation(() => {});

        result = repository.getToken('did:example:000000000000000000');
      });

      afterEach(async function () {
        spyLogError?.mockClear().mockRestore();
      });

      it('should return null', async function () {
        expect(result).toBeNull();
      });

      it('should log warn message', async function () {
        expect(spyLogError).toHaveBeenCalledWith(
          'no token found for did: did:example:000000000000000000',
        );
      });
    });
  });
});
