import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { Response } from 'supertest';
import { AppModule } from '../src/modules/app';
import { Server } from 'http';
import { decode, JwtPayload, sign } from 'jsonwebtoken';
import { IAccessTokenPayload, LoginResponseDto } from '../src/modules/auth';
import { ConfigService } from '@nestjs/config';
import { setTimeout } from 'timers/promises';
import { parse as parseCookies } from 'set-cookie-parser';

import { RedisMemoryServer } from 'redis-memory-server';
import { SiweVerifyRequestDto } from '../src/modules/auth/dto/siwe-verify-request.dto';
import { providers, Wallet } from 'ethers';
import { SiweMessage } from 'siwe';

if (!process.env.IDENTITY_TOKEN) {
  console.log('IDENTITY_TOKEN env var not set');
  process.exit(1);
}

describe('AppController (e2e)', () => {
  const identityToken = process.env.IDENTITY_TOKEN;
  let app: INestApplication;
  let appHttpServer: Server;
  let configService: ConfigService;
  let redisServer: RedisMemoryServer;

  beforeAll(async () => {
    redisServer = new RedisMemoryServer({
      instance: {
        port: parseInt(process.env.REDIS_PORT) | 61379,
      },
      autoStart: true,
    });

    await redisServer.ensureInstance();

    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();

    configService = app.get<ConfigService>(ConfigService);

    appHttpServer = app.getHttpServer();

    await setTimeout(3000); // delaying to get rid of errors caused by passsport-did-auth
  }, 15000);

  afterAll(async function () {
    await app.close();
    await redisServer.stop();
  });

  describe('/healthcheck/operational', function () {
    let response: Response;

    beforeEach(async function () {
      response = await request(appHttpServer).get('/healthcheck/operational');
    });

    it('should respond with 200', async function () {
      expect(response.statusCode).toBe(200);
    });

    it('should report all checks OK', async function () {
      const { body } = response;

      expect(body.status).toBe('ok');
      expect(Object.values(body.error)).toHaveLength(0);
      expect(Object.keys(body.info).sort()).toEqual(
        ['rpc', 'redis', 'ipfs'].sort(),
      );
      expect(Object.values(body.info)).toHaveLength(3);

      Object.values(body.info).forEach((check: Record<string, string>) =>
        expect(check.status).toBe('up'),
      );
    });
  });

  describe('/auth/login (POST)', function () {
    let response: Response;

    describe('when called with valid identity token', function () {
      beforeAll(async function () {
        response = await request(appHttpServer).post('/auth/login').send({
          identityToken,
        });
      }, 30000);

      it('should respond with 200 status code', async function () {
        expect(response.statusCode).toBe(201);
      });

      it('should respond with correct body fields', async function () {
        expect(response.body).toEqual(
          expect.objectContaining({
            access_token: expect.any(String),
            refresh_token: expect.any(String),
            type: 'Bearer',
            expires_in: expect.any(Number),
          }),
        );
      });

      it('should respond with Auth cookie set correctly', async function () {
        expect(response.headers['set-cookie']).toBeDefined();

        const cookies = parseCookies(response.headers['set-cookie'], {
          map: true,
        });

        expect(cookies['token']).toBeDefined();

        const authCookie = cookies['token'];

        expect(authCookie.httpOnly).toBe(true);
        expect(authCookie.secure).toBe(true);
        expect(authCookie.sameSite).toBe('Strict');
      });

      describe('should respond with access token that', function () {
        let tokenDecoded: IAccessTokenPayload;

        beforeAll(async function () {
          tokenDecoded = decode(
            response.body.access_token,
          ) as IAccessTokenPayload;
        });

        it('should be valid', async function () {
          expect(tokenDecoded).toBeTruthy();
        });

        it('should contain expected fields', async function () {
          expect(tokenDecoded).toEqual(
            expect.objectContaining({
              id: expect.any(String),
              did: expect.any(String),
              iat: expect.any(Number),
              exp: expect.any(Number),
            }),
          );
        });

        it('should have correct expiration time', async function () {
          expect(tokenDecoded.exp - tokenDecoded.iat).toEqual(
            configService.get<number>('JWT_ACCESS_TTL'),
          );
        });

        it('should have correct roles', async function () {
          const expectedRoles = configService.get<string>('ACCEPTED_ROLES')
            ? configService.get<string>('ACCEPTED_ROLES').split(',')
            : [];

          expect(tokenDecoded.roles).toEqual(
            expect.arrayContaining(expectedRoles),
          );
        });

        it('should have did field matching identity token', async function () {
          expect(tokenDecoded.did).toEqual(
            (decode(identityToken) as JwtPayload).iss,
          );
        });
      });
    });
    //TODO: implement tests for malformed identity token once passport-did-auth is fixed (https://github.com/energywebfoundation/passport-did-auth/issues/294)
  });

  describe('/auth/login/siwe/initiate (GET) when called', function () {
    let response: Response;

    beforeAll(async function () {
      response = await request(appHttpServer).post('/auth/login/siwe/initiate');
    });

    it('should respond with 200 status code', async function () {
      expect(response.statusCode).toBe(201);
    });

    it('should respond with a nonce', async function () {
      expect(response.body).toEqual(
        expect.objectContaining({ nonce: expect.any(String) }),
      );
    });
  });

  describe('/auth/login/siwe/verify (POST)', function () {
    let response: Response;
    let provider: providers.Provider;
    let wallet: Wallet;

    describe('when called with no request body', function () {
      beforeEach(async function () {
        response = await request(appHttpServer).post('/auth/login/siwe/verify');
      });

      it('should respond with 401 status code', async function () {
        expect(response.statusCode).toBe(401);
      });

      it('should respond with no access token', async function () {
        expect(response.body).toEqual(
          expect.not.objectContaining({
            token: expect.any(String),
          }),
        );
      });

      it('should respond with no refresh token', async function () {
        expect(response.body).toEqual(
          expect.not.objectContaining({
            accessToken: expect.any(String),
          }),
        );
      });
    });

    describe('when called with an invalid message', function () {
      beforeEach(async function () {
        response = await request(appHttpServer)
          .post('/auth/login/siwe/verify')
          .send({
            message: 'invalid message',
            signature: 'invalid signature',
          } as SiweVerifyRequestDto);
      });

      it('should respond with 400 status code', async function () {
        expect(response.statusCode).toBe(400);
      });

      it('should respond with no access token', async function () {
        expect(response.body).toEqual(
          expect.not.objectContaining({
            token: expect.any(String),
          }),
        );
      });

      it('should respond with no refresh token', async function () {
        expect(response.body).toEqual(
          expect.not.objectContaining({
            accessToken: expect.any(String),
          }),
        );
      });

      it('should respond with error description', async function () {
        expect(response.body).toEqual(
          expect.objectContaining({
            statusCode: 400,
            message: expect.stringMatching(
              /Message .* can not be parsed to SiweMessage/,
            ),
            error: 'Bad Request',
          }),
        );
      });
    });

    describe('when called with a valid message and signature', function () {
      let uri: string;

      beforeAll(async () => {
        provider = new providers.JsonRpcProvider(process.env.RPC_URL);
        wallet = Wallet.createRandom().connect(provider);
        uri = new URL(
          '/auth/login/siwe/verify',
          new URL(configService.get<string>('SELF_BASE_URL')).origin,
        ).href;
      });

      describe('with valid nonce and uri', function () {
        beforeEach(async function () {
          const nonce = (
            await request(appHttpServer).post('/auth/login/siwe/initiate')
          ).body?.nonce;

          const message = new SiweMessage({
            domain: 'localhost:3000',
            address: wallet.address,
            uri,
            version: '1',
            chainId: (await wallet.provider.getNetwork()).chainId,
            nonce,
          }).prepareMessage();

          const signature = await wallet.signMessage(message);

          const payload: SiweVerifyRequestDto = {
            message,
            signature,
          };

          response = await request(appHttpServer)
            .post('/auth/login/siwe/verify')
            .send(payload);
        });

        it('should respond with 201 status code', async function () {
          expect(response.statusCode).toBe(201);
        });

        it('should respond with access and refresh tokens', async function () {
          expect(response.body).toEqual(
            expect.objectContaining({
              access_token: expect.any(String),
              refresh_token: expect.any(String),
            }),
          );
        });
      });

      describe('with valid nonce and invalid uri', function () {
        beforeEach(async function () {
          const nonce = (
            await request(appHttpServer).get('/auth/login/siwe/initiate')
          ).body?.nonce;

          const message = new SiweMessage({
            domain: 'localhost:3000',
            address: wallet.address,
            uri: 'https://some.other.site/auth/login/siwe/verify',
            version: '1',
            chainId: (await wallet.provider.getNetwork()).chainId,
            nonce,
          }).prepareMessage();

          const signature = await wallet.signMessage(message);

          const payload: SiweVerifyRequestDto = {
            message,
            signature,
          };

          response = await request(appHttpServer)
            .post('/auth/login/siwe/verify')
            .send(payload);
        });

        it('should respond with 401 status code', async function () {
          expect(response.statusCode).toBe(401);
        });

        it('should respond with no access token', async function () {
          expect(response.body).toEqual(
            expect.not.objectContaining({
              token: expect.any(String),
            }),
          );
        });

        it('should respond with no refresh token', async function () {
          expect(response.body).toEqual(
            expect.not.objectContaining({
              accessToken: expect.any(String),
            }),
          );
        });

        it('should respond with error description', async function () {
          expect(response.body).toEqual(
            expect.objectContaining({
              statusCode: 401,
              message: 'uri in siwe message payload is incorrect',
              error: 'Unauthorized',
            }),
          );
        });
      });

      describe('with invalid nonce and valid uri', function () {
        beforeEach(async function () {
          const message = new SiweMessage({
            domain: 'localhost:3000',
            address: wallet.address,
            uri,
            version: '1',
            chainId: (await wallet.provider.getNetwork()).chainId,
            nonce: 'invalidNonce',
          }).prepareMessage();

          const signature = await wallet.signMessage(message);

          const payload: SiweVerifyRequestDto = {
            message,
            signature,
          };

          response = await request(appHttpServer)
            .post('/auth/login/siwe/verify')
            .send(payload);
        });

        it('should respond with 401 status code', async function () {
          expect(response.statusCode).toBe(401);
        });

        it('should respond with no access token', async function () {
          expect(response.body).toEqual(
            expect.not.objectContaining({
              token: expect.any(String),
            }),
          );
        });

        it('should respond with no refresh token', async function () {
          expect(response.body).toEqual(
            expect.not.objectContaining({
              accessToken: expect.any(String),
            }),
          );
        });

        it('should respond with error description', async function () {
          expect(response.body).toEqual(
            expect.objectContaining({
              statusCode: 401,
              message: 'invalid nonce: invalidNonce',
              error: 'Unauthorized',
            }),
          );
        });
      });
    });
  });

  describe('/auth/token-introspection (GET)', function () {
    let accessToken: string;
    let response: Response;

    describe('when called with a valid access token', function () {
      beforeAll(async function () {
        ({ accessToken } = await logIn(appHttpServer, identityToken));
      }, 15000);

      beforeEach(async function () {
        response = await request(appHttpServer)
          .get('/auth/token-introspection')
          .set({
            Authorization: `Bearer ${accessToken}`,
          });
      });

      it('should respond with 200 status code', async function () {
        expect(response.statusCode).toBe(200);
      });
    });

    describe('when called without an access token', function () {
      beforeEach(async function () {
        response = await request(appHttpServer).get(
          '/auth/token-introspection',
        );
      });

      it('should respond with 401 status code', async function () {
        expect(response.statusCode).toBe(401);
      });
    });

    describe('when called with malformad access token', function () {
      beforeEach(async function () {
        response = await request(appHttpServer)
          .get('/auth/token-introspection')
          .set({
            Authorization: `Bearer malformedaccesstoken`,
          });
      });

      it('should respond with 401 status code', async function () {
        expect(response.statusCode).toBe(401);
      });
    });

    describe('when called with malformed Authorization header', function () {
      beforeEach(async function () {
        response = await request(appHttpServer)
          .get('/auth/token-introspection')
          .set({
            Authorization: `malformedheadervalue`,
          });
      });

      it('should respond with 401 status code', async function () {
        expect(response.statusCode).toBe(401);
      });
    });

    describe('when called with token with invalid signature', function () {
      let invalidAccessToken: string;

      beforeAll(async function () {
        const { accessToken } = await logIn(appHttpServer, identityToken);
        const { id, did, roles } = decode(accessToken) as IAccessTokenPayload;
        invalidAccessToken = sign({ id, did, roles }, 'invalid secret');
      }, 15000);

      beforeEach(async function () {
        response = await request(appHttpServer)
          .get('/auth/token-introspection')
          .set({
            Authorization: `Bearer ${invalidAccessToken}`,
          });
      });

      it('should respond with 401 status code', async function () {
        expect(response.statusCode).toBe(401);
      });
    });
  });

  describe('/auth/refresh-token (POST)', function () {
    describe('when called with a valid refresh token', function () {
      let accessToken: string;
      let accessTokenDecoded: IAccessTokenPayload;
      let refreshToken: string;
      let response: Response;
      beforeAll(async function () {
        ({ accessToken, refreshToken } = await logIn(
          appHttpServer,
          identityToken,
        ));

        accessTokenDecoded = decode(accessToken) as IAccessTokenPayload;

        await setTimeout(1000);

        response = await request(appHttpServer)
          .post('/auth/refresh-token')
          .send({
            refreshToken,
          });
      }, 15000);

      it('should respond with 201 status code', async function () {
        expect(response.statusCode).toBe(201);
      });

      it('should respond with correct body fields', async function () {
        expect(response.body).toEqual(
          expect.objectContaining({
            access_token: expect.any(String),
            refresh_token: expect.any(String),
            type: 'Bearer',
            expires_in: expect.any(Number),
          }),
        );
      });

      it('should respond with a new access token', async function () {
        const newAccessToken = response.body.access_token;
        expect(newAccessToken).not.toEqual(accessToken);

        const newAccessTokenDecoded = decode(
          newAccessToken,
        ) as IAccessTokenPayload;
        expect(newAccessTokenDecoded.iat).toBeGreaterThan(
          accessTokenDecoded.iat,
        );

        expect(newAccessTokenDecoded.id).not.toEqual(accessTokenDecoded.id);
        expect(newAccessTokenDecoded.did).toEqual(accessTokenDecoded.did);
        expect(newAccessTokenDecoded.roles.sort()).toEqual(
          accessTokenDecoded.roles.sort(),
        );
      });

      it('should respond with a new refresh token', async function () {
        const newRefreshToken = response.body.refresh_token;
        expect(newRefreshToken).not.toEqual(refreshToken);

        const newRefreshTokenDecoded = decode(
          newRefreshToken,
        ) as IAccessTokenPayload;
        expect(newRefreshTokenDecoded.iat).toBeGreaterThan(
          accessTokenDecoded.iat,
        );

        expect(newRefreshTokenDecoded.id).not.toEqual(accessTokenDecoded.id);
        expect(newRefreshTokenDecoded.did).toEqual(accessTokenDecoded.did);
        expect(newRefreshTokenDecoded.roles.sort()).toEqual(
          accessTokenDecoded.roles.sort(),
        );
      });

      it('should respond with Auth cookie set correctly', async function () {
        expect(response.headers['set-cookie']).toBeDefined();

        const cookies = parseCookies(response.headers['set-cookie'], {
          map: true,
        });

        expect(cookies['token']).toBeDefined();

        const authCookie = cookies['token'];

        expect(authCookie.value).toBe(response.body.access_token);

        expect(authCookie.httpOnly).toBe(true);
        expect(authCookie.secure).toBe(true);
        expect(authCookie.sameSite).toBe('Strict');
      });
    });

    describe('when called without access token', function () {
      let response: Response;
      beforeAll(async function () {
        response = await request(appHttpServer).post('/auth/refresh-token');
      });

      it('should respond with 401 status code', async function () {
        expect(response.statusCode).toBe(401);
      });
    });

    describe('when called with token with invalid signature', function () {
      let response: Response;

      beforeEach(async function () {
        const { refreshToken: validRefreshToken } = await logIn(
          appHttpServer,
          identityToken,
        );

        const { id, did, roles } = decode(
          validRefreshToken,
        ) as IAccessTokenPayload;

        response = await request(appHttpServer)
          .post('/auth/refresh-token')
          .send({
            refreshToken: sign({ id, did, roles }, 'invalid secret'),
          });
      }, 15000);

      it('should respond with 403 status code', async function () {
        expect(response.statusCode).toBe(403);
      });
    });

    describe('when called with malformed refresh token', function () {
      let response: Response;

      beforeAll(async function () {
        response = await request(appHttpServer)
          .post('/auth/refresh-token')
          .send({
            refreshToken: 'malformed token',
          });
      });

      it('should respond with 403 status code', async function () {
        expect(response.statusCode).toBe(403);
      });

      it('should respond with body containing no tokens', async function () {
        expect(response.body).not.toEqual(
          expect.objectContaining(['access_token', 'refresh_token']),
        );
      });
    });
  });

  describe('/auth/refresh_token (GET)', function () {
    let response: Response;

    describe('when called with a valid refresh token', function () {
      let refreshToken: string;

      beforeEach(async function () {
        const start = Date.now();
        ({ refreshToken } = await logIn(appHttpServer, identityToken));

        console.log(`logged in in ${Date.now() - start}ms`);

        response = await request(appHttpServer).get(
          `/auth/refresh_token?refresh_token=${refreshToken}`,
        );
      });

      it('should respond with 200 status code', async function () {
        expect(response.statusCode).toBe(200);
      });

      it('should respond with a body containing access and refresh tokens', async function () {
        expect(response.body).toEqual(
          expect.objectContaining({
            access_token: expect.any(String),
            refresh_token: expect.any(String),
          }),
        );
      });
    });

    describe('when called with an invalid refresh token', function () {
      beforeEach(async function () {
        response = await request(appHttpServer).get(
          `/auth/refresh_token?refresh_token=invalid-token`,
        );
      });

      it('should respond with 403 status code', async function () {
        expect(response.statusCode).toBe(403);
      });

      it('should respond with a body containing no access nor refresh tokens', async function () {
        expect(response.body).toEqual(
          expect.not.objectContaining({
            access_token: expect.any(String),
          }),
        );

        expect(response.body).toEqual(
          expect.not.objectContaining({
            refresh_token: expect.any(String),
          }),
        );
      });
    });

    describe('when called with no refresh token', function () {
      beforeEach(async function () {
        response = await request(appHttpServer).get(`/auth/refresh_token`);
      });

      it('should respond with 401 status code', async function () {
        expect(response.statusCode).toBe(401);
      });

      it('should respond with a body containing no access nor refresh tokens', async function () {
        expect(response.body).toEqual(
          expect.not.objectContaining({
            access_token: expect.any(String),
          }),
        );

        expect(response.body).toEqual(
          expect.not.objectContaining({
            refresh_token: expect.any(String),
          }),
        );
      });
    });

    describe('when called with empty refresh token', function () {
      beforeEach(async function () {
        response = await request(appHttpServer).get(
          `/auth/refresh_token?refresh_token=`,
        );
      });

      it('should respond with 401 status code', async function () {
        expect(response.statusCode).toBe(401);
      });

      it('should respond with a body containing no access nor refresh tokens', async function () {
        expect(response.body).toEqual(
          expect.not.objectContaining({
            access_token: expect.any(String),
          }),
        );

        expect(response.body).toEqual(
          expect.not.objectContaining({
            refresh_token: expect.any(String),
          }),
        );
      });
    });
  });

  describe('/auth/logout', function () {
    describe('whan called with a valid refresh token', function () {
      let refreshToken: string;
      let response: Response;

      beforeAll(async function () {
        ({ refreshToken } = await logIn(appHttpServer, identityToken));

        response = await request(appHttpServer)
          .post('/auth/refresh-token')
          .send({
            refreshToken,
          });
      }, 15000);

      it('should respond with 201 status code', async function () {
        expect(response.statusCode).toBe(201);
      });
    });

    describe('when called without a refresh token', function () {
      let response: Response;

      beforeAll(async function () {
        response = await request(appHttpServer)
          .post('/auth/refresh-token')
          .send({});
      });

      it('should respond with 401 status code', async function () {
        expect(response.statusCode).toBe(401);
      });
    });

    describe('when called with invalid refresh token', function () {
      let response: Response;

      beforeAll(async function () {
        response = await request(appHttpServer)
          .post('/auth/refresh-token')
          .send({
            refreshToken: 'invalid',
          });
      });

      it('should respond with 403 status code', async function () {
        expect(response.statusCode).toBe(403);
      });
    });
  });
});

async function logIn(
  httpServer: Server,
  identityToken: string,
): Promise<{ accessToken: string; refreshToken: string }> {
  const body = (
    await request(httpServer).post('/auth/login').send({ identityToken })
  ).body as LoginResponseDto;

  const { access_token: accessToken, refresh_token: refreshToken } = body;

  return { accessToken, refreshToken };
}
