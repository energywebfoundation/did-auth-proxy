import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { Response } from 'supertest';
import { AppModule } from '../src/app.module';
import { Server } from 'http';
import { decode, JwtPayload, sign } from 'jsonwebtoken';
import { IAccessTokenPayload } from '../src/auth/auth.interface';
import { ConfigService } from '@nestjs/config';
import { LoginResponseDto } from '../src/auth/dto/login-response.dto';
import { setTimeout } from 'timers/promises';
import { parse as parseCookies } from 'set-cookie-parser';

describe('AppController (e2e)', () => {
  const identityToken = process.env.IDENTITY_TOKEN;
  let app: INestApplication;
  let appHttpServer: Server;
  let configService: ConfigService;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();

    configService = app.get<ConfigService>(ConfigService);

    appHttpServer = app.getHttpServer();
  });

  afterAll(async function () {
    await app.close();
  });

  describe('/auth (GET)', function () {
    let response: Response;

    beforeEach(async function () {
      response = await request(appHttpServer).get('/auth');
    });

    it('should respond with 200 status code', async function () {
      expect(response.statusCode).toBe(200);
    });
  });

  describe('/auth/login (POST)', function () {
    let response: Response;

    describe('when called with valid identity token', function () {
      beforeAll(async function () {
        response = await request(appHttpServer).post('/auth/login').send({
          identityToken,
        });
      }, 15000);

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

        expect(cookies['Auth']).toBeDefined();

        const authCookie = cookies['Auth'];

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
          expect(tokenDecoded.roles).toEqual(
            expect.arrayContaining(
              configService.get<string>('ACCEPTED_ROLES').split(','),
            ),
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
    });

    describe('when called without access token', function () {
      let response: Response;
      beforeAll(async function () {
        response = await request(appHttpServer).post('/auth/refresh-token');
      });

      it('should respond with 403 status code', async function () {
        expect(response.statusCode).toBe(403);
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
