// NOTE: the two assignments below must run *before* `AppModule` is imported.
//
// `AppModule` (see `../src/modules/app/app.module.ts`) calls
// `ConfigModule.forRoot()` at module-load time, and `@nestjs/config`
// resolves each variable's final value by merging `process.env` on top of
// whatever `dotenv` loaded from a `.env` file - `process.env` always wins,
// and dotenv never overwrites a key that is already set. Setting these
// here, ahead of the `import` below, is therefore the only reliable way to
// control what `ConfigService` resolves for this test run, regardless of
// what a local `.env`/`test/.env` contains:
//
// - `NODE_ENV=production` disables the `pino-pretty` transport that
//   `app.module.ts` configures for any non-production environment. That
//   transport ships log lines off to a worker thread, which this suite has
//   no simple way to observe. With no transport configured, pino falls
//   back to writing directly to `process.stdout` - but only if
//   `process.stdout.write` has already been monkey-patched by the time the
//   pino instance is created (pino's `hasBeenTampered` check, see
//   `pino/lib/tools.js`). That's why the `jest.spyOn` below is installed
//   before the Nest app (and therefore the pino-http middleware) is built.
// - `LOG_LEVEL=info` guarantees the request/response log lines this test
//   inspects are actually emitted. `test/.env.example` sets
//   `LOG_LEVEL=error`, which would otherwise silently swallow every line
//   this test depends on and make its assertions vacuous.
process.env.NODE_ENV = 'production';
process.env.LOG_LEVEL = 'info';

import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { Server } from 'http';
import { randomUUID } from 'crypto';
import { sign } from 'jsonwebtoken';
import { RedisMemoryServer } from 'redis-memory-server';
import { AppModule } from '../src/modules/app';

describe('Sensitive header redaction in logs (e2e)', () => {
  let app: INestApplication;
  let appHttpServer: Server;
  let redisServer: RedisMemoryServer;
  let writeSpy: jest.SpyInstance;
  let logChunks: string[];

  beforeAll(async () => {
    redisServer = new RedisMemoryServer({
      instance: {
        port: parseInt(process.env.REDIS_PORT) || 61379,
      },
      autoStart: true,
    });

    await redisServer.ensureInstance();

    // Must be installed before `app.init()` - see the comment at the top of
    // this file for why. Everything pino-http writes for the lifetime of
    // this test file ends up here instead of the real stdout.
    logChunks = [];
    writeSpy = jest
      .spyOn(process.stdout, 'write')
      .mockImplementation((chunk: string | Uint8Array): boolean => {
        logChunks.push(chunk.toString());
        return true;
      });

    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();

    appHttpServer = app.getHttpServer();
  }, 60000);

  afterAll(async () => {
    writeSpy.mockRestore();
    await app.close();
    await redisServer.stop();
  });

  describe('when a request carries an Authorization bearer token and a Cookie header', () => {
    // Real, well-formed (but throwaway-signed) JWTs, each with a random
    // claim so the exact string is guaranteed unique to this test run and
    // can't accidentally match unrelated log content. The endpoint below
    // does not need to authenticate successfully for this to be meaningful:
    // pino-http logs the raw req/res headers on every request regardless of
    // the outcome, which is exactly the plaintext leak that the `redact`
    // config in `app.module.ts` fixes.
    const fakeAccessToken = sign(
      { sub: 'e2e-redaction-test-header', nonce: randomUUID() },
      'e2e-test-throwaway-secret',
    );
    const fakeCookieValue = sign(
      { sub: 'e2e-redaction-test-cookie', nonce: randomUUID() },
      'e2e-test-throwaway-secret',
    );

    beforeAll(async () => {
      logChunks.length = 0;

      await request(appHttpServer)
        .get('/auth/token-introspection')
        .set('Authorization', `Bearer ${fakeAccessToken}`)
        .set('Cookie', `token=${fakeCookieValue}`);
    });

    it('logs at least one line for the request', () => {
      expect(logChunks.length).toBeGreaterThan(0);
    });

    it('does not leak the raw bearer token into the logs', () => {
      expect(logChunks.join('')).not.toContain(fakeAccessToken);
    });

    it('does not leak the raw cookie value into the logs', () => {
      expect(logChunks.join('')).not.toContain(fakeCookieValue);
    });

    it('redacts the Authorization/Cookie header values with the configured censor', () => {
      expect(logChunks.join('')).toContain('[Redacted]');
    });
  });
});
