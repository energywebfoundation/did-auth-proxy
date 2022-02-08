import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { ConfigService } from '@nestjs/config';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { RefreshTokenRepository } from './refresh-token.repository';
import { verify } from 'jsonwebtoken';

describe('AuthService', () => {
  let service: AuthService;
  let jwtService: JwtService;
  let configService: ConfigService;
  let refreshTokenRepository: RefreshTokenRepository;

  const mockConfigService = {
    get(key: string) {
      return {
        JWT_ACCESS_TTL: 1,
        JWT_REFRESH_TTL: 5,
      }[key];
    },
  };

  const mockRefreshTokenRepository = {
    // eslint-disable-next-line @typescript-eslint/no-empty-function
    saveToken() {},
  };

  const payload = {
    did: 'did:eth:0x82FcB31385EaBe261E4e6003b9F2Cb2af34e2654',
    roles: [
      'role1.roles.app-test2.apps.artur.iam.ewc',
      'role2.roles.app-test2.apps.artur.iam.ewc',
    ],
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      imports: [
        JwtModule.register({
          secretOrPrivateKey: 'secretKeyValid',
        }),
      ],
      providers: [
        AuthService,
        { provide: ConfigService, useValue: mockConfigService },
        {
          provide: RefreshTokenRepository,
          useValue: mockRefreshTokenRepository,
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    configService = module.get<ConfigService>(ConfigService);
    jwtService = module.get<JwtService>(JwtService);
    refreshTokenRepository = module.get<RefreshTokenRepository>(
      RefreshTokenRepository,
    );
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('generateAccessToken()', function () {
    it('should sign token with jwtService', async function () {
      const spy = jest.spyOn(jwtService, 'sign');

      const token = await service.generateAccessToken(payload);

      const tokenPayload = verify(token, 'secretKeyValid') as Record<
        string,
        any
      >;

      expect(spy).toBeCalledWith(
        { id: tokenPayload.id, ...payload },
        { expiresIn: configService.get('JWT_ACCESS_TTL') },
      );

      spy.mockClear();
    });
  });

  describe('generateRefreshToken()', function () {
    it('should sign token with jwtService', async function () {
      const spy = jest.spyOn(jwtService, 'sign');

      const token = await service.generateRefreshToken(payload);

      const tokenPayload = verify(token, 'secretKeyValid') as Record<
        string,
        any
      >;

      expect(spy).toBeCalledWith(
        { id: tokenPayload.id, ...payload },
        { expiresIn: configService.get('JWT_REFRESH_TTL') },
      );

      spy.mockClear();
    });

    it('should save generated token in a repository', async function () {
      const spy = jest.spyOn(refreshTokenRepository, 'saveToken');

      const token = await service.generateRefreshToken(payload);

      expect(spy).toBeCalledWith(token);

      spy.mockClear();
    });
  });
});
