import {
  BadRequestException,
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { verifyCredential } from 'didkit-wasm-node';
import { providers as EthersProviders } from 'ethers';
import { Request } from 'express';
import { JwtPayload } from 'jsonwebtoken';
import { PinoLogger } from 'nestjs-pino';
import {
  DomainReader,
  ethrReg,
  InvalidSiweMessage,
  LoginStrategy,
  Methods,
  ResolverContractType,
  RoleCredentialResolver,
  RoleIssuerResolver,
  RoleRevokerResolver,
} from 'passport-did-auth';
import { CACHED_JSONRPC } from '../auth.const';
import { AuthService } from '../auth.service';

@Injectable()
export class AuthStrategy extends PassportStrategy(LoginStrategy, 'login') {
  constructor(
    private readonly logger: PinoLogger,
    private readonly configService: ConfigService,
    private readonly authService: AuthService,
    @Inject(CACHED_JSONRPC)
    private readonly _provider: EthersProviders.JsonRpcProvider & {
      clearCache: () => void;
    },
  ) {
    const provider = _provider;
    const domainReader = new DomainReader({
      ensRegistryAddress: configService.get<string>('ENS_REGISTRY_ADDRESS'),
      provider,
    });

    domainReader.addKnownResolver({
      chainId: configService.get<number>('CHAIN_ID'),
      address: configService.get<string>('ENS_RESOLVER_ADDRESS'),
      type: ResolverContractType.RoleDefinitionResolver_v2,
    });
    const cacheServerUrl = process.env.CACHE_SERVER_URL;
    const privateKey = process.env.CACHE_SERVER_LOGIN_PRVKEY;

    super(
      {
        jwtSecret: process.env.JWT_SECRET,
        jwtSignOptions: { algorithm: 'HS256' },
        rpcUrl: process.env.RPC_URL,
        cacheServerUrl: process.env.CACHE_SERVER_URL,
        acceptedRoles: parseAcceptedRoles(process.env.ACCEPTED_ROLES),
        privateKey: process.env.CACHE_SERVER_LOGIN_PRVKEY,
        didContractAddress: process.env.DID_REGISTRY_ADDRESS,
        ensRegistryAddress: process.env.ENS_REGISTRY_ADDRESS,
        includeAllRoles: configService.get<boolean>('INCLUDE_ALL_ROLES'),
        siweMessageUri: new URL(
          '/auth/login/siwe/verify',
          new URL(configService.get<string>('SELF_BASE_URL')).origin,
        ).href,
      },
      new RoleIssuerResolver(domainReader),
      new RoleRevokerResolver(domainReader),
      new RoleCredentialResolver(
        provider,
        {
          abi: ethrReg.abi,
          address: configService.get<string>('DID_REGISTRY_ADDRESS'),
          method: Methods.Erc1056,
        },
        privateKey,
        cacheServerUrl,
      ),
      verifyCredential,
    );

    this.logger.setContext(AuthStrategy.name);

    this.logger.info(
      `accepted roles: ${parseAcceptedRoles(
        process.env.ACCEPTED_ROLES,
      ).join()}`,
    );
  }

  authenticate(req: Request) {
    try {
      super.authenticate(req);
    } catch (err) {
      if (err instanceof InvalidSiweMessage) {
        throw new BadRequestException(err.message);
      }

      throw err;
    }
  }

  async validate(
    token: string,
    payload: unknown,
    done: (err?: Error, user?: unknown, info?: unknown) => void,
  ): Promise<void> {
    if (isJwtPayload(payload)) {
      try {
        await this.authService.identityTokenValidate(
          (payload as JwtPayload).iat,
          (payload as JwtPayload).exp,
        );
      } catch (error) {
        done(error);
        return;
      }
    }

    return super.validate(
      token,
      payload,
      (err?: Error, user?: unknown, info?: unknown) => {
        // this._provider.clearCache();
        if (
          err?.message === 'Signature does not match address of the message.' ||
          err?.message === 'uri in siwe message payload is incorrect'
        ) {
          done(new UnauthorizedException(err.message), user, info);
        } else {
          if (!user && info) {
            done(new UnauthorizedException(info), user, info);
          } else {
            done(err, user, info);
          }
        }
      },
    );
  }
}

function parseAcceptedRoles(ACCEPTED_ROLES: string): string[] {
  return ACCEPTED_ROLES ? ACCEPTED_ROLES.split(',') : [];
}

function isJwtPayload(payload: unknown): payload is JwtPayload {
  return (
    typeof payload === 'object' &&
    payload !== null &&
    'iat' in payload &&
    'exp' in payload
  );
}
