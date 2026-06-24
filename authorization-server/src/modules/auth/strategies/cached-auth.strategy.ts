import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { verifyCredential } from 'didkit-wasm-node';
import { Request } from 'express';
import { PinoLogger } from 'nestjs-pino';
import {
  chainConfigs,
  DidStore,
  InvalidSiweMessage,
  LoginStrategy,
  Methods,
} from 'passport-did-auth';
import { CacheServerClient } from 'passport-did-auth/dist/lib/cacheServerClient';
import { IRoleDefinitionV2 } from '@energyweb/credential-governance';
import {
  CachedCredentialResolver,
  CachedIssuerResolver,
  CachedRevokerResolver,
} from './cached-resolvers';

@Injectable()
export class CachedAuthStrategy extends PassportStrategy(
  LoginStrategy,
  'login',
) {
  constructor(
    private readonly logger: PinoLogger,
    private readonly configService: ConfigService,
  ) {
    const cacheServerUrl = process.env.CACHE_SERVER_URL;
    const privateKey = process.env.CACHE_SERVER_LOGIN_PRVKEY;
    const chainId = configService.get<number>('CHAIN_ID');

    const dummyProvider = {
      _isProvider: true,
      getNetwork: async () => ({ chainId }),
      getBlockNumber: async () => 0,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any;

    const cacheServerClient = new CacheServerClient({
      url: cacheServerUrl,
      privateKey: privateKey,
      provider: dummyProvider,
    });
    cacheServerClient.login();

    const didStore = new DidStore({
      baseURL: cacheServerUrl,
      didPrefix: `did:${Methods.Erc1056}:${chainConfigs()[chainId].chainName}`,
      privateKey: privateKey,
    });

    const cachedIssuerResolver = new CachedIssuerResolver(cacheServerClient);
    const cachedRevokerResolver = new CachedRevokerResolver(cacheServerClient);
    const cachedCredentialResolver = new CachedCredentialResolver(
      cacheServerClient,
      didStore,
    );

    super(
      {
        jwtSecret: process.env.JWT_SECRET,
        jwtSignOptions: { algorithm: 'HS256' },
        rpcUrl: process.env.RPC_URL,
        acceptedRoles: parseAcceptedRoles(process.env.ACCEPTED_ROLES),
        didContractAddress: process.env.DID_REGISTRY_ADDRESS,
        ensRegistryAddress: process.env.ENS_REGISTRY_ADDRESS,
        ipfsUrl: CachedAuthStrategy.getIpfsClientConfig(configService).url,
        includeAllRoles: configService.get<boolean>('INCLUDE_ALL_ROLES'),
        siweMessageUri: new URL(
          '/auth/login/siwe/verify',
          new URL(configService.get<string>('SELF_BASE_URL')).origin,
        ).href,
      },
      cachedIssuerResolver,
      cachedRevokerResolver,
      cachedCredentialResolver,
      verifyCredential,
    );

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (this as any).cacheServerClient = cacheServerClient;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (this as any).provider = dummyProvider;

    this.logger.setContext(CachedAuthStrategy.name);

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
    return super.validate(
      token,
      payload,
      (err?: Error, user?: unknown, info?: unknown) => {
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

  async getRoleDefinition(
    namespace: string,
  ): Promise<IRoleDefinitionV2 | null> {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const cacheServerClient = (this as any).cacheServerClient;
    if (!cacheServerClient?.isAvailable) {
      throw new Error(
        `[Cache Only] SSI-Hub Cache Server unavailable. Cannot resolve role definition for ${namespace}.`,
      );
    }
    return cacheServerClient.getRoleDefinition({ namespace });
  }

  static getIpfsClientConfig(configService: ConfigService): {
    url: string;
    headers: Record<string, string> | null;
  } {
    let auth;

    if (
      configService.get<string>('IPFS_PROJECTID') &&
      configService.get<string>('IPFS_PROJECTSECRET')
    ) {
      auth =
        'Basic ' +
        Buffer.from(
          configService.get<string>('IPFS_PROJECTID') +
            ':' +
            configService.get<string>('IPFS_PROJECTSECRET'),
        ).toString('base64');
    }

    return {
      url:
        `${configService.get<string>('IPFS_PROTOCOL')}://` +
        `${configService.get<string>('IPFS_HOST')}` +
        `:${configService.get<string>('IPFS_PORT')}`,
      headers: auth
        ? {
            authorization: auth,
          }
        : null,
    };
  }
}

function parseAcceptedRoles(ACCEPTED_ROLES: string): string[] {
  return ACCEPTED_ROLES ? ACCEPTED_ROLES.split(',') : [];
}
