import {
  DidStore,
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
import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ConfigService } from '@nestjs/config';
import { PinoLogger } from 'nestjs-pino';
import { verifyCredential } from 'didkit-wasm-node';
import { providers } from 'ethers';
import { Request } from 'express';

@Injectable()
export class AuthStrategy extends PassportStrategy(LoginStrategy, 'login') {
  constructor(
    private readonly logger: PinoLogger,
    private readonly configService: ConfigService,
  ) {
    const provider = new providers.JsonRpcProvider(
      configService.get<string>('RPC_URL'),
    );

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
        ipfsUrl: AuthStrategy.getIpfsClientConfig(configService).url,
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
        new DidStore(AuthStrategy.getIpfsClientConfig(configService)),
        privateKey,
        cacheServerUrl,
      ),
      verifyCredential,
    );

    this.logger.setContext(AuthStrategy.name);

    this.logger.info(
      `ipfsClientConfig ${JSON.stringify(
        AuthStrategy.getIpfsClientConfig(configService),
      )}`,
    );

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
