import {
  DidStore,
  DomainReader,
  ethrReg,
  LoginStrategy,
  Methods,
  ResolverContractType,
  RoleCredentialResolver,
  RoleIssuerResolver,
  RoleRevokerResolver,
} from 'passport-did-auth';
import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ConfigService } from '@nestjs/config';
import { PinoLogger } from 'nestjs-pino';
import { verifyCredential } from 'didkit-wasm-node';
import { providers } from 'ethers';

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

    const ipfsConfig = AuthStrategy.getIpfsClientConfig(configService);

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
        includeAllRoles: false,
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
        new DidStore(ipfsConfig.url, ipfsConfig.headers),
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

    const port =
      configService.get<number>('IPFS_PORT') &&
      configService.get<number>('IPFS_PORT') !== 443
        ? ':' + configService.get<number>('IPFS_PORT')
        : '';

    return {
      url: `https://${configService.get<string>('IPFS_HOST')}${port}`,
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
