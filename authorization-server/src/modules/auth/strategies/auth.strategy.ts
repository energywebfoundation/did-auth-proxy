import { LoginStrategy } from 'passport-did-auth';
import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { LoggerService } from '../../logger';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthStrategy extends PassportStrategy(LoginStrategy, 'login') {
  constructor(
    private readonly logger: LoggerService,
    private readonly configService: ConfigService,
  ) {
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

    const ipfsClientConfig = {
      host: configService.get<string>('IPFS_HOST'),
      port: configService.get<number>('IPFS_PORT'),
      protocol: 'https',
      headers: auth
        ? {
            authorization: auth,
          }
        : null,
    };

    super({
      jwtSecret: process.env.JWT_SECRET,
      jwtSignOptions: { algorithm: 'HS256' },
      rpcUrl: process.env.RPC_URL,
      cacheServerUrl: process.env.CACHE_SERVER_URL,
      acceptedRoles: parseAcceptedRoles(process.env.ACCEPTED_ROLES),
      privateKey: process.env.CACHE_SERVER_LOGIN_PRVKEY,
      didContractAddress: process.env.DID_REGISTRY_ADDRESS,
      ensRegistryAddress: process.env.ENS_REGISTRY_ADDRESS,
      ipfsUrl: ipfsClientConfig,
    });

    this.logger.setContext(AuthStrategy.name);

    this.logger.log(`ipfsClientConfig ${JSON.stringify(ipfsClientConfig)}`);
    this.logger.log(
      `accepted roles: ${parseAcceptedRoles(
        process.env.ACCEPTED_ROLES,
      ).join()}`,
    );
  }
}

function parseAcceptedRoles(ACCEPTED_ROLES: string): string[] {
  return ACCEPTED_ROLES ? ACCEPTED_ROLES.split(',') : [];
}
