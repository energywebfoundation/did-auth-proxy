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
    const projectId = '2DTpW5Ddx5odgzd8tY1lzPCRSeF'; // 2DT... is from JH infura porject - to be deleted
    const projectSecret = 'f0b2110757d2c0642c5d7a62ed84d9bf'; // f0b.. is from JHInfura project - to be deleted

    const auth =
      'Basic ' +
      Buffer.from(projectId + ':' + projectSecret).toString('base64');

    const ipfsClientConfig = {
      host: 'ipfs.infura.io',
      port: 5001,
      protocol: 'https',
      headers: {
        authorization: auth,
      },
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
      ipfsClientConfig: ipfsClientConfig,
    });

    this.logger.setContext(AuthStrategy.name);

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
