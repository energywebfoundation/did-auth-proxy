import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { LoggerService } from '../logger';
import { IDidAccessTokenPayload } from './types';

@Injectable()
export class RolesValidationService {
  constructor(
    private readonly configService: ConfigService,
    private readonly logger: LoggerService,
  ) {
    this.logger.setContext(RolesValidationService.name);
  }

  public async didAccessTokenRolesAreValid(
    verifiedRoles: IDidAccessTokenPayload['verifiedRoles'],
  ): Promise<boolean> {
    const acceptedRoles = this.configService
      .get('ACCEPTED_ROLES', [])
      .split(',');
    const roles = verifiedRoles.map((r) => r.namespace);

    this.logger.debug(
      `validating ${JSON.stringify(roles)} against ${acceptedRoles}`,
    );

    return roles.some((r) => acceptedRoles.includes(r));
  }
}
