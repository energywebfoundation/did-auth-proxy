import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { RoleStatus } from 'passport-did-auth';
import { PinoLogger } from 'nestjs-pino';

@Injectable()
export class RolesValidationService {
  constructor(
    private readonly configService: ConfigService,
    private readonly logger: PinoLogger,
  ) {
    this.logger.setContext(RolesValidationService.name);
  }

  public async didAccessTokenRolesAreValid(
    userRoles: RoleStatus[],
  ): Promise<boolean> {
    const acceptedRoles = this.configService
      .get('ACCEPTED_ROLES', '')
      .split(',')
      .filter(Boolean);

    if (acceptedRoles.length === 0) {
      this.logger.error(`acceptedRoles is empty`);
      return false;
    }

    const roles = userRoles.map((r) => r.namespace);

    this.logger.debug(
      `validating ${JSON.stringify(roles)} against ${JSON.stringify(
        acceptedRoles,
      )}`,
    );

    return roles.some((r) => acceptedRoles.includes(r));
  }
}
