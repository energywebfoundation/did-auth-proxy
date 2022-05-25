import { CanActivate, ExecutionContext, Inject } from '@nestjs/common';
import { RolesValidationService } from '../roles-validation.service';
import { decode as decodeJWT } from 'jsonwebtoken';
import { IDidAccessTokenPayload } from '../types';
import { LoggerService } from '../../logger';

//TODO: test like this: https://stackoverflow.com/questions/55848238/nestjs-unit-test-mock-method-guard

export class ValidVerifiedRolesGuard implements CanActivate {
  constructor(
    @Inject(LoggerService)
    private readonly logger: LoggerService,
    private readonly rolesValidationService: RolesValidationService,
  ) {
    logger.setContext(ValidVerifiedRolesGuard.name);
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const { user } = context.switchToHttp().getRequest();
    if (!user) {
      return false;
    }

    const didAccessTokenPayload = decodeJWT(
      user,
    ) as unknown as IDidAccessTokenPayload;

    this.logger.debug(
      `validating verified roles: ${JSON.stringify(
        didAccessTokenPayload.verifiedRoles,
      )}`,
    );

    const verifiedRolesAreValid =
      await this.rolesValidationService.didAccessTokenRolesAreValid(
        didAccessTokenPayload.verifiedRoles,
      );

    if (!verifiedRolesAreValid) {
      this.logger.error(
        `unexpected verified roles: ${didAccessTokenPayload.verifiedRoles}`,
      );
      throw new Error(
        `unexpected verified roles: ${didAccessTokenPayload.verifiedRoles}`,
      );
    }

    return verifiedRolesAreValid;
  }
}
