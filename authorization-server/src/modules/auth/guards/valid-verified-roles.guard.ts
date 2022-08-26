import {
  CanActivate,
  ExecutionContext,
  Inject,
  InternalServerErrorException,
} from '@nestjs/common';
import { RolesValidationService } from '../roles-validation.service';
import { decode as decodeJWT } from 'jsonwebtoken';
import { IDidAccessTokenPayload } from '../types';
import { PinoLogger } from 'nestjs-pino';

//TODO: test like this: https://stackoverflow.com/questions/55848238/nestjs-unit-test-mock-method-guard

export class ValidVerifiedRolesGuard implements CanActivate {
  constructor(
    @Inject(PinoLogger)
    private readonly logger: PinoLogger,
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
      const errorMessage = `unexpected verified roles: ${JSON.stringify(
        didAccessTokenPayload.verifiedRoles,
      )}`;

      this.logger.error(errorMessage);
      throw new InternalServerErrorException({
        statusCode: 500,
        message: errorMessage,
        error: 'Internal Server Error',
      });
    }

    return verifiedRolesAreValid;
  }
}
