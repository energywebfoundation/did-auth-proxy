import { Test, TestingModule } from '@nestjs/testing';
import { RolesValidationService } from './roles-validation.service';
import { ConfigService } from '@nestjs/config';
import { PinoLogger } from 'nestjs-pino';
import { RoleCredentialStatus } from 'passport-did-auth';

const mockConfigService = {
  get: <T>(key: string): T => {
    return {
      ACCEPTED_ROLES:
        'role1.roles.app1.apps.org1.iam.ewc,role2.roles.app1.apps.org2.iam.ewc',
    }[key] as unknown as T;
  },
};

describe('RolesValidationService', function () {
  let service: RolesValidationService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RolesValidationService,
        { provide: ConfigService, useValue: mockConfigService },
        { provide: PinoLogger, useValue: new PinoLogger({}) },
      ],
    }).compile();

    service = module.get<RolesValidationService>(RolesValidationService);
  });

  it('should be defined', function () {
    expect(service).toBeDefined();
  });

  describe('when called with expected verifiedRoles', function () {
    it('should resolve to true', async function () {
      expect(
        await service.didAccessTokenRolesAreValid([
          {
            name: 'role1',
            namespace: 'role1.roles.app1.apps.org1.iam.ewc',
            status: RoleCredentialStatus.VALID,
          },
        ]),
      ).toBe(true);
    });
  });

  describe('when called with unexpected verifiedRoles', function () {
    it('should resolve to false', async function () {
      expect(
        await service.didAccessTokenRolesAreValid([
          {
            name: 'role2',
            namespace: 'role2.roles.app1.apps.org1.iam.ewc',
            status: RoleCredentialStatus.VALID,
          },
        ]),
      ).toBe(false);
    });
  });
});
