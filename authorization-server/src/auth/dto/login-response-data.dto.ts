import { ApiProperty } from '@nestjs/swagger';
import {
  IsIn,
  IsInt,
  IsJWT,
  IsNotEmpty,
  IsString,
  validateSync,
} from 'class-validator';
import { IAccessTokenPayload } from '../auth.interface';
import { decode as decodeJWT } from 'jsonwebtoken';

export class LoginResponseDataDto {
  @ApiProperty({
    example:
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkaWQiOiJkaWQ6ZXRocjoweDgyRmNCMzEzODVFYUJlMjYxRTRlNjAwM2I5RjJDYjJhZjM0ZTI2NTQiLCJ2ZXJpZmllZFJvbGVzIjpbeyJuYW1lIjoicm9sZTEiLCJuYW1lc3BhY2UiOiJyb2xlMS5yb2xlcy5hcHAtdGVzdDIuYXBwcy5hcnR1ci5pYW0uZXdjIn1dLCJpYXQiOjE2NDQyNDMwNzB9.uvJoXxVBrTC2lCWsF7DQTNEPVmgPoBlSSOE9Y6JFpZQ',
  })
  @IsString()
  @IsNotEmpty()
  @IsJWT()
  access_token: string;

  @ApiProperty({ example: 'Bearer' })
  @IsIn(['Bearer'])
  type: 'Bearer';

  @ApiProperty({ example: 3600 })
  @IsInt()
  expires_in: number;

  @ApiProperty()
  @IsString()
  @IsNotEmpty()
  refresh_token: string;

  protected validate() {
    const errors = validateSync(this);
    if (errors.length > 0) {
      throw new Error(
        `validation error: ${errors
          .map((e) =>
            Object.keys(e.constraints)
              .map((k) => e.constraints[k])
              .join(),
          )
          .join('; ')}`,
      );
    }
  }

  constructor({
    accessToken,
    refreshToken,
  }: {
    accessToken: string;
    refreshToken: string;
  }) {
    const accessTokenDecoded: IAccessTokenPayload = decodeJWT(
      accessToken,
    ) as IAccessTokenPayload;

    const tokenTTL = accessTokenDecoded.exp - accessTokenDecoded.iat;
    const expiresIn =
      tokenTTL - Math.ceil((Date.now() - accessTokenDecoded.iat * 1000) / 1000);

    Object.assign(this, {
      access_token: accessToken,
      type: 'Bearer',
      expires_in: expiresIn,
      refresh_token: refreshToken,
    });

    this.validate();
  }
}
