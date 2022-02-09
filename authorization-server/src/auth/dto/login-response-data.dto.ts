import { ApiProperty } from '@nestjs/swagger';

export class LoginResponseDataDto {
  @ApiProperty({
    example:
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkaWQiOiJkaWQ6ZXRocjoweDgyRmNCMzEzODVFYUJlMjYxRTRlNjAwM2I5RjJDYjJhZjM0ZTI2NTQiLCJ2ZXJpZmllZFJvbGVzIjpbeyJuYW1lIjoicm9sZTEiLCJuYW1lc3BhY2UiOiJyb2xlMS5yb2xlcy5hcHAtdGVzdDIuYXBwcy5hcnR1ci5pYW0uZXdjIn1dLCJpYXQiOjE2NDQyNDMwNzB9.uvJoXxVBrTC2lCWsF7DQTNEPVmgPoBlSSOE9Y6JFpZQ',
  })
  access_token: string;

  @ApiProperty({ example: 'Bearer' })
  type: string;

  @ApiProperty({ example: 3600 })
  expires_in: number;

  @ApiProperty()
  refresh_token: string;
}
