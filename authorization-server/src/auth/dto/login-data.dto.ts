import { ApiProperty } from '@nestjs/swagger';

export class LoginDataDTO {
  @ApiProperty({
    example: 'eyJhbGciOiJFUzI1NiIs************MjczYzVlMmRiMzE3ODFj',
  })
  identityToken: string;
}
