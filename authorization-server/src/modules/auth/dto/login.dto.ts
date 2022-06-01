import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class LoginDto {
  @ApiProperty({
    example: 'eyJhbGciOiJFUzI1NiIs************MjczYzVlMmRiMzE3ODFj',
  })
  @IsString()
  @IsNotEmpty()
  identityToken: string;
}
