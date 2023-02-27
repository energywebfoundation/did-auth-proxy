import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

export class SiweVerifyRequestDto {
  @ApiProperty()
  @IsString()
  message: string;

  @ApiProperty()
  @IsString()
  signature: string;
}
