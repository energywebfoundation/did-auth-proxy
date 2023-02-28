import { ApiProperty } from '@nestjs/swagger';
import { Exclude, Expose } from 'class-transformer';

@Exclude()
export class SiweInitResponseDto {
  @ApiProperty()
  @Expose()
  nonce: string;

  constructor(properties: Partial<SiweInitResponseDto>) {
    Object.assign(this, properties);
  }
}
