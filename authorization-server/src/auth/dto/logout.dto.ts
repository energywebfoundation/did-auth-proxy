import { ApiProperty } from '@nestjs/swagger';
import { IsBoolean, IsNotEmpty, IsString } from 'class-validator';

export class LogoutDto {
  @ApiProperty({})
  @IsString()
  @IsNotEmpty()
  refreshToken: string;

  @ApiProperty({ example: false })
  @IsBoolean()
  @IsNotEmpty()
  allDevices: boolean;
}
