import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsBoolean, IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class LogoutDto {
  @ApiPropertyOptional({})
  @IsString()
  @IsNotEmpty()
  @IsOptional()
  refreshToken?: string;

  @ApiProperty({ example: false })
  @IsBoolean()
  @IsNotEmpty()
  allDevices: boolean;
}
