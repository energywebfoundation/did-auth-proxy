import { Injectable, OnModuleInit } from '@nestjs/common';
import { LoggerService } from '../logger/logger.service';
import { ConfigService } from '@nestjs/config';
import { resolve } from 'path';
import { readFile } from 'fs/promises';
import { IsNotEmpty, IsString, validateSync } from 'class-validator';

class HATokenFileRecordDto {
  @IsNotEmpty()
  @IsString()
  did: string;

  @IsNotEmpty()
  @IsString()
  token: string;

  constructor(props: HATokenFileRecordDto) {
    Object.assign(this, props);

    const errors = validateSync(this);
    if (errors.length > 0) {
      throw new Error(errors.toString());
    }
  }
}

@Injectable()
export class HomeAssistantTokenRepository implements OnModuleInit {
  private tokens: Record<string, { token: string }> = {};

  constructor(
    private readonly logger: LoggerService,
    private readonly configService: ConfigService,
  ) {
    this.logger.setContext(HomeAssistantTokenRepository.name);
  }

  async onModuleInit(): Promise<void> {
    this.logger.debug(`onModuleInit`);

    await this.loadDataFromFile();
  }

  public async loadDataFromFile() {
    const path = resolve(
      this.configService.get<string>('HOME_ASSISTANT_TOKENS_FILE'),
    );

    this.logger.debug(`loading data from ${path}`);

    const data = await readFile(path, 'utf8');

    let dataParsed;

    try {
      dataParsed = JSON.parse(data);
    } catch (error) {
      this.logger.error(`error parsing data from ${path}`);
      throw new Error(`error parsing data from ${path}`);
    }

    if (!Array.isArray(dataParsed)) {
      this.logger.error(`data from ${path} is not an array`);
      throw new Error(`data from ${path} is not an array`);
    }

    for (const fileRecord of dataParsed) {
      let record: HATokenFileRecordDto;

      try {
        record = new HATokenFileRecordDto(fileRecord);
      } catch (err) {
        this.logger.error(
          `invalid token data record: ${JSON.stringify(fileRecord)}`,
        );
        throw err;
      }
      this.tokens[record.did] = record;
    }

    this.logger.debug(`loaded ${Object.keys(this.tokens).length} tokens`);
    this.logger.debug(`loaded tokens for dids: ${Object.keys(this.tokens)}`);
  }

  public async getToken(did: string): Promise<string | null> {
    if (!this.tokens[did]) {
      this.logger.warn(`no token found for did: ${did}`);
      return null;
    }

    return this.tokens[did].token;
  }
}
