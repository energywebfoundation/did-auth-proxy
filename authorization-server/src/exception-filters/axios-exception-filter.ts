import { BaseExceptionFilter } from '@nestjs/core';
import { ArgumentsHost, Catch, HttpServer } from '@nestjs/common';
import { AxiosError } from 'axios';
import { PinoLogger } from 'nestjs-pino';

@Catch(AxiosError)
export class AxiosExceptionFilter extends BaseExceptionFilter {
  constructor(server: HttpServer, private readonly logger: PinoLogger) {
    logger.setContext(AxiosExceptionFilter.name);
    super(server);
  }

  catch(error: AxiosError, host: ArgumentsHost) {
    if (error.response) {
      this.logger.error(
        `${error.config.method.toUpperCase()} ${error.config.url}, ${
          error.response.status
        } ${error.response.statusText}`,
      );
    } else if (error.request) {
      this.logger.error(
        `${error.config.method.toUpperCase()} ${error.config.url}, ${
          error.message
        }`,
      );
    } else {
      this.logger.error(error.toString());
    }

    super.catch(error, host);
  }
}
