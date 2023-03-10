import { Injectable, NestMiddleware } from '@nestjs/common';
import { NextFunction, Request, Response } from 'express';
import { PinoLogger } from 'nestjs-pino';

@Injectable()
export class DisableBlockAuthRoutesMiddleware implements NestMiddleware {
  constructor(private readonly logger: PinoLogger) {
    logger.setContext(DisableBlockAuthRoutesMiddleware.name);
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  use(req: Request, res: Response, next: NextFunction) {
    this.logger.warn(`unexpected ${req.method} ${req.originalUrl} request`);

    res.status(404).send({
      message:
        'Authentication at this endpoint is disabled. Other authentication protocols may be available',
    });
  }
}
