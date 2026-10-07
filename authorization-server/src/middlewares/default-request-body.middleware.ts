import { Injectable, NestMiddleware } from '@nestjs/common';
import { NextFunction, Request, Response } from 'express';

/**
 * Express 5 leaves `req.body` undefined when a request has no body, whereas
 * Express 4 always initialised it to `{}`. passport-did-auth (login strategy)
 * and the DTO validation in AuthController expect an object, so this middleware
 * restores the Express 4 default.
 */
@Injectable()
export class DefaultRequestBodyMiddleware implements NestMiddleware {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  use(req: Request, res: Response, next: NextFunction) {
    if (req.body === undefined) {
      req.body = {};
    }

    next();
  }
}
