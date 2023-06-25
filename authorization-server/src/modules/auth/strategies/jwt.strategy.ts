import { ExtractJwt, JwtFromRequestFunction, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as express from 'express';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(config: ConfigService) {
    const extractorFunctions: JwtFromRequestFunction[] = [];

    const fromHeader = ExtractJwt.fromAuthHeaderAsBearerToken();

    const fromCookie = (req: express.Request) =>
      req?.cookies &&
      req.cookies[config.get<string>('AUTH_COOKIE_NAME_ACCESS_TOKEN')];

    if (config.get<boolean>('AUTH_HEADER_ENABLED')) {
      extractorFunctions.push(fromHeader);
    }

    if (config.get<boolean>('AUTH_COOKIE_ENABLED')) {
      extractorFunctions.push(fromCookie);
    }

    super({
      jwtFromRequest: ExtractJwt.fromExtractors(extractorFunctions),
      ignoreExpiration: false,
      secretOrKey: config.get<string>('JWT_SECRET'),
    });
  }

  async validate(payload: unknown) {
    return payload;
  }
}
