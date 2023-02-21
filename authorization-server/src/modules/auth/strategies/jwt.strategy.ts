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
      req &&
      req.cookies &&
      req.cookies[config.get<string>('AUTH_COOKIE_NAME_ACCESS_TOKEN')];

    if (config.get<boolean>('AUTH_COOKIE_ENABLED')) {
      if (config.get<boolean>('AUTH_COOKIE_ONLY')) {
        extractorFunctions.push(fromCookie);
      } else {
        extractorFunctions.push(fromHeader);
        extractorFunctions.push(fromCookie);
      }
    } else {
      extractorFunctions.push(fromHeader);
    }

    super({
      jwtFromRequest: ExtractJwt.fromExtractors(extractorFunctions),
      ignoreExpiration: false,
      secretOrKey: process.env.JWT_SECRET,
    });
  }

  async validate(payload: unknown) {
    return payload;
  }
}
