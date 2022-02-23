import {
  ConsoleLogger,
  ConsoleLoggerOptions,
  Injectable,
  Scope,
} from '@nestjs/common';

@Injectable({ scope: Scope.TRANSIENT })
export class LoggerService extends ConsoleLogger {
  constructor(context?: string, options?: ConsoleLoggerOptions) {
    const optionsDefault: ConsoleLoggerOptions = {
      timestamp: true,
    };

    super(context, { ...optionsDefault, ...options });

    if (process.env.NODE_ENV === 'test') {
      this.setLogLevels(['error', 'warn']);
    }
  }
}
