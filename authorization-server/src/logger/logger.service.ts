import {
  ConsoleLogger,
  ConsoleLoggerOptions,
  Injectable,
  LogLevel,
  Scope,
} from '@nestjs/common';
import { isCI } from '../helpers';

export { LogLevel } from '@nestjs/common';

@Injectable({ scope: Scope.TRANSIENT })
export class LoggerService extends ConsoleLogger {
  constructor(context?: string, options?: ConsoleLoggerOptions) {
    const optionsDefault: ConsoleLoggerOptions = {
      timestamp: true,
    };

    super(context, { ...optionsDefault, ...options });

    if (isCI()) {
      this.setLogLevels(['error', 'warn']);
    }
  }

  protected getTimestamp(): string {
    return new Date().toISOString();
  }

  setLogLevelsFromString(levels: string) {
    super.setLogLevels(levels.split(',') as LogLevel[]);
  }
}
