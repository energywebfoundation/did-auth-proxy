import { DynamicModule, Module } from '@nestjs/common';
import { OpenTelemetryModule } from 'nestjs-otel';
import { ConfigService } from '@nestjs/config';

@Module({})
export class TracingModule {
  public static forRoot(): DynamicModule {
    return {
      imports: [
        OpenTelemetryModule.forRootAsync({
          useFactory: (configService: ConfigService) => {
            return {
              metrics: {
                hostMetrics: true,
                defaultMetrics: false,
                apiMetrics: {
                  enable: true,
                  ignoreUndefinedRoutes: false,
                },
              },
            };
          },
          inject: [ConfigService],
        }),
      ],
      controllers: [],
      providers: [],
      exports: [],
      module: TracingModule,
    };
  }
}
