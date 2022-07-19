import { BatchSpanProcessor } from '@opentelemetry/sdk-trace-base';
import { getNodeAutoInstrumentations } from '@opentelemetry/auto-instrumentations-node';
import { NodeSDK } from '@opentelemetry/sdk-node';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { Resource } from '@opentelemetry/resources';
import { SemanticResourceAttributes } from '@opentelemetry/semantic-conventions';
import { B3InjectEncoding, B3Propagator } from '@opentelemetry/propagator-b3';
import {
  CompositePropagator,
  W3CBaggagePropagator,
  W3CTraceContextPropagator,
} from '@opentelemetry/core';
import { diag, DiagConsoleLogger, DiagLogLevel } from '@opentelemetry/api';

diag.setLogger(new DiagConsoleLogger(), DiagLogLevel.ERROR);

const exporter = new OTLPTraceExporter({
  url: process.env.OTEL_TRACING_URL,
});

// @TODO - https://github.com/open-telemetry/opentelemetry-js/issues/2675#issuecomment-1098198722
// const metricExporter = new OTLPMetricExporter({
//   url: 'http://localhost:4318/v1/metrics',
// });

export const otelSDK = new NodeSDK({
  metricInterval: 1000,
  resource: new Resource({
    [SemanticResourceAttributes.SERVICE_NAME]: process.env.OTEL_SERVICE_NAME,
    [SemanticResourceAttributes.DEPLOYMENT_ENVIRONMENT]:
      process.env.OTEL_ENVIRONMENT,
  }),
  traceExporter: exporter,
  textMapPropagator: new CompositePropagator({
    propagators: [
      new W3CTraceContextPropagator(),
      new W3CBaggagePropagator(),
      new B3Propagator(),
      new B3Propagator({
        injectEncoding: B3InjectEncoding.MULTI_HEADER,
      }),
    ],
  }),
  spanProcessor: new BatchSpanProcessor(exporter, {
    maxQueueSize: 10,
    maxExportBatchSize: 10,
    scheduledDelayMillis: 50,
    exportTimeoutMillis: 3000,
  }),
  instrumentations: [getNodeAutoInstrumentations()],
});
