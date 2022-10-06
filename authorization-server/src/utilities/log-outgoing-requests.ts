import { ClientRequest, IncomingMessage, RequestOptions } from 'http';

export interface Config {
  logStartOfRequest: boolean;
  logRequestStartTime: boolean;
  logStackTrace: boolean;
  logStackTraceErrorsOnly: boolean;
  logRequestBodies: boolean;
  logRequestHeaders: boolean;
  logResponseBodies: boolean;
}

export function logOutgoingRequests(
  /* eslint-disable-next-line @typescript-eslint/no-explicit-any */
  httpModule: {
    request: (
      options: string | RequestOptions | URL,
      callback?: (res: IncomingMessage) => void,
    ) => ClientRequest;
  },
  config: Config,
) {
  const original = httpModule.request;

  httpModule.request = function wrapMethodRequest(
    options: RequestOptions,
    callback: (res: IncomingMessage) => void,
  ): ClientRequest {
    const stackTrace = new Error().stack
      .split('\n')
      .filter((line) => line !== 'Error: ')
      .join('\n');
    const start = Date.now();

    if (config.logStartOfRequest) {
      console.log(
        `OUTGOING_REQUEST_START [${new Date().toISOString()}] ${
          options.method
        } ${getUrlFromRequestOptions(options)}`,
      );
    }

    const clientRequest = original(options, callback) as ClientRequest;
    const originalWrite = clientRequest.write;

    let requestBody = '';
    clientRequest.write = function (...args): boolean {
      requestBody += args[0].toString();
      return originalWrite.apply(this, args);
    };

    clientRequest.on('error', (err) => {
      const finished = Date.now();

      console.log(
        `OUTGOING_REQUEST_ERR ${getUrlFromRequestOptions(
          options,
        )} errored after ${finished - start}ms: ${err}`,
      );

      if (config.logStackTrace) {
        console.log(stackTrace);
      }
    });

    clientRequest.on('response', (response: IncomingMessage) => {
      let responseBody = '';

      response.on('data', (chunk) => {
        responseBody += chunk.toString();
      });

      response.on('end', () => {
        const finished = Date.now();
        console.log(
          getStringLogMessage(
            {
              requestOptions: options,
              requestBody,
              response,
              responseBody,
              timeElapsed: finished - start,
            },
            {
              logRequestStartTime: config.logRequestStartTime,
              logRequestBody: config.logRequestBodies,
              logResponseBody: config.logResponseBodies,
              logRequestHeaders: config.logRequestHeaders,
            },
          ),
        );

        if (config.logStackTrace && !config.logStackTraceErrorsOnly) {
          console.log(stackTrace);
        }
      });
    });

    return clientRequest;
  };
}

function getUrlFromRequestOptions(requestOptions: RequestOptions): string {
  return `${requestOptions.protocol}//${requestOptions.hostname}${
    requestOptions.port ? `:${requestOptions.port}` : ''
  }${requestOptions.path}`;
}

function getStringLogMessage(
  args: {
    requestOptions: RequestOptions;
    requestBody: string;
    response: IncomingMessage;
    responseBody: string;
    timeElapsed: number;
  },
  options: {
    logRequestStartTime: boolean;
    logRequestBody: boolean;
    logResponseBody: boolean;
    logRequestHeaders: boolean;
  },
): string {
  const { requestOptions, requestBody, response, responseBody, timeElapsed } =
    args;

  let logMessagePrefix = 'OUTGOING_REQUEST_OK';

  if (!(response.statusCode >= 200 && response.statusCode < 300)) {
    logMessagePrefix = 'OUTGOING_REQUEST_ERR';
  }

  const timestamp = options.logRequestStartTime
    ? ` [${new Date().toISOString()}] `
    : ' ';

  return `${logMessagePrefix}${timestamp}${timeElapsed}ms ${
    requestOptions.method
  } ${getUrlFromRequestOptions(requestOptions)}${
    options.logRequestBody ? ` [${requestBody}]` : ''
  }${
    options.logRequestHeaders
      ? ' ' +
        JSON.stringify({
          headers: requestOptions.headers,
        })
      : ''
  } ${response.statusCode} ${response.statusMessage}${
    options.logResponseBody
      ? ` responseBody=${responseBody.replace(/\n$/, '')}`
      : ''
  }`;
}
