import {
  HealthCheckError,
  HealthIndicator,
  HealthIndicatorResult,
} from '@nestjs/terminus';
import { Injectable } from '@nestjs/common';
import axios from 'axios';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class RpcHealthIndicator extends HealthIndicator {
  constructor(private readonly config: ConfigService) {
    super();
  }

  async checkStatus(key: string): Promise<HealthIndicatorResult> {
    let data: Record<string, unknown> | string;

    try {
      ({ data } = await axios.post<string>(
        // example request taken from https://ethereum.org/en/developers/docs/apis/json-rpc/#curl-examples
        this.config.get('RPC_URL', ''),
        {
          jsonrpc: '2.0',
          method: 'web3_clientVersion',
          params: [],
          id: 67,
        },
        {
          maxRedirects: 0,
          timeout: 5000,
        },
      ));
    } catch (err) {
      let reason: string;

      if (err.response) {
        reason = `${err.response.status} ${err.response.statusText}`;
      } else if (err.request) {
        reason = err.message;
      } else {
        throw err;
      }

      throw new HealthCheckError(
        'ping request failed',
        this.getStatus(key, false, { reason }),
      );
    }

    if (
      ['jsonrpc', 'result', 'id'].filter(
        (key) => !Object.keys(data).includes(key),
      ).length > 0
    ) {
      throw new HealthCheckError(
        'ping request failed',
        this.getStatus(key, false, { reason: 'unexpected response body' }),
      );
    }

    return this.getStatus(key, true);
  }
}
