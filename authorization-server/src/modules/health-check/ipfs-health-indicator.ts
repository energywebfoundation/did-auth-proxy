import {
  HealthCheckError,
  HealthIndicator,
  HealthIndicatorResult,
} from '@nestjs/terminus';
import { Injectable } from '@nestjs/common';
import axios from 'axios';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class IpfsHealthIndicator extends HealthIndicator {
  private ipfsBaseUrl: string;
  private ipfsAuth: string | undefined;

  constructor(private readonly config: ConfigService) {
    super();
    this.ipfsBaseUrl =
      `${config.get('IPFS_PROTOCOL')}://` +
      `${config.get('IPFS_HOST')}:${config.get('IPFS_PORT')}`;

    if (
      config.get<string>('IPFS_PROJECTSECRET') &&
      config.get<string>('IPFS_PROJECTID')
    ) {
      this.ipfsAuth =
        'Basic ' +
        Buffer.from(
          `${config.get<string>('IPFS_PROJECTID')}:${config.get<string>(
            'IPFS_PROJECTSECRET',
          )}`,
        ).toString('base64');
    }
  }

  async checkStatus(key: string): Promise<HealthIndicatorResult> {
    const headers = {
      ...(this.ipfsAuth ? { authorization: this.ipfsAuth } : {}),
    };

    try {
      await axios.post<string>(`${this.ipfsBaseUrl}/api/v0/version`, null, {
        headers,
        maxRedirects: 0,
        timeout: 5000,
      });
    } catch (err) {
      let reason: string;

      console.log(err.headers);

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

    return this.getStatus(key, true);
  }
}
