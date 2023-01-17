import * as Joi from 'joi';

export const envVarsValidationSchema = Joi.object({
  NODE_ENV: Joi.string()
    .valid('development', 'production', 'test')
    .default('development'),

  LOG_LEVEL: Joi.string()
    .valid('silent', 'fatal', 'error', 'warn', 'info', 'debug', 'trace')
    .default('debug'),

  PORT: Joi.number().default(3000),
  BIND: Joi.string().ip().default('127.0.0.1'),

  CHAIN_ID: Joi.number().positive().default(73799),
  RPC_URL: Joi.string().uri().default('https://volta-rpc.energyweb.org/'),
  CACHE_SERVER_URL: Joi.string()
    .uri()
    .default('https://identitycache-dev.energyweb.org/v1'),
  CACHE_SERVER_LOGIN_PRVKEY: Joi.string()
    .regex(/^(0x)?[0-9a-f]+$/)
    .required(),
  DID_REGISTRY_ADDRESS: Joi.string().required(),
  ENS_REGISTRY_ADDRESS: Joi.string().required(),
  ENS_RESOLVER_ADDRESS: Joi.string().required(),

  IPFS_HOST: Joi.string().hostname().optional().default('ipfs.infura.io'),
  IPFS_PORT: Joi.number().positive().optional().default(5001),
  IPFS_PROJECTID: Joi.string().optional().allow(''),
  IPFS_PROJECTSECRET: Joi.string().optional().allow(''),

  ACCEPTED_ROLES: Joi.string().optional().allow(''),
  INCLUDE_ALL_ROLES: Joi.boolean().required(),

  REDIS_HOST: Joi.string().hostname().default('127.0.0.1'),
  REDIS_PORT: Joi.number().port().default(6379),
  REDIS_PASSWORD: Joi.string().optional().allow(''),

  FAIL_ON_REDIS_UNAVAILABLE: Joi.bool().default(false),

  JWT_SECRET: Joi.string().required(),
  JWT_ACCESS_TTL: Joi.number().default(3600),
  JWT_REFRESH_TTL: Joi.number().default(86400),

  AUTH_COOKIE_NAME: Joi.string().default('Auth'),
  AUTH_COOKIE_ENABLED: Joi.boolean().default(false),
  AUTH_COOKIE_SECURE: Joi.boolean().default(true),
  AUTH_COOKIE_SAMESITE_POLICY: Joi.string()
    .regex(/(none|lax|strict)/)
    .default('strict'),
});
