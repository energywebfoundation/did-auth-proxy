import * as Joi from 'joi';

export const envVarsValidationSchema = Joi.object({
  NODE_ENV: Joi.string()
    .valid('development', 'production', 'test')
    .default('development'),

  LOG_LEVEL: Joi.string()
    .valid('silent', 'fatal', 'error', 'warn', 'info', 'debug', 'trace')
    .default('debug'),

  PORT: Joi.number().default(3000),

  CORS_MAX_AGE: Joi.number().integer().positive().default(60),
  CORS_ORIGIN: Joi.string().default('*'),

  BIND: Joi.string().ip().default('127.0.0.1'),
  SELF_BASE_URL: Joi.string().uri().required(),
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

  IPFS_PROTOCOL: Joi.string().valid('http', 'https').required(),
  IPFS_HOST: Joi.string().hostname().required(),
  IPFS_PORT: Joi.number().port().required(),
  IPFS_PROJECTID: Joi.string().optional().allow(''),
  IPFS_PROJECTSECRET: Joi.string().optional().allow(''),

  BLOCKNUM_AUTH_ENABLED: Joi.boolean().required(),
  ACCEPTED_ROLES: Joi.string().optional().allow(''),
  INCLUDE_ALL_ROLES: Joi.boolean().required(),

  REDIS_HOST: Joi.string().hostname().default('127.0.0.1'),
  REDIS_PORT: Joi.number().port().default(6379),
  REDIS_PASSWORD: Joi.string().optional().allow(''),

  FAIL_ON_REDIS_UNAVAILABLE: Joi.bool().default(false),

  JWT_SECRET: Joi.string().required(),
  JWT_ACCESS_TTL: Joi.number().default(3600),
  JWT_REFRESH_TTL: Joi.number().default(86400),

  SIWE_NONCE_TTL: Joi.number().positive().required(),

  AUTH_COOKIE_NAME_ACCESS_TOKEN: Joi.string().default('token'),
  AUTH_COOKIE_NAME_REFRESH_TOKEN: Joi.string().default('refreshToken'),
  AUTH_COOKIE_ENABLED: Joi.boolean().default(false),
  AUTH_HEADER_ENABLED: Joi.boolean().default(true),
  AUTH_COOKIE_SECURE: Joi.boolean().default(true),
  AUTH_COOKIE_SAMESITE_POLICY: Joi.string()
    .regex(/(none|lax|strict)/)
    .default('strict'),

  DISABLE_HEALTHCHECK_RPC: Joi.boolean().default(false),
  DISABLE_HEALTHCHECK_IPFS: Joi.boolean().default(false),
  DISABLE_HEALTHCHECK_REDIS: Joi.boolean().default(false),

  SWAGGER_PATH: Joi.string().default('swagger'),
});
