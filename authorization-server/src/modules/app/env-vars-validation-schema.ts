import * as Joi from 'joi';

export const envVarsValidationSchema = Joi.object({
  NODE_ENV: Joi.string()
    .valid('development', 'production', 'test')
    .default('development'),

  LOG_LEVELS: Joi.string()
    .regex(
      /^((log|warn|error|debug|verbose)?(,(log|warn|error|debug|verbose))*)$/,
    )
    .default('log,warn,error,debug,verbose'),

  PORT: Joi.number().default(3000),
  BIND: Joi.string().ip().default('127.0.0.1'),

  RPC_URL: Joi.string().uri().default('https://volta-rpc.energyweb.org/'),
  CACHE_SERVER_URL: Joi.string()
    .uri()
    .default('https://identitycache-dev.energyweb.org/v1'),
  CACHE_SERVER_LOGIN_PRVKEY: Joi.string()
    .regex(/^(0x)?[0-9a-f]+$/)
    .required(),
  DID_REGISTRY_ADDRESS: Joi.string().required(),
  ENS_REGISTRY_ADDRESS: Joi.string().required(),

  ACCEPTED_ROLES: Joi.string().required(),

  REDIS_HOST: Joi.string().hostname().default('127.0.0.1'),
  REDIS_PORT: Joi.number().port().default(6379),
  REDIS_PASSWORD: Joi.string().optional(),

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

  OTEL_ENABLED: Joi.boolean().default(false),
  OTEL_TRACING_URL: Joi.string()
    .uri()
    .default('http://localhost:4318/v1/traces'),
  OTEL_SERVICE_NAME: Joi.string().default('did-auth-proxy'),
  OTEL_ENVIRONMENT: Joi.string().default('local'),
});
