import { configDotenv } from 'dotenv'
import development from './development'
import test from './test'
import production from './production'

configDotenv()

const defaults = {
  NODE_ENV: process.env.PROJECT_NODE_ENV,
  PORT: process.env.PROJECT_PORT,
  DATABASE_URL: process.env.PROJECT_DATABASE_URL,
  PAPERTRAIL_PORT: process.env.PROJECT_PAPERTRAIL_PORT,
  PAPERTRAIL_URL: process.env.PROJECTT_PAPERTRAIL_URL,
  APP_NAME: process.env.APP_NAME,
  DOMAIN: process.env.PROJECT_DOMAIN,
  SALT_ROUNDS: parseInt(process.env.PROJECT_SALT_ROUNDS as string),
  SECRET: process.env.PROJECT_SECRET,
  MAILJET_KEY: process.env.MAILJET_API_KEY,
  MAILJET_SECRET: process.env.MAILJET_SECRET_KEY,
}

export default {
  development: { ...defaults, ...development },
  test: { ...defaults, ...test },
  production: { ...defaults, ...production },
}[process.env.PROJECT_NODE_ENV || 'development']
