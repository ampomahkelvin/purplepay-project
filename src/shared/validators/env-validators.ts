import { z } from 'zod';
import { AppEnv } from '../enums';

export interface EnvProps {
  PORT: number;
  NODE_ENV: string;
  DATABASE_URL: string;
  APP_NAME: string;
  SALT_ROUNDS: number;
  SECRET: string;
  DOMAIN: string;
  MAILJET_KEY: string;
  MAILJET_SECRET: string;
}

export const envValidatorSchema = z.object({
  PORT: z.string().default('8000'),
  NODE_ENV: z.string().default(AppEnv.DEVELOPMENT),
  DATABASE_URL: z.string(),
  APP_NAME: z.string(),
  SALT_ROUNDS: z.number(),
  SECRET: z.string(),
  DOMAIN: z.string(),
  MAILJET_KEY:z.string(),
  MAILJET_SECRET:z.string()
});