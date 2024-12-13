import { z } from 'zod'

export const loginUserSchema = z.object({
  email: z.string().email(),
  password: z.string(),
})

export const emailSchema = z.object({
  email: z.string().email(),
})

export const verifyOtpSchema = z.object({
  email: z.string().email(),
  otp: z.string(),
})

export const resetPasswordSchema = z.object({
  email: z.string().email(),
  password: z.string(),
  passwordConfirm: z.string(),
})

export type LoginUserSchema = typeof loginUserSchema._type
export type EmailSchema = typeof emailSchema._type
