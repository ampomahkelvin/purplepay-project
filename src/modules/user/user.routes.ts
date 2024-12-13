import express from 'express'
import { UserController } from './user.controller'
import { ValidationMiddleware } from './middlewares/user-middleware'
import {
  emailSchema,
  loginUserSchema,
  resetPasswordSchema,
  verifyOtpSchema,
} from './validation'

const router = express.Router()

router.post(
  '/login',
  ValidationMiddleware.validateRequest(loginUserSchema),
  UserController.loginUser,
)
router.post(
  '/send/reset-email',
  ValidationMiddleware.validateRequest(emailSchema),
  UserController.sendResetPasswordEmail,
)
router.post(
  '/verify-otp',
  ValidationMiddleware.validateRequest(verifyOtpSchema),
  UserController.verifyOtp,
)
router.post(
  '/reset-password',
  ValidationMiddleware.validateRequest(resetPasswordSchema),
  UserController.resetPassword,
)

export default router
