import { Response, Request, NextFunction } from 'express'
import { UserService } from './services'
import { ApiError } from '../../shared/utils/api-error'

export class UserController {
  static loginUser = async (
    req: Request,
    res: Response,
    next: NextFunction,
  ) => {
    const body = req.body
    if (!body.email || !body.password) throw new ApiError(400, 'Missing fields')

    try {
      const { user, token } = await UserService.loginUser(
        body.email.toLowerCase().trim(),
        body.password.trim(),
      )

      if (!user)
        res.json({
          status: 400,
          message: 'Email or password is incorrect',
        })

      res.json({
        status: 200,
        message: 'User login successful',
        token: token,
        user,
      })
    } catch (e) {
      next(e)
    }
  }

  static sendResetPasswordEmail = async (
    req: Request,
    res: Response,
    next: NextFunction,
  ) => {
    const { email } = req.body
    if (!email) throw new ApiError(400, 'Enter an email')

    try {
      const response = await UserService.sendResetPasswordEmail(email.trim())
      res.json({
        status: 200,
        message: 'Email sent successfully',
        response,
      })
    } catch (e) {
      next(e)
    }
  }

  static verifyOtp = async (
    req: Request,
    res: Response,
    next: NextFunction,
  ) => {
    const { email, otp } = req.body
    if (!email || !otp) throw new ApiError(400, 'Missing fields')

    try {
      await UserService.verifyOtp(email, otp.toString().trim().toUpperCase())
      res.json({
        status: 200,
        message: 'Otp verified',
      })
    } catch (e) {
      next(e)
    }
  }

  static resetPassword = async (
    req: Request,
    res: Response,
    next: NextFunction,
  ) => {
    const { email, password, passwordConfirm } = req.body
    if (!email || !password || !passwordConfirm)
      throw new ApiError(400, 'Missing fields')
    if (password !== passwordConfirm)
      throw new ApiError(404, 'Passwords do not match')

    try {
      await UserService.resetPassword(email.trim(), password.trim())
      res.json({
        status: 200,
        message: 'Password changed successfully',
      })
    } catch (e) {
      next(e)
    }
  }
}
