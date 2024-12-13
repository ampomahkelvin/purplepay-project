import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import * as crypto from 'node:crypto'
import { OtpRepository, UserRepository } from '../repositories'
import Env from '../../../shared/utils/env'
import { ApiError } from '../../../shared/utils/api-error'
import SendEmail from '../../../services/mail-service'

const getUserByEmail = async (email: string) => {
  const user = await UserRepository.getUser(email)
  if (!user) throw new ApiError(404, 'User does not exist')
  return user
}

export class UserService {
  static loginUser = async (email: string, password: string) => {
    const user = await getUserByEmail(email)
    const secret = Env.get('SECRET')
    const passwordMatch = await bcrypt.compare(password, user.password)

    if (!passwordMatch) throw new ApiError(400, 'Credentials are incorrect')
    if (!secret) throw new ApiError(400, 'Jwt Secret missing')

    try {
      const token = jwt.sign({ userId: user.id, email: user.email }, secret, {
        expiresIn: '1h',
      })

      return { user, token }
    } catch (e) {
      throw e
    }
  }

  static sendResetPasswordEmail = async (email: string) => {
    const user = await getUserByEmail(email)
    const expiry = new Date(Date.now() + 10 * 60 * 1000)
    // generate otp code
    const otpCode = crypto.randomBytes(3).toString('hex').toUpperCase()

    try {
      // save otp in the db. Hash otp first. I think for security
      const hashedOtp = crypto
        .createHash('sha256')
        .update(otpCode)
        .digest('hex')
      await OtpRepository.saveOtp(user.id, hashedOtp, expiry)

      return await SendEmail.sendOtp(otpCode, email)
    } catch (e) {
      throw e
    }
  }

  static verifyOtp = async (email: string, otpCode: string) => {
    const user = await getUserByEmail(email)
    // get userId
    const userId = user.id

    // get otp in db and compare it
    const otp = await OtpRepository.getOtp(userId)

    if (!otp) throw new ApiError(404, 'OTP not found')
    const hashedOtp = crypto.createHash('sha256').update(otpCode).digest('hex')

    if (hashedOtp !== otp.otp) {
      throw new ApiError(400, 'Invalid OTP')
    }
    if (new Date() > otp.expiresAt) {
      throw new ApiError(400, 'OTP has expired')
    }

    try {
      await OtpRepository.verifyOtp(hashedOtp, userId)

      return otp
    } catch (e) {
      throw e
    }
  }

  static resetPassword = async (email: string, newPassword: string) => {
    const user = await getUserByEmail(email)
    const userId = user.id

    // check if otp is verified or exists
    const otp = await OtpRepository.getOtp(userId)
    if (!otp || !otp.isVerified)
      throw new ApiError(400, 'Otp not verified or incorrect')

    // check if otp has already been used
    if (otp.isUsed)
      throw new ApiError(400, 'Otp has been used. Request another')

    const hashedPassword = await bcrypt.hash(newPassword, 12)

    if (await bcrypt.compare(newPassword, user.password))
      throw new ApiError(
        400,
        'New password cannot be the same as the current password',
      )

    try {
      // overwrite prev password
      const updatedUser = await UserRepository.updatePassword(
        hashedPassword,
        email,
      )
      await OtpRepository.setOtpToUsed(otp.otp, userId)
      await SendEmail.sendResetSuccessful(email)
      return updatedUser
    } catch (e) {
      throw e
    }
  }
}
