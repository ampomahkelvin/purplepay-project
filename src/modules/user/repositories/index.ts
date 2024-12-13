import { otpCodes, userQueries } from '../queries'
import { sqlQuest } from '../../../config/database'
import { ApiError } from '../../../shared/utils/api-error'

export class UserRepository {
  static getUser = async (email: string) => {
    try {
      const user = await sqlQuest.oneOrNone(userQueries.getUser, [email])
      if (!user) return new ApiError(404, 'User not found')

      return user
    } catch (e) {
      throw e
    }
  }

  static updatePassword = async (password: string, email: string) => {
    try {
      return await sqlQuest.none(userQueries.updatePassword, [password, email])
    } catch (e) {
      throw e
    }
  }
}

export class OtpRepository {
  static getOtp = async (userId: number) => {
    try {
      const otp = await sqlQuest.oneOrNone(otpCodes.getOtpCode, [userId])
      if (!otp) return new ApiError(404, 'Code does not exist in database')

      return otp
    } catch (e) {
      throw e
    }
  }

  static saveOtp = async (
    userId: number,
    otp: string,
    expirationDate: Date,
  ) => {
    try {
      // try to update the OTP for the userId
      const result = await sqlQuest.oneOrNone(otpCodes.updateOtpCode, [
        otp,
        expirationDate,
        userId,
      ])

      // If no rows were affected, that means no OTP existed for this user, so we insert a new one
      if (!result) {
        return await sqlQuest.one(otpCodes.insertOtpCode, [
          userId,
          otp,
          expirationDate,
        ])
      }

      return result
    } catch (e) {
      throw e
    }
  }

  static verifyOtp = async (otp: string, userId: number) => {
    try {
      return await sqlQuest.oneOrNone(otpCodes.verifyOtpCode, [userId, otp])
    } catch (e) {
      throw e
    }
  }

  static setOtpToUsed = async (otp: string, userId: number) => {
    try {
      return await sqlQuest.oneOrNone(otpCodes.setOtpToUsed, [userId, otp])
    } catch (e) {
      throw e
    }
  }
}
