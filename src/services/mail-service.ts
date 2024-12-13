import { Client, SendEmailV3_1, LibraryResponse } from 'node-mailjet'
import Env from '../shared/utils/env'

const mailjet = new Client({
  apiKey: Env.get<string>('MAILJET_KEY'),
  apiSecret: Env.get<string>('MAILJET_SECRET'),
})

export default class SendEmail {
  static sendOtp = async (otp: string, recipientEmail: string) => {
    const data: SendEmailV3_1.Body = {
      Messages: [
        {
          From: {
            Email: 'boatengampomah.kelvin@gmail.com',
          },
          To: [
            {
              Email: recipientEmail,
            },
          ],
          TemplateLanguage: true,
          TemplateErrorReporting: {
            Email: 'admin@yourapp.com',
            Name: 'Reporter',
          },
          Subject: 'Password Reset Request',
          HTMLPart: `
        <h3>Reset Your Password</h3>
        <p>Dear Whatever your name is,</p>
        <p>You forgot your password. Do not let that happen again:</p>
        <p>Your OTP code is: <strong>${otp}</strong></p>
      `,
          TextPart: ` Reset Your Password
        Dear Whatever your name is,
        
        You forgot your password. Do not let that happen again:
        
        Your OTP code is: ${otp} `,
        },
      ],
    }

    try {
      const result: LibraryResponse<SendEmailV3_1.Response> = await mailjet
        .post('send', { version: 'v3.1' })
        .request(data)
      const { Status } = result.body.Messages[0]

      if (Status !== 'success') throw new Error('Failed to send email')
    } catch (e) {
      throw e
    }
  }

  static sendResetSuccessful = async (recipientEmail: string) => {
    const data: SendEmailV3_1.Body = {
      Messages: [
        {
          From: {
            Email: 'boatengampomah.kelvin@gmail.com',
          },
          To: [
            {
              Email: recipientEmail,
            },
          ],
          TemplateLanguage: true,
          TemplateErrorReporting: {
            Email: 'admin@yourapp.com',
            Name: 'Reporter',
          },
          Subject: 'Password Reset Successful',
          HTMLPart: `
        <h3>Password Reset Successful</h3>
        <p>Dear Whatever your name is,</p>
        <p>You have successfully reset your password. Do not forget it again :(</p>
        
      `,
          TextPart: ` Password Reset Successful
        Dear Whatever your name is,
        
        You have successfully reset your password. Do not forget it again :(
        `,
        },
      ],
    }

    try {
      const result: LibraryResponse<SendEmailV3_1.Response> = await mailjet
        .post('send', { version: 'v3.1' })
        .request(data)
      const { Status } = result.body.Messages[0]

      if (Status !== 'success') throw new Error('Failed to send email')
    } catch (e) {
      throw e
    }
  }
}
