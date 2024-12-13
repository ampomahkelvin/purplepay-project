import sinon from 'sinon'
import { sqlQuest } from '../../../config/database'
import { SqlQuest } from '@bitreel/sql-quest'
import { OtpRepository, UserRepository } from '../repositories'
import { ApiError } from '../../../shared/utils/api-error'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import { UserService } from '../services'
import Env from '../../../shared/utils/env'
import { describe } from 'mocha'
import SendEmail from '../../../services/mail-service'
const chai = require('chai')
const sinonChai = require('sinon-chai')
import * as crypto from 'crypto'

chai.use(sinonChai)
const { expect } = chai

describe('UserRepository', () => {
  let sqlQuestStub: sinon.SinonStubbedInstance<SqlQuest>
  beforeEach(() => {
    // stub db
    sqlQuestStub = sinon.stub(sqlQuest)
  })

  afterEach(() => {
    // restore
    sinon.restore()
  })

  describe('Get user', async () => {
    it('should get user if found', async () => {
      const mockUser = { id: 1, email: 'test@example.com' }
      sqlQuestStub.oneOrNone.resolves(mockUser)

      const result = await UserRepository.getUser('test@example.com')
      expect(result).to.deep.equal(mockUser)
      sinon.assert.calledWith(sqlQuestStub.oneOrNone, sinon.match.string, [
        'test@example.com',
      ])
    })

    it('should throw ApiError if user not found', async () => {
      sqlQuestStub.oneOrNone.resolves(null)

      try {
        await UserRepository.getUser('test@example.com')
      } catch (e) {
        expect(e).to.be.instanceof(ApiError)
        expect(e.status).to.equal(404)
        expect(e.message).to.equal('User not found')
      }
    })

    it('should throw an error if database query fails', async function () {
      sqlQuestStub.oneOrNone.rejects(new Error('Database error'))

      try {
        await UserRepository.getUser('test@example.com')
      } catch (err) {
        expect(err.message).to.equal('Database error')
      }
    })
  })

  describe('Update Password', () => {
    it('update password', async () => {
      sqlQuestStub.none.resolves()

      await UserRepository.updatePassword('newPassword', 'test@example.com')
      sinon.assert.calledWith(sqlQuestStub.none, sinon.match.string, [
        'newPassword',
        'test@example.com',
      ])
    })

    it('should throw an error if query fails', async () => {
      sqlQuestStub.none.rejects(new Error('Database Error'))
      try {
        await UserRepository.updatePassword('newPassword', 'test@example.com')
      } catch (e) {
        expect(e.message).to.equal('Database Error')
      }
    })
  })
})

describe('OtpRepository', () => {
  let sqlQuestStub: sinon.SinonStubbedInstance<SqlQuest>
  beforeEach(() => {
    // stub db
    sqlQuestStub = sinon.stub(sqlQuest)
  })

  afterEach(() => {
    // restore
    sinon.restore()
  })

  describe('Get Otp', () => {
    it('should successfully get otp', async () => {
      const mockOtp = {
        otp: '123ABC',
        expirationDate: new Date(),
        isUsed: false,
        isVerified: false,
        userId: 1,
      }
      sqlQuestStub.oneOrNone.resolves(mockOtp)

      const result = await OtpRepository.getOtp(1)
      expect(result).to.deep.equal(mockOtp)
      sinon.assert.calledWith(sqlQuestStub.oneOrNone, sinon.match.string, [1])
    })

    it('should throw an ApiError if otp not found', async function () {
      sqlQuestStub.oneOrNone.resolves(null)

      try {
        await OtpRepository.getOtp(1)
      } catch (err) {
        expect(err).to.be.an.instanceof(ApiError)
        expect(err.status).to.equal(404)
        expect(err.message).to.equal('Otp does not exist in database')
      }
    })

    it('should throw an error if db query fails', async function () {
      sqlQuestStub.oneOrNone.rejects(new Error('Database error'))

      try {
        await OtpRepository.getOtp(1)
      } catch (err) {
        expect(err.message).to.equal('Database error')
      }
    })
  })

  describe('Save otp', () => {
    it('should successfully save otp', async () => {
      const mockOtp = {
        otp: '123ABC',
        expirationDate: new Date(),
        isUsed: false,
        isVerified: false,
        userId: 1,
      }
      sqlQuestStub.oneOrNone.resolves(mockOtp)

      const result = await OtpRepository.saveOtp(1, '123456', new Date())

      expect(result).to.deep.equal(mockOtp)
      sinon.assert.calledWith(sqlQuestStub.oneOrNone, sinon.match.string, [
        '123456',
        sinon.match.instanceOf(Date),
        1,
      ])
    })

    it('should insert otp if no existing OTP for the user', async function () {
      const mockResult = { otp: '123456', expirationDate: new Date() }
      sqlQuestStub.oneOrNone.resolves(null)
      sqlQuestStub.one.resolves(mockResult)

      const result = await OtpRepository.saveOtp(1, '123456', new Date())

      expect(result).to.deep.equal(mockResult)
      sinon.assert.calledWith(sqlQuestStub.one, sinon.match.string, [
        1,
        '123456',
        sinon.match.instanceOf(Date),
      ])
    })

    it('should throw an error if db query fails', async function () {
      sqlQuestStub.oneOrNone.rejects(new Error('Database error'))

      try {
        await OtpRepository.saveOtp(1, '123456', new Date())
      } catch (err) {
        expect(err.message).to.equal('Database error')
      }
    })
  })

  describe('verifyOtp', function () {
    it('should return otp if found and valid', async function () {
      const mockOtp = { otp: '123456' }
      sqlQuestStub.oneOrNone.resolves(mockOtp)

      const result = await OtpRepository.verifyOtp('123456', 1)

      expect(result).to.deep.equal(mockOtp)
      sinon.assert.calledWith(sqlQuestStub.oneOrNone, sinon.match.string, [
        1,
        '123456',
      ])
    })

    it('should throw an error if otp verification fails', async function () {
      sqlQuestStub.oneOrNone.resolves(null)

      try {
        await OtpRepository.verifyOtp('123456', 1)
      } catch (err) {
        expect(err.message).to.equal('Otp not found')
      }
    })
  })

  describe('setOtpToUsed', function () {
    it('should mark OTP as used successfully', async function () {
      const mockResult = { otp: '123456' }
      sqlQuestStub.oneOrNone.resolves(mockResult)

      const result = await OtpRepository.setOtpToUsed('123456', 1)

      expect(result).to.deep.equal(mockResult)
      sinon.assert.calledWith(sqlQuestStub.oneOrNone, sinon.match.string, [
        1,
        '123456',
      ])
    })

    it('should throw an error if database query fails', async function () {
      sqlQuestStub.oneOrNone.rejects(new Error('Database error'))

      try {
        await OtpRepository.setOtpToUsed('123456', 1)
      } catch (err) {
        expect(err.message).to.equal('Database error')
      }
    })
  })
})

// SERVICES TESTS
describe('UserService', () => {
  let sendEmailStub: any
  let getUserStub: any
  let updatePasswordSub: any
  let getOtpStub: any
  let bcryptCompareStub: any
  let bcryptHashStub: any
  let setOtpToUsedStub: any

  beforeEach(() => {
    sendEmailStub = sinon.stub(SendEmail, 'sendOtp')
    getUserStub = sinon.stub(UserRepository, 'getUser')
    updatePasswordSub = sinon.stub(UserRepository, 'updatePassword')
    getOtpStub = sinon.stub(OtpRepository, 'getOtp')
    bcryptCompareStub = sinon.stub(bcrypt, 'compare')
    bcryptHashStub = sinon.stub(bcrypt, 'hash')
    setOtpToUsedStub = sinon.stub(OtpRepository, 'setOtpToUsed')
  })

  afterEach(() => {
    // restore
    sinon.restore()
  })

  describe('LoginUser', () => {
    it('should successfully login user and return user and token', async () => {
      const mockUser = {
        id: 1,
        email: 'test@example.com',
        password: 'password',
      }
      const mockJwt = 'mockjwt'
      getUserStub.resolves(mockUser)
      bcryptCompareStub.resolves(true)
      sinon.stub(jwt, 'sign').resolves(mockJwt)

      const result = await UserService.loginUser('test@example.com', 'password')
      const token = await result.token

      expect(result).to.have.property('user')
      expect(result).to.have.property('token')
      expect(token).to.equal(mockJwt)
    })

    it('should throw error if password is incorrect', async () => {
      const mockUser = {
        id: 1,
        email: 'test@example.com',
        password: 'password',
      }
      getUserStub.resolves(mockUser)
      bcryptCompareStub.resolves(false)

      try {
        await UserService.loginUser('test@example.com', 'wrong-password')
      } catch (err) {
        expect(err).to.be.an.instanceof(ApiError)
        expect(err.code).to.equal(400)
        expect(err.message).to.equal('Credentials are incorrect')
      }
    })

    it('should throw error if JWT secret is missing', async function () {
      const mockUser = {
        id: 1,
        email: 'test@example.com',
        password: 'password',
      }
      getUserStub.resolves(mockUser)
      bcryptCompareStub.resolves(true)
      sinon.stub(Env, 'get').returns(null) // No secret

      try {
        await UserService.loginUser('test@example.com', 'password')
      } catch (err) {
        expect(err).to.be.an.instanceof(ApiError)
        expect(err.code).to.equal(400)
        expect(err.message).to.equal('Jwt Secret missing')
      }
    })
  })

  describe('SendResetPasswordEmail', () => {
    afterEach(() => {
      // restore
      sinon.restore()
    })

    it('should send email successfully', async () => {
      const mockUser = { id: 1, email: 'test@example.com' }
      // const otpCode = 'ABC123'

      getUserStub.resolves(mockUser)

      sinon.stub(OtpRepository, 'saveOtp').resolves()

      sendEmailStub.resolves('Email sent')

      const result =
        await UserService.sendResetPasswordEmail('test@example.com')

      expect(result).to.equal('Email sent')
      sinon.assert.calledWith(sendEmailStub, sinon.match.string, mockUser.email)
    })

    it('should throw error if user does not exist', async function () {
      getUserStub.resolves(null)

      try {
        await UserService.sendResetPasswordEmail('nonexistent@example.com')
      } catch (err) {
        expect(err).to.be.an.instanceof(ApiError)
        expect(err.code).to.equal(404)
        expect(err.message).to.equal('User does not exist')
      }
    })
  })

  describe('verifyOtp', function () {
    afterEach(() => {
      // restore
      sinon.restore()
    })
    it('should verify OTP successfully', async function () {
      const mockUser = { id: 1, email: 'test@example.com' }
      const otpCode = 'ABC123'
      const hashedOtp = crypto.createHash('sha256').update(otpCode).digest('hex')

      const mockOtp = {
        otp: hashedOtp,
        expiresAt: new Date(Date.now() + 10 * 60 * 1000),
        isVerified: false,
        isUsed: false,
      }
      getUserStub.resolves(mockUser)
      getOtpStub.resolves(mockOtp)

      const verifyOtpStub = sinon.stub(OtpRepository, 'verifyOtp').resolves(mockOtp)
      const result = await UserService.verifyOtp('test@example.com', otpCode)

      expect(result).to.deep.equal(mockOtp)
      sinon.assert.calledOnce(verifyOtpStub)
    })

    it('should throw error if OTP is invalid', async function () {
      const mockUser = { id: 1, email: 'test@example.com' }
      getUserStub.resolves(mockUser)
      const otpCode = 'ABC123'
      const hashedOtp = 'hashed-otp'
      const mockOtp = {
        otp: hashedOtp,
        expiresAt: new Date(Date.now() + 10 * 60 * 1000),
        isVerified: false,
      }
      getOtpStub.resolves(mockOtp)

      try {
        await UserService.verifyOtp('test@example.com', otpCode)
      } catch (err) {
        expect(err).to.be.an.instanceof(ApiError)
        expect(err.code).to.equal(400)
        expect(err.message).to.equal('Invalid OTP')
      }
    })
  })

  describe('resetPassword', function () {
    it('should reset the password successfully', async function () {
      const mockUser = {
        id: 1,
        email: 'test@example.com',
        password: 'hashed-password',
      }
      const newPassword = 'newpassword'
      getUserStub.resolves(mockUser)
      getOtpStub.resolves({
        otp: 'hashed-otp',
        isVerified: true,
        isUsed: false,
      })
      bcryptCompareStub.resolves(false)
      bcryptHashStub.resolves('new-hashed-password')
      updatePasswordSub.resolves(mockUser)
      setOtpToUsedStub.resolves()

      const result = await UserService.resetPassword(
        'test@example.com',
        newPassword,
      )

      expect(result).to.deep.equal(mockUser)
      sinon.assert.calledWith(
        updatePasswordSub,
        'new-hashed-password',
        'test@example.com',
      )
      sinon.assert.calledOnce(setOtpToUsedStub)
    })

    it('should throw error if OTP is not verified', async function () {
      const mockUser = {
        id: 1,
        email: 'test@example.com',
        password: 'hashed-password',
      }
      getUserStub.resolves(mockUser)
      getOtpStub.resolves({
        otp: 'hashed-otp',
        isVerified: false,
        isUsed: false,
      })

      try {
        await UserService.resetPassword('test@example.com', 'newpassword')
      } catch (err) {
        expect(err).to.be.an.instanceof(ApiError)
        expect(err.code).to.equal(400)
        expect(err.message).to.equal('Otp not verified or incorrect')
      }
    })
  })
})
