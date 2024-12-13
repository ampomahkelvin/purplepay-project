const getUser = `
SELECT * FROM "user" WHERE email = $1
`

const updatePassword = `
UPDATE "user" SET "password" = $1 WHERE "email" = $2
`

const getOtpCode = `
SELECT * from "otpCode" where "userId" = $1
`

// Update OTP if it exists
const updateOtpCode = `
    UPDATE "otpCode" 
    SET "otp" = $1, "expiresAt" = $2, "isVerified" = false, "isUsed" = false
    WHERE "userId" = $3
    RETURNING *
`

// Insert OTP if no record exists for the user
const insertOtpCode = `
  INSERT INTO "otpCode" ("userId", "otp", "expiresAt")
  VALUES ($1, $2, $3)
  RETURNING *
`

const verifyOtpCode = `
    UPDATE "otpCode"
    SET "isVerified" = true
    WHERE "userId" = $1 AND "otp" = $2 
    RETURNING * 
`

const setOtpToUsed = `
    UPDATE "otpCode"
    SET "isUsed" = true
    WHERE "userId" = $1 AND "otp" = $2 
    RETURNING *
`

export const userQueries = {
  getUser,
  updatePassword,
}

export const otpCodes = {
  getOtpCode,
  insertOtpCode,
  updateOtpCode,
  verifyOtpCode,
  setOtpToUsed,
}
