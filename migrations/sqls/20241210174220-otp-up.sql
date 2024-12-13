/* Replace with your SQL commands */
CREATE TABLE IF NOT EXISTS  "otpCode" (
    "id" SERIAL PRIMARY KEY,
    "userId" INT,
    "otp" VARCHAR(255),
    "expiresAt" TIMESTAMP,
    "isVerified" BOOLEAN NOT NULL DEFAULT FALSE,
    FOREIGN KEY ("userId") REFERENCES "user"(id) ON DELETE CASCADE,
    "isUsed" BOOLEAN DEFAULT FALSE NOT NULL
);
