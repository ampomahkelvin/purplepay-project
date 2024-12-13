/* Replace with your SQL commands */
CREATE TABLE IF NOT EXISTS "user" (
    "id" SERIAL PRIMARY KEY,
    "email" VARCHAR NOT NULL,
    "password" VARCHAR NOT NULL
);