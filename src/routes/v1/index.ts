import express from 'express'
import UserRouter from '../../modules/user/user.routes'

const appRouter = express.Router()

appRouter.use('/user', UserRouter)

export const router = appRouter
