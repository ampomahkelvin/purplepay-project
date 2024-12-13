import express, { Express, Request, Response } from 'express'
import cors from 'cors'
import { router, ROUTES } from '../routes/route'
import { ApiError } from '../shared/utils/api-error'
// import path from 'path'

export default function App(): Express {
  const app = express()

  const corsOptions = {
    origin: '*',
    credentials: true,
  }
  app.use(cors(corsOptions))
  app.use(express.json())
  app.use(express.urlencoded({ extended: true }))

  app.get('/', (_: Request, res: Response) => {
    res.send('Project Express + TypeScript Server')
  })

  app.use(ROUTES.V1_PATH, router)

  app.use(ApiError.appError)
  app.use(ApiError.genericError)

  return app
}
