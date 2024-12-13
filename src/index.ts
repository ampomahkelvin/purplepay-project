import http from 'http'
import { Express } from 'express'
import { envValidatorSchema } from './shared/validators/env-validators'
import Env from './shared/utils/env'
import App from './config/express'
import { AppEnv } from './shared/enums'
import { configDotenv } from 'dotenv'
import { connectDB } from './config/database'

configDotenv()

async function main(App: (...args: any[]) => Express) {
  await connectDB()
  await Env.validateEnv(envValidatorSchema)

  const app = App()

  const server = http.createServer(app)

  const PORT = Env.get<number>('PORT') || 8080
  const NODE_ENV = Env.get<string>('NODE_ENV')

  NODE_ENV !== AppEnv.PRODUCTION &&
    server.on('listening', () => {
      console.log(`listening on http://localhost:${PORT}`)
    })

  server.listen(PORT)
}

main(App)
