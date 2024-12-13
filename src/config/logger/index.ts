import Env from '../../shared/utils/env'
import winston from 'winston'
// import { Papertrail } from 'winston-papertrail'

import DailyRotateFile from 'winston-daily-rotate-file'
import appRootPath from 'app-root-path'

const logFormat = winston.format.combine(
  winston.format.timestamp(),
  winston.format.errors({ stack: true }),
  winston.format.colorize({ all: true }),
  winston.format.printf((info) => {
    const { level, message, label, timestamp } = info

    const logTimestamp =
      typeof timestamp === 'string' || typeof timestamp === 'number'
        ? new Date(timestamp).toUTCString()
        : new Date().toUTCString()
    return `[${logTimestamp}]: ${label} : - ${level}: ${message}`
  }),
)

const infoLogRotationTransport = new DailyRotateFile({
  filename: `${appRootPath}//logs//info`,
  datePattern: 'YYYY-MM-DD-HH:MM',
  zippedArchive: true,
  maxSize: '10m',
  maxFiles: '80d',
  level: 'info',
  extension: '.log',
  handleExceptions: true,
})

const errorLogRotationTransport = new DailyRotateFile({
  filename: `${appRootPath}//logs//error`,
  datePattern: 'YYYY-MM-DD-HH:MM',
  zippedArchive: true,
  maxSize: '10m',
  maxFiles: '80d',
  level: 'error',
  extension: '.log',
  handleExceptions: true,
})

// const paperTrailTransport = new Papertrail({
//   host: `${Env.get<string>('PAPERTRAIL_URL')}`.split('\r')[0],
//   port: Env.get<string>('PAPERTRAIL_PORT'),
//   program: `${Env.get<string>('APP_NAME')}`, // optional, name of your application
// })
const loggerInfo = (env: string) => {
  let logger
  switch (env) {
    case 'production':
      logger = winston.createLogger({
        level: 'info',
        format: logFormat,
        transports: [
          infoLogRotationTransport,
          errorLogRotationTransport,
          // paperTrailTransport,
        ],
        exitOnError: false,
      })
      break
    case 'development':
      logger = winston.createLogger({
        level: 'info',
        format: logFormat,
        transports: [
          infoLogRotationTransport,
          errorLogRotationTransport,
          new winston.transports.Console(),
          // paperTrailTransport,
        ],
        exitOnError: false,
      })
      break
    case 'test':
      logger = winston.createLogger({
        level: 'info',
        format: logFormat,
        transports: [
          infoLogRotationTransport,
          errorLogRotationTransport,
          new winston.transports.Console(),
        ],
        exitOnError: false,
      })
      break
    default:
      logger = winston.createLogger({
        level: 'info',
        format: logFormat,
        transports: [
          infoLogRotationTransport,
          errorLogRotationTransport,
          new winston.transports.Console(),
          // paperTrailTransport,
        ],
        exitOnError: false,
      })
  }

  return logger
}

const logger = loggerInfo(Env.get<string>('NODE_ENV'))
export default class Logger {
  constructor(private readonly defaultContext: string) {}
  public static log(message: string | any, context?: string): void {
    logger.info(message, {
      label: `${Env.get<string>('APP_NAME')}::${context}`,
    })
  }

  public static error(message: string, err: any): void {
    logger.error(message, err)
  }

  public log(message: string | any, context?: string) {
    const labelFormat = `${Env.get<string>('APP_NAME')}::${
      context ?? this.defaultContext
    }`
    logger.info(message, { label: labelFormat })
  }

  public error(message: string, err: any = null): void {
    logger.error(message, err)
  }
}
