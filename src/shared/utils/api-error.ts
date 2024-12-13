import { ZodError } from 'zod'
import { Request, Response, NextFunction } from 'express'
import { StatusCodes, getReasonPhrase } from 'http-status-codes'
import Logger from '../../config/logger'

const logger = new Logger('ApiError')

export class ApiError extends Error {
  private readonly code: number
  private readonly details: number
  constructor(code: number, message: string, details?: any) {
    super(message)
    this.code = code
    this.details = details
  }

  get statusCode(): number {
    return this.code
  }

  get errorDetails(): number {
    return this.details
  }

  static appError(err: any, req: Request, res: Response, next: NextFunction) {
    let { code } = err
    const { details } = err

    const status = 'error'

    if (err instanceof ZodError) {
      const { message } = err

      code = StatusCodes.FORBIDDEN
      logger.error(`
            Zod validation error: 
            status - ${status}
            message - ${message}
            url - ${req.originalUrl}
            method - ${req.method}
            IP - ${req.ip}
            Error Stack - ${err.stack}
            `)

      const errorMessage: string[] = JSON.parse(message).map(
        (error: { message: string; path: string }) =>
          `${error.path}: ${error.message} \n`,
      )

      res.status(code).json({
        message: errorMessage.join(' '),
        status,
        type: getReasonPhrase(code),
      })
    }

    if (err instanceof ApiError || (code && typeof code === 'number')) {
      logger.error(`
            API error:
            status - error
            message - ${err.message}
            url - ${req.originalUrl}
            method - ${req.method}
            IP - ${req.ip}
            Error Stack - ${err.stack}
          `)
      console.log('API error')

      res.status(code || 500).json({
        message: err.message,
        status,
        type: getReasonPhrase(code || 500),
        error: details,
      })
    } else {
      return next(err)
    }
  }

  /**
   * Generic error response handler of internal and unhandled exceptions.
   *
   * @param  {Object}   err
   * @param  {Object}   req
   * @param  {Object}   res
   * @param  {Function} next
   */
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  static genericError(
    err: any,
    req: Request,
    res: Response,
    next: NextFunction,
  ) {
    const message = 'An error occurred, we are looking into it.'
    const status = 'error'
    const url = req.originalUrl

    logger.error(`
            Generic error:
            status - ${status}
            message - ${err.message} 
            url - ${url} 
            method - ${req.method} 
            IP - ${req.ip}
          `)

    res.status(err.status || 500).json({
      message,
      status,
      type: getReasonPhrase(StatusCodes.INTERNAL_SERVER_ERROR),
    })
    next()
  }
}
