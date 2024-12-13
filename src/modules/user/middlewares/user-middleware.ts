import { NextFunction, Request, Response } from 'express'
import { ApiError } from '../../../shared/utils/api-error'
import { ZodType } from 'zod'

export class ValidationMiddleware {
  static readonly validateRequest = <T extends ZodType<any, any, any>>(
    schema: T,
  ) => {
    return (req: Request, res: Response, next: NextFunction) => {
      schema
        .parseAsync({ ...req.query, ...req.body })
        .then(() => {
          return next()
        })
        .catch((error) => {
          return ApiError.appError(error, req, res, next)
        })
    }
  }
}
