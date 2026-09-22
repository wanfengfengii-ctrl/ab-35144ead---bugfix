'use strict';
// Structured application errors. Every error thrown by the service layer is an
// ApiError carrying a stable machine-readable code and an HTTP status; the HTTP
// layer renders them as {"error":{"code","message","details"}}.

export class ApiError extends Error {
  /**
   * @param {string} code stable machine code
   * @param {number} status HTTP status
   * @param {string} message human-readable message
   * @param {Record<string, unknown>} [details]
   */
  constructor(code, status, message, details = undefined) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

export const errors = {
  validation: (msg, details) => new ApiError('VALIDATION_ERROR', 400, msg, details),
  unauthorized: (msg = 'unauthorized') => new ApiError('UNAUTHORIZED', 401, msg),
  notFound: (msg, details) => new ApiError('NOT_FOUND', 404, msg, details),
  deviceNotFound: (id) =>
    new ApiError('DEVICE_NOT_FOUND', 404, `device ${id} is not registered`, { deviceId: id }),
  conflict: (code, msg, details) => new ApiError(code, 409, msg, details),
  gone: (msg, details) => new ApiError('GONE', 410, msg, details),
  payloadTooLarge: (msg, details) => new ApiError('PAYLOAD_TOO_LARGE', 413, msg, details),
  internal: (msg = 'internal error') => new ApiError('INTERNAL_ERROR', 500, msg),
};
