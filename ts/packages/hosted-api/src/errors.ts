import { ControlPlaneError } from '@threatforest/control-plane';

export class HostedApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly expose: boolean;

  constructor(
    status: number,
    code: string,
    message: string,
    options: ErrorOptions & { expose?: boolean } = {},
  ) {
    super(message, options);
    this.name = 'HostedApiError';
    this.status = status;
    this.code = code;
    this.expose = options.expose ?? status < 500;
  }
}

export function badRequest(message: string, code = 'invalid_request'): HostedApiError {
  return new HostedApiError(400, code, message);
}

export function unauthorized(message = 'Authentication is required.'): HostedApiError {
  return new HostedApiError(401, 'unauthorized', message);
}

export function forbidden(message = 'Request origin verification failed.'): HostedApiError {
  return new HostedApiError(403, 'forbidden', message);
}

export function notFound(message: string): HostedApiError {
  return new HostedApiError(404, 'not_found', message);
}

export function conflict(message: string, code = 'conflict'): HostedApiError {
  return new HostedApiError(409, code, message);
}

export function gone(message: string, code = 'hosted_unsupported'): HostedApiError {
  return new HostedApiError(410, code, message);
}

export function payloadTooLarge(message: string): HostedApiError {
  return new HostedApiError(413, 'payload_too_large', message);
}

export function uriTooLong(message: string): HostedApiError {
  return new HostedApiError(414, 'uri_too_long', message);
}

export function unprocessable(message: string): HostedApiError {
  return new HostedApiError(422, 'invalid_input', message);
}

export function tooManyRequests(message: string): HostedApiError {
  return new HostedApiError(429, 'rate_limited', message);
}

export function mapError(error: unknown): HostedApiError {
  if (error instanceof HostedApiError) {
    return error;
  }
  if (error instanceof ControlPlaneError) {
    const statusByCode: Record<ControlPlaneError['code'], number> = {
      already_exists: 409,
      conflict: 409,
      immutable_record: 409,
      invalid_input: 422,
      lease_lost: 409,
      not_found: 404,
      stale_revision: 409,
    };
    return new HostedApiError(statusByCode[error.code], error.code, error.message, {
      cause: error,
    });
  }
  if (
    error instanceof SyntaxError ||
    (typeof error === 'object' &&
      error !== null &&
      'name' in error &&
      (error as { name: unknown }).name === 'ZodError')
  ) {
    return unprocessable(error instanceof Error ? error.message : 'Request validation failed.');
  }
  return new HostedApiError(500, 'internal_error', 'Internal server error.', {
    cause: error,
    expose: false,
  });
}
