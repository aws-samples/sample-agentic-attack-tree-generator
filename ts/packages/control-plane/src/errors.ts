export type ControlPlaneErrorCode =
  | 'already_exists'
  | 'conflict'
  | 'immutable_record'
  | 'invalid_input'
  | 'lease_lost'
  | 'not_found'
  | 'stale_revision';

export class ControlPlaneError extends Error {
  readonly code: ControlPlaneErrorCode;

  constructor(code: ControlPlaneErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'ControlPlaneError';
    this.code = code;
  }
}

export function alreadyExists(message: string): ControlPlaneError {
  return new ControlPlaneError('already_exists', message);
}

export function conflict(message: string, cause?: unknown): ControlPlaneError {
  return new ControlPlaneError('conflict', message, { cause });
}

export function immutableRecord(message: string): ControlPlaneError {
  return new ControlPlaneError('immutable_record', message);
}

export function invalidInput(message: string): ControlPlaneError {
  return new ControlPlaneError('invalid_input', message);
}

export function leaseLost(message: string, cause?: unknown): ControlPlaneError {
  return new ControlPlaneError('lease_lost', message, { cause });
}

export function notFound(message: string): ControlPlaneError {
  return new ControlPlaneError('not_found', message);
}

export function staleRevision(message: string): ControlPlaneError {
  return new ControlPlaneError('stale_revision', message);
}
