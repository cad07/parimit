export class ParimitError extends Error {
  readonly code: string;
  readonly statusCode: number;
  readonly details?: unknown;

  constructor(code: string, message: string, statusCode = 400, details?: unknown) {
    super(message);
    this.name = "ParimitError";
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;
  }
}

export function asParimitError(error: unknown): ParimitError {
  if (error instanceof ParimitError) return error;
  return new ParimitError("INTERNAL_ERROR", "Unexpected internal error", 500);
}
