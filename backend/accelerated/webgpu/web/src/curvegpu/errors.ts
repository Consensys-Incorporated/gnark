/**
 * Base class for all errors thrown by the curvegpu library.
 */
export class CurveGPUError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CurveGPUError";
  }
}

/**
 * Thrown when WebGPU is not available in the current environment, or when
 * the adapter/device cannot be acquired.
 */
export class CurveGPUNotSupportedError extends CurveGPUError {
  constructor(message: string) {
    super(message);
    this.name = "CurveGPUNotSupportedError";
  }
}

/**
 * Thrown when the GPU device is lost while an operation is in progress,
 * or exposed on the context so callers can subscribe to device-loss events.
 */
export class CurveGPUDeviceLostError extends CurveGPUError {
  constructor(message: string) {
    super(message);
    this.name = "CurveGPUDeviceLostError";
  }
}

/**
 * Thrown when a shader file cannot be fetched or a required section is missing.
 */
export class CurveGPUShaderError extends CurveGPUError {
  constructor(message: string) {
    super(message);
    this.name = "CurveGPUShaderError";
  }
}
