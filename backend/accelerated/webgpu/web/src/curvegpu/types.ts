export type CurveID = "bn254" | "bls12_381" | "bls12_377";
export type FieldID = "fr" | "fp";

/**
 * Host/GPU layout of one field element. Byte sizes for each curve live in
 * the curve data table (`curves.ts`); see `shapeFor`.
 */
export interface FieldShape {
  curve: CurveID;
  field: FieldID;
  hostWords: 4 | 6;
  gpuLimbs: 8 | 12;
  byteSize: 32 | 48;
}

export type U32x8 = Uint32Array & { length: 8 };
export type U32x12 = Uint32Array & { length: 12 };
