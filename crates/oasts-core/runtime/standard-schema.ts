// Relative `.ts` import suffixes are contractual: the Rust embedding engine rewrites them to the configured emit extension.
export interface Issue {
  readonly message: string;
  readonly path?: ReadonlyArray<PropertyKey | PathSegment>;
}

export interface PathSegment {
  readonly key: PropertyKey;
}
