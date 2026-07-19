/**
 * Typed configuration surface for `oasts.config.ts` files.
 *
 * `UserConfig` is a hand-authored mirror of the Rust schema-version-1 config
 * (`crates/oasts-core/src/config.rs`); the Rust core revalidates every
 * value, so drift here can only reject valid configs at type-check time,
 * never admit invalid ones at runtime.
 */

/** Exactly one local path or HTTP(S) URL. */
export type Input = { path: string; url?: never } | { url: string; path?: never };

/** Boolean shorthand or an artifact option block. */
export type ArtifactSetting = boolean | { enabled?: boolean; directory?: string };

/** Artifact selectors. Types default on; everything else defaults off. */
export interface ArtifactsConfig {
  types?: ArtifactSetting;
  client?: ArtifactSetting;
  zod?: ArtifactSetting;
  validators?: ArtifactSetting;
  tanstack?: ArtifactSetting;
  msw?: ArtifactSetting;
}

/** Type representation options. */
export interface TypesConfig {
  enum?: "literal" | "const";
  enumExtensions?: "accept" | "reject";
  dateTime?: "string" | "date" | "temporal";
  date?: "string" | "temporal";
  readonly?: boolean;
}

/** Declaration and file naming options. */
export interface NamingConfig {
  fileCase?: "kebab" | "snake" | "camel" | "pascal" | "preserve";
  typeCase?: string;
  propertyCase?: string;
  operationCase?: "camel" | "preserve";
  enumMemberCase?: "pascal" | "camel" | "screamingSnake" | "preserve";
  typePrefix?: string;
  typeSuffix?: string;
}

/** Schema-derived TSDoc switches. */
export interface DocumentationConfig {
  enabled?: boolean;
  summary?: boolean;
  description?: boolean;
  deprecated?: boolean;
  examples?: boolean;
  constraints?: boolean;
}

/** Generated module mechanics. */
export interface EmitConfig {
  runtimeDirectory?: string;
  importExtension?: string;
  banner?: string[];
  format?: string;
}

/** Local document/ref trust boundary. */
export interface LocalTrustConfig {
  allowPaths?: string[];
}

/** Document-graph size and depth bounds. */
export interface LimitsConfig {
  maxDocumentBytes?: number;
  maxTotalBytes?: number;
  maxDocuments?: number;
  maxRefDepth?: number;
}

/** The schema-version-1 single-spec configuration. */
export interface UserConfig {
  $schema?: string;
  schemaVersion: 1;
  workspaceRoot?: string;
  input: Input;
  output: string;
  namespace?: string;
  artifacts?: ArtifactsConfig;
  types?: TypesConfig;
  naming?: NamingConfig;
  documentation?: DocumentationConfig;
  emit?: EmitConfig;
  local?: LocalTrustConfig;
  limits?: LimitsConfig;
}

/** Identity function providing `UserConfig` typing for script configs. */
export function defineConfig(config: UserConfig): UserConfig {
  return config;
}
