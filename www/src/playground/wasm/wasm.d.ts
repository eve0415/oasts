declare module "*.wasm" {
	/**
	 * Workers compile imported WebAssembly at deploy time and hand the route a ready module;
	 * compiling from bytes at runtime is not permitted there.
	 */
	const module: WebAssembly.Module;
	export default module;
}
