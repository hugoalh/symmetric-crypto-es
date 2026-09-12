export interface CPCEPBinOptions {
	errorGetUndefined?: Error;
}
export class CPCEPBin<T> {
	#bin: Map<symbol, T> = new Map<symbol, T>();
	#errorGetUndefined: Error;
	constructor(options: CPCEPBinOptions = {}) {
		const {
			errorGetUndefined = new ReferenceError(`Unknown value!`)
		}: CPCEPBinOptions = options;
		this.#errorGetUndefined = errorGetUndefined;
	}
	get(s: symbol): T {
		const value: T | undefined = this.#bin.get(s);
		if (typeof value === "undefined") {
			throw this.#errorGetUndefined;
		}
		return value;
	}
	getAndDelete(s: symbol): T {
		const value: T | undefined = this.#bin.get(s);
		this.#bin.delete(s);
		if (typeof value === "undefined") {
			throw this.#errorGetUndefined;
		}
		return value;
	}
	set(s: symbol, value: T): void {
		this.#bin.set(s, value);
	}
}
