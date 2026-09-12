import { CPCEPBin } from "../../_cpcep_bin.ts";
export type SymmetricCryptoAlgorithm =
	| "AES-CBC"
	| "AES-CTR"
	| "AES-GCM";
export type SymmetricCryptoKeyType =
	| string
	| ArrayBuffer
	| DataView
	| Uint8Array
	| Uint16Array
	| Uint32Array
	| BigUint64Array;
export interface SymmetricCryptorKeyInput {
	/**
	 * Algorithm of the symmetric crypto.
	 * @default {"AES-CBC"}
	 */
	algorithm?: SymmetricCryptoAlgorithm;
	/**
	 * Key of the symmetric crypto.
	 */
	key: SymmetricCryptoKeyType;
}
interface SymmetricCryptorKeyPayload {
	algorithm: SymmetricCryptoAlgorithm;
	key: CryptoKey;
}
const binCPCEPSymmetricCryptor: CPCEPBin<SymmetricCryptorKeyPayload[]> = new CPCEPBin<SymmetricCryptorKeyPayload[]>({
	errorGetUndefined: new ReferenceError(`Unknown Symmetric Cryptor payload!`)
});
/**
 * **\[LEGACY\]**
 * 
 * Symmetric cryptor, a password based cryptor.
 * 
 * **Edition:** webcrypto.1
 */
export class SymmetricCryptor {
	get [Symbol.toStringTag](): string {
		return "SymmetricCryptor";
	}
	#payloads: readonly SymmetricCryptorKeyPayload[];
	/**
	 * Initialize; Only able to create new instance from {@linkcode createSymmetricCryptor}.
	 * @param {symbol} s CPCEP symbol.
	 */
	private constructor(s: symbol) {
		this.#payloads = binCPCEPSymmetricCryptor.getAndDelete(s);
	}
	/**
	 * Decrypt data.
	 * @param {Uint8Array} data Data that need to decrypt.
	 * @returns {Promise<Uint8Array>} A decrypted data.
	 */
	async decrypt(data: Uint8Array): Promise<Uint8Array> {
		if (data.length === 0) {
			return data;
		}
		let storage: Uint8Array = data;
		for (let index = this.#payloads.length - 1; index >= 0; index -= 1) {
			const {
				algorithm,
				key
			}: SymmetricCryptorKeyPayload = this.#payloads[index];
			let algorithmPayload: AlgorithmIdentifier | AesCbcParams | AesCtrParams | AesGcmParams;
			let context: BufferSource;
			switch (algorithm) {
				case "AES-CBC":
					algorithmPayload = {
						name: algorithm,
						iv: storage.slice(0, 16)
					};
					context = storage.slice(16);
					break;
				case "AES-CTR":
					algorithmPayload = {
						name: algorithm,
						counter: storage.slice(0, 16),
						length: 64
					};
					context = storage.slice(16);
					break;
				case "AES-GCM":
					algorithmPayload = {
						name: algorithm,
						iv: storage.slice(0, 12)
					};
					context = storage.slice(12);
					break;
				default:
					throw new Error(`\`${algorithm}\` is not a valid symmetric crypto algorithm! How did you get to here?`);
			}
			storage = new Uint8Array(await crypto.subtle.decrypt(algorithmPayload, key, context));
		}
		return storage;
	}
}
async function createCryptorKey(input: SymmetricCryptorKeyInput | SymmetricCryptoKeyType): Promise<SymmetricCryptorKeyPayload> {
	let algorithm: SymmetricCryptoAlgorithm;
	let key: SymmetricCryptoKeyType;
	if (
		typeof input === "string" ||
		input instanceof ArrayBuffer ||
		input instanceof DataView ||
		input instanceof Uint8Array ||
		input instanceof Uint16Array ||
		input instanceof Uint32Array ||
		input instanceof BigUint64Array
	) {
		algorithm = "AES-CBC";
		key = input;
	} else {
		algorithm = input.algorithm ?? "AES-CBC";
		key = input.key;
	}
	return {
		algorithm,
		//@ts-ignore I have no idea why this cause type error.
		key: await crypto.subtle.importKey("raw", await crypto.subtle.digest("SHA-256", (typeof key === "string") ? new TextEncoder().encode(key) : key), { name: algorithm }, false, ["decrypt", "encrypt"])
	};
}
export interface SymmetricCryptorOptions {
	/**
	 * Times of the crypto.
	 * @default {1}
	 */
	times?: number;
}
/**
 * **\[LEGACY\]**
 * 
 * Create new instance of the {@link SymmetricCryptor symmetric cryptor}.
 * 
 * **Edition:** webcrypto.1
 * @param {SymmetricCryptoKeyType} key Key.
 * @param {SymmetricCryptorOptions} [options] Options.
 * @returns {Promise<SymmetricCryptor>}
 */
export async function createSymmetricCryptor(key: SymmetricCryptoKeyType, options?: SymmetricCryptorOptions): Promise<SymmetricCryptor>;
/**
 * **\[LEGACY\]**
 * 
 * Create new instance of the {@link SymmetricCryptor symmetric cryptor}.
 * 
 * **Edition:** webcrypto.1
 * @param {SymmetricCryptorKeyInput} input Input of the key.
 * @param {SymmetricCryptorOptions} [options] Options.
 * @returns {Promise<SymmetricCryptor>}
 */
export async function createSymmetricCryptor(input: SymmetricCryptorKeyInput, options?: SymmetricCryptorOptions): Promise<SymmetricCryptor>;
/**
 * **\[LEGACY\]**
 * 
 * Create new instance of the {@link SymmetricCryptor symmetric cryptor}.
 * 
 * **Edition:** webcrypto.1
 * @param {(SymmetricCryptorKeyInput | SymmetricCryptoKeyType)[]} inputs Inputs of the key.
 * @returns {Promise<SymmetricCryptor>}
 */
export async function createSymmetricCryptor(inputs: (SymmetricCryptorKeyInput | SymmetricCryptoKeyType)[]): Promise<SymmetricCryptor>;
export async function createSymmetricCryptor(param0: SymmetricCryptorKeyInput | SymmetricCryptoKeyType | (SymmetricCryptorKeyInput | SymmetricCryptoKeyType)[], options: SymmetricCryptorOptions = {}): Promise<SymmetricCryptor> {
	const payloads: SymmetricCryptorKeyPayload[] = [];
	if (Array.isArray(param0)) {
		payloads.push(...await Promise.all(param0.map((input: SymmetricCryptorKeyInput | SymmetricCryptoKeyType): Promise<SymmetricCryptorKeyPayload> => {
			return createCryptorKey(input);
		})));
	} else {
		const cryptor: SymmetricCryptorKeyPayload = await createCryptorKey(param0);
		if (typeof options.times === "undefined") {
			payloads.push(cryptor);
		} else {
			if (!(Number.isSafeInteger(options.times) && options.times >= 1)) {
				throw new TypeError(`Argument \`options.times\` is not a number which is integer, safe, and >= 1!`);
			}
			for (let index: number = 0; index < options.times; index += 1) {
				payloads.push(cryptor);
			}
		}
	}
	if (payloads.length > 0) {
		//deno-lint-ignore hugoalh/symbol-description -- Private symbol.
		const s: symbol = Symbol();
		binCPCEPSymmetricCryptor.set(s, payloads);
		//@ts-expect-error Private constructor.
		return new SymmetricCryptor(s);
	}
	throw new Error(`Parameter \`inputs\` is not defined!`);
}
