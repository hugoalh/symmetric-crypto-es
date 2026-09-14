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
interface SymmetricCryptorPayload {
	algorithm: SymmetricCryptoAlgorithm;
	key: CryptoKey;
}
const binCPCEPSymmetricCryptor: CPCEPBin<SymmetricCryptorPayload> = new CPCEPBin<SymmetricCryptorPayload>({
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
	#algorithm: SymmetricCryptoAlgorithm;
	#key: CryptoKey;
	/**
	 * Initialize; Only able to create new instance from {@linkcode createSymmetricCryptor}.
	 * @param {symbol} s CPCEP symbol.
	 */
	private constructor(s: symbol) {
		const {
			algorithm,
			key
		}: SymmetricCryptorPayload = binCPCEPSymmetricCryptor.getAndDelete(s);
		this.#algorithm = algorithm;
		this.#key = key;
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
		let algorithmPayload: AlgorithmIdentifier | AesCbcParams | AesCtrParams | AesGcmParams;
		let context: BufferSource;
		switch (this.#algorithm) {
			case "AES-CBC":
				algorithmPayload = {
					name: this.#algorithm,
					iv: data.slice(0, 16)
				};
				context = data.slice(16);
				break;
			case "AES-CTR":
				algorithmPayload = {
					name: this.#algorithm,
					counter: data.slice(0, 16),
					length: 64
				};
				context = data.slice(16);
				break;
			case "AES-GCM":
				algorithmPayload = {
					name: this.#algorithm,
					iv: data.slice(0, 12)
				};
				context = data.slice(12);
				break;
			default:
				throw new Error(`\`${this.#algorithm}\` is not a valid symmetric crypto algorithm! How did you get to here?`);
		}
		return new Uint8Array(await crypto.subtle.decrypt(algorithmPayload, this.#key, context));
	}
}
export interface SymmetricCryptorOptions {
	/**
	 * Algorithm of the symmetric crypto.
	 * @default {"AES-CBC"}
	 */
	algorithm?: SymmetricCryptoAlgorithm;
}
/**
 * **\[LEGACY\]**
 * 
 * Create new instance of the {@link SymmetricCryptor symmetric cryptor}.
 * 
 * **Edition:** webcrypto.1
 * @param {SymmetricCryptoKeyType} key Key.
 * @param {SymmetricCryptorOptions} [options={}] Options.
 * @returns {Promise<SymmetricCryptor>}
 */
export async function createSymmetricCryptor(key: SymmetricCryptoKeyType, options: SymmetricCryptorOptions = {}): Promise<SymmetricCryptor> {
	const { algorithm = "AES-CBC" }: SymmetricCryptorOptions = options;
	//deno-lint-ignore hugoalh/symbol-description -- Private symbol.
	const s: symbol = Symbol();
	//@ts-ignore I have no idea why this cause type error.
	const keyData: ArrayBuffer = await crypto.subtle.digest("SHA-256", (typeof key === "string") ? new TextEncoder().encode(key) : key);
	const keyCrypto: CryptoKey = await crypto.subtle.importKey("raw", keyData, { name: algorithm }, false, ["decrypt", "encrypt"]);
	binCPCEPSymmetricCryptor.set(s, {
		algorithm,
		key: keyCrypto
	});
	//@ts-expect-error Private constructor.
	return new SymmetricCryptor(s);
}
/**
 * **\[LEGACY\]**
 * 
 * Chain of the symmetric cryptors, multiple passwords based cryptor.
 * 
 * **Edition:** webcrypto.1
 */
export class SymmetricCryptorChain {
	get [Symbol.toStringTag](): string {
		return "SymmetricCryptorChain";
	}
	#chain: readonly SymmetricCryptor[];
	/**
	 * Initialize.
	 * @param {readonly SymmetricCryptor[]} cryptors Chain of the symmetric cryptors.
	 */
	constructor(cryptors: readonly SymmetricCryptor[]) {
		if (cryptors.length === 0) {
			throw new Error(`Parameter \`cryptors\` is not defined!`);
		}
		for (let index: number = 0; index < cryptors.length; index += 1) {
			if (!(cryptors[index] instanceof SymmetricCryptor)) {
				throw new TypeError(`Parameter \`cryptors[${index}]\` is not an instance of symmetric cryptor!`);
			}
		}
		this.#chain = [...cryptors];
	}
	/**
	 * Decrypt data.
	 * @param {Uint8Array} data Data that need to decrypt.
	 * @returns {Promise<Uint8Array>} A decrypted data.
	 */
	async decrypt(data: Uint8Array): Promise<Uint8Array> {
		let storage: Uint8Array = data;
		for (const cryptor of this.#chain.toReversed()) {
			storage = await cryptor.decrypt(storage);
		}
		return storage;
	}
}
