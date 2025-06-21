import { Buffer } from "node:buffer";
export type SymmetricCryptorAlgorithm =
	| "AES-CBC"
	| "AES-CTR"
	| "AES-GCM";
const algorithms: readonly SymmetricCryptorAlgorithm[] = [
	"AES-CBC",
	"AES-CTR",
	"AES-GCM"
];
/**
 * Type of the key of the symmetric cryptor.
 */
export type SymmetricCryptorKeyType =
	| string
	| ArrayBuffer
	| BigUint64Array
	| DataView
	| Uint8Array
	| Uint16Array
	| Uint32Array;
/**
 * Key input of the symmetric cryptor.
 */
export interface SymmetricCryptorKeyInput {
	/**
	 * Algorithm of the symmetric cryptor.
	 * @default {"AES-CBC"}
	 */
	algorithm?: SymmetricCryptorAlgorithm;
	/**
	 * Key of the symmetric cryptor.
	 */
	key: SymmetricCryptorKeyType;
}
export type SymmetricCryptorCipherTextDecoder = (data: string) => Uint8Array | Promise<Uint8Array>;
export type SymmetricCryptorCipherTextEncoder = (data: Uint8Array) => string | Promise<string>;
export type SymmetricCryptorCipherTextCoderDefault =
	| "base64"
	| "base64url";
const cipherTextCodersDefault: readonly SymmetricCryptorCipherTextCoderDefault[] = [
	"base64",
	"base64url"
];
export interface SymmetricCryptorCipherTextCoderOptions {
	/**
	 * Decoder of the stringify cipher text, must be pair with property {@linkcode encoder}.
	 */
	decoder: SymmetricCryptorCipherTextDecoder;
	/**
	 * Encoder of the stringify cipher text, must be pair with property {@linkcode decoder}.
	 */
	encoder: SymmetricCryptorCipherTextEncoder;
}
export interface SymmetricCryptorOptions {
	/**
	 * Coder of the stringify cipher text.
	 * @default {"base64"}
	 */
	cipherTextCoder?: SymmetricCryptorCipherTextCoderDefault | SymmetricCryptorCipherTextCoderOptions;
	/**
	 * Times of the crypto.
	 * @default {1}
	 */
	times?: number;
}
class SymmetricCryptorService {
	#algorithm: SymmetricCryptorAlgorithm;
	#cryptoKey: CryptoKey;
	#saltLength: number;
	constructor(algorithm: SymmetricCryptorAlgorithm, cryptoKey: CryptoKey) {
		this.#algorithm = algorithm;
		this.#cryptoKey = cryptoKey;
		switch (this.#algorithm) {
			case "AES-CBC":
			case "AES-CTR":
				this.#saltLength = 16;
				break;
			case "AES-GCM":
				this.#saltLength = 12;
				break;
		}
	}
	#resolveDecryptParameters(data: Uint8Array): AesCbcParams | AesCtrParams | AesGcmParams {
		switch (this.#algorithm) {
			case "AES-CBC":
			case "AES-GCM":
				return {
					name: this.#algorithm,
					iv: data.slice(0, this.#saltLength)
				};
			case "AES-CTR":
				return {
					name: this.#algorithm,
					counter: data.slice(0, this.#saltLength),
					length: 64
				};
		}
	}
	#resolveEncryptParameters(salt: Uint8Array): AesCbcParams | AesCtrParams | AesGcmParams {
		switch (this.#algorithm) {
			case "AES-CBC":
			case "AES-GCM":
				return {
					name: this.#algorithm,
					iv: salt
				};
			case "AES-CTR":
				return {
					name: this.#algorithm,
					counter: salt,
					length: 64
				};
		}
	}
	async decrypt(data: Uint8Array): Promise<Uint8Array> {
		return new Uint8Array(await crypto.subtle.decrypt(this.#resolveDecryptParameters(data), this.#cryptoKey, data.slice(this.#saltLength)));
	}
	async encrypt(data: Uint8Array): Promise<Uint8Array> {
		const salt: Uint8Array = crypto.getRandomValues(new Uint8Array(this.#saltLength));
		return Uint8Array.from([...salt, ...new Uint8Array(await crypto.subtle.encrypt(this.#resolveEncryptParameters(salt), this.#cryptoKey, data))]);
	}
	static async create(input: SymmetricCryptorKeyInput | SymmetricCryptorKeyType): Promise<SymmetricCryptorService> {
		let algorithm: SymmetricCryptorAlgorithm = "AES-CBC";
		let key: BufferSource;
		if (typeof input === "string") {
			key = new TextEncoder().encode(input);
		} else if (
			input instanceof ArrayBuffer ||
			input instanceof BigUint64Array ||
			input instanceof DataView ||
			input instanceof Uint8Array ||
			input instanceof Uint16Array ||
			input instanceof Uint32Array
		) {
			key = input;
		} else {
			if (typeof input.algorithm !== "undefined") {
				if (!algorithms.includes(input.algorithm)) {
					throw new RangeError(`\`${input.algorithm}\` is not a valid symmetric crypto algorithm! Only accept these values: ${algorithms.join(", ")}`);
				}
				algorithm = input.algorithm;
			}
			key = (typeof input.key === "string") ? new TextEncoder().encode(input.key) : input.key;
		}
		const keyFmt: ArrayBuffer = await crypto.subtle.digest("SHA-256", key);
		return new this(algorithm, await crypto.subtle.importKey("raw", keyFmt, { name: algorithm }, false, ["decrypt", "encrypt"]));
	}
}
function resolveCipherTextCoder(coder: SymmetricCryptorCipherTextCoderDefault | SymmetricCryptorCipherTextCoderOptions = "base64"): SymmetricCryptorCipherTextCoderOptions {
	if (typeof coder === "string") {
		if (cipherTextCodersDefault.includes(coder.toLowerCase() as SymmetricCryptorCipherTextCoderDefault)) {
			return {
				decoder(data: string): Uint8Array {
					return Uint8Array.from(Buffer.from(data, coder));
				},
				encoder(data: Uint8Array): string {
					return Buffer.from(data).toString(coder);
				}
			};
		}
		throw new RangeError(`\`${coder}\` is not a valid default coder! Only accept these values: ${cipherTextCodersDefault.join(", ")}`);
	}
	return coder;
}
/**
 * A password based cryptor, with basic functions.
 */
export class SymmetricCryptorBasic {
	get [Symbol.toStringTag](): string {
		return "SymmetricCryptorBasic";
	}
	#cipherTextDecoder: SymmetricCryptorCipherTextDecoder;
	#cipherTextEncoder: SymmetricCryptorCipherTextEncoder;
	#cryptoKeys: SymmetricCryptorService[] | undefined;
	#keyIsSingle: boolean;
	#keyOnSingleRepeats: number = 1;
	#keysToCryptoKeysFail: Error | undefined = undefined;
	#keysToCryptoKeysPromise: Promise<SymmetricCryptorService[]> | undefined = undefined;
	/**
	 * Initialize the symmetric cryptor.
	 * @param {SymmetricCryptorKeyInput | SymmetricCryptorKeyType} key Key of the symmetric cryptor.
	 * @param {SymmetricCryptorOptions} [options={}] Options of the symmetric cryptor.
	 */
	constructor(key: SymmetricCryptorKeyInput | SymmetricCryptorKeyType, options?: SymmetricCryptorOptions);
	/**
	 * Initialize the symmetric cryptor.
	 * @param {(SymmetricCryptorKeyInput | SymmetricCryptorKeyType)[]} keys Keys of the symmetric cryptor.
	 * @param {Omit<SymmetricCryptorOptions, "times">} [options={}] Options of the symmetric cryptor.
	 */
	constructor(keys: readonly (SymmetricCryptorKeyInput | SymmetricCryptorKeyType)[], options?: Omit<SymmetricCryptorOptions, "times">);
	constructor(keys: SymmetricCryptorKeyInput | SymmetricCryptorKeyType | readonly (SymmetricCryptorKeyInput | SymmetricCryptorKeyType)[], options: SymmetricCryptorOptions = {}) {
		const cipherTextCoder: SymmetricCryptorCipherTextCoderOptions = resolveCipherTextCoder(options.cipherTextCoder);
		this.#cipherTextDecoder = cipherTextCoder.decoder;
		this.#cipherTextEncoder = cipherTextCoder.encoder;
		if (Array.isArray(keys)) {
			if (keys.length === 0) {
				throw new ReferenceError(`Parameter \`keys\` is not defined!`);
			}
			this.#keyIsSingle = false;
			this.#keysToCryptoKeysPromise = Promise.all(keys.map((key: SymmetricCryptorKeyInput | SymmetricCryptorKeyType): Promise<SymmetricCryptorService> => {
				return SymmetricCryptorService.create(key);
			}));
		} else {
			this.#keyIsSingle = true;
			if (typeof options.times !== "undefined") {
				if (!(Number.isSafeInteger(options.times) && options.times >= 1)) {
					throw new TypeError(`\`${options.times}\` (parameter \`options.times\`) is not a number which is integer, safe, and >= 1!`);
				}
				this.#keyOnSingleRepeats = options.times;
			}
			this.#keysToCryptoKeysPromise = Promise.all([SymmetricCryptorService.create(keys as SymmetricCryptorKeyInput | SymmetricCryptorKeyType)]);
		}
	}
	/**
	 * Make sure the symmetric cryptor is ready to use.
	 * 
	 * In most of the cases, users do not need to call this method.
	 * 
	 * This method can call many times without any issue.
	 * @returns {Promise<void>}
	 */
	async ready(): Promise<void> {
		if (typeof this.#keysToCryptoKeysPromise !== "undefined") {
			try {
				const cryptoKeys: readonly SymmetricCryptorService[] = await this.#keysToCryptoKeysPromise;
				this.#cryptoKeys = [];
				if (this.#keyIsSingle) {
					for (let index: number = 0; index < this.#keyOnSingleRepeats; index += 1) {
						this.#cryptoKeys.push(cryptoKeys[0]);
					}
				} else {
					this.#cryptoKeys.push(...cryptoKeys);
				}
			} catch (error) {
				this.#keysToCryptoKeysFail = error as Error;
			}
			this.#keysToCryptoKeysPromise = undefined;
		}
		if (typeof this.#keysToCryptoKeysFail !== "undefined") {
			throw this.#keysToCryptoKeysFail;
		}
	}
	async #getCryptoKeys(): Promise<readonly SymmetricCryptorService[]> {
		await this.ready();
		if (
			typeof this.#cryptoKeys === "undefined" ||
			this.#cryptoKeys.length === 0
		) {
			throw new Error(`Crypto keys are somehow not exist! Please submit a bug report.`);
		}
		return this.#cryptoKeys;
	}
	async #decrypt(data: Uint8Array): Promise<Uint8Array> {
		const cryptoKeys: readonly SymmetricCryptorService[] = await this.#getCryptoKeys();
		if (data.length === 0) {
			return data;
		}
		let bin: Uint8Array = new Uint8Array(data);
		for (const cryptoKey of cryptoKeys.toReversed()) {
			bin = await cryptoKey.decrypt(bin);
		}
		return bin;
	}
	/**
	 * Decrypt the data.
	 * @param {string} data Data that need to decrypt.
	 * @returns {Promise<string>} The decrypted data.
	 */
	async decrypt(data: string): Promise<string>;
	/**
	 * Decrypt the data.
	 * @param {Uint8Array} data Data that need to decrypt.
	 * @returns {Promise<Uint8Array>} The decrypted data.
	 */
	async decrypt(data: Uint8Array): Promise<Uint8Array>;
	async decrypt(data: string | Uint8Array): Promise<string | Uint8Array> {
		if (typeof data === "string") {
			const cipherTextDecoded: Uint8Array = await this.#cipherTextDecoder(data);
			return new TextDecoder().decode(await this.#decrypt(cipherTextDecoded));
		}
		return await this.#decrypt(data);
	}
	async #encrypt(data: Uint8Array): Promise<Uint8Array> {
		const cryptoKeys: readonly SymmetricCryptorService[] = await this.#getCryptoKeys();
		let bin: Uint8Array = new Uint8Array(data);
		for (const cryptoKey of cryptoKeys) {
			bin = await cryptoKey.encrypt(bin);
		}
		return bin;
	}
	/**
	 * Encrypt the data.
	 * @param {string} data Data that need to encrypt.
	 * @returns {Promise<string>} The encrypted data.
	 */
	async encrypt(data: string): Promise<string>;
	/**
	 * Encrypt the data.
	 * @param {Uint8Array} data Data that need to encrypt.
	 * @returns {Promise<Uint8Array>} The encrypted data.
	 */
	async encrypt(data: Uint8Array): Promise<Uint8Array>;
	async encrypt(data: string | Uint8Array): Promise<string | Uint8Array> {
		if (typeof data === "string") {
			const encrypted: Uint8Array = await this.#encrypt(new TextEncoder().encode(data));
			return await this.#cipherTextEncoder(encrypted);
		}
		return await this.#encrypt(data);
	}
}
export default SymmetricCryptorBasic;
