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
 * Input of the key of the symmetric cryptor.
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
class SymmetricCryptoService {
	#algorithmName: string;
	#cryptoKey: CryptoKey;
	#tokenLength: number;
	#resolveDecryptParameters: (data: Uint8Array) => AesCbcParams | AesCtrParams | AesGcmParams;
	#resolveEncryptParameters: (token: Uint8Array) => AesCbcParams | AesCtrParams | AesGcmParams;
	constructor(cryptoKey: CryptoKey) {
		this.#cryptoKey = cryptoKey;
		this.#algorithmName = this.#cryptoKey.algorithm.name;
		switch (this.#algorithmName) {
			case "AES-CBC":
			case "AES-GCM":
				this.#tokenLength = (this.#algorithmName === "AES-GCM") ? 12 : 16;
				this.#resolveDecryptParameters = (data: Uint8Array): AesCbcParams | AesGcmParams => {
					return {
						name: this.#algorithmName,
						iv: data.slice(0, this.#tokenLength)
					};
				};
				this.#resolveEncryptParameters = (token: Uint8Array): AesCbcParams | AesGcmParams => {
					return {
						name: this.#algorithmName,
						iv: token
					};
				};
				break;
			case "AES-CTR":
				this.#tokenLength = 16;
				this.#resolveDecryptParameters = (data: Uint8Array): AesCtrParams => {
					return {
						name: this.#algorithmName,
						counter: data.slice(0, this.#tokenLength),
						length: 64
					};
				};
				this.#resolveEncryptParameters = (token: Uint8Array): AesCtrParams => {
					return {
						name: this.#algorithmName,
						counter: token,
						length: 64
					};
				};
				break;
			default:
				throw new Error(`Unsupported algorithm \`${this.#algorithmName}\`!`);
		}
	}
	async decrypt(data: Uint8Array): Promise<Uint8Array> {
		return new Uint8Array(await crypto.subtle.decrypt(this.#resolveDecryptParameters(data), this.#cryptoKey, data.slice(this.#tokenLength)));
	}
	async encrypt(data: Uint8Array): Promise<Uint8Array> {
		const token: Uint8Array = crypto.getRandomValues(new Uint8Array(this.#tokenLength));
		return Uint8Array.from([...token, ...new Uint8Array(await crypto.subtle.encrypt(this.#resolveEncryptParameters(token), this.#cryptoKey, data))]);
	}
	static async create(input: SymmetricCryptorKeyInput | SymmetricCryptorKeyType): Promise<SymmetricCryptoService> {
		let algorithm: SymmetricCryptorAlgorithm = "AES-CBC";
		let key: SymmetricCryptorKeyType;
		if (
			typeof input === "string" ||
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
			key = input.key;
		}
		return new this(await crypto.subtle.importKey("raw", await crypto.subtle.digest("SHA-256", (typeof key === "string") ? new TextEncoder().encode(key) : key), { name: algorithm }, false, ["decrypt", "encrypt"]));
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
 * A password based cryptor.
 */
export class SymmetricCryptorBasic {
	get [Symbol.toStringTag](): string {
		return "SymmetricCryptorBasic";
	}
	#cipherTextDecoder: SymmetricCryptorCipherTextDecoder;
	#cipherTextEncoder: SymmetricCryptorCipherTextEncoder;
	#cryptoKeysStorage: SymmetricCryptoService[] | undefined;
	#keyIsSingle: boolean;
	#keyOnSingleRepeats: number = 1;
	#keysToCryptoKeysFail: Error | undefined = undefined;
	#keysToCryptoKeysPromise: Promise<SymmetricCryptoService[]> | undefined = undefined;
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
			this.#keysToCryptoKeysPromise = Promise.all(keys.map((key: SymmetricCryptorKeyInput | SymmetricCryptorKeyType): Promise<SymmetricCryptoService> => {
				return SymmetricCryptoService.create(key);
			}));
		} else {
			this.#keyIsSingle = true;
			if (typeof options.times !== "undefined") {
				if (!(Number.isSafeInteger(options.times) && options.times >= 1)) {
					throw new TypeError(`\`${options.times}\` (parameter \`options.times\`) is not a number which is integer, safe, and >= 1!`);
				}
				this.#keyOnSingleRepeats = options.times;
			}
			this.#keysToCryptoKeysPromise = Promise.all([SymmetricCryptoService.create(keys as SymmetricCryptorKeyInput | SymmetricCryptorKeyType)]);
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
				const result: readonly SymmetricCryptoService[] = await this.#keysToCryptoKeysPromise;
				this.#cryptoKeysStorage = [];
				if (this.#keyIsSingle) {
					for (let index: number = 0; index < this.#keyOnSingleRepeats; index += 1) {
						this.#cryptoKeysStorage.push(result[0]);
					}
				} else {
					this.#cryptoKeysStorage.push(...result);
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
	async #getCryptoKeys(): Promise<readonly SymmetricCryptoService[]> {
		await this.ready();
		if (
			typeof this.#cryptoKeysStorage === "undefined" ||
			this.#cryptoKeysStorage.length === 0
		) {
			throw new Error(`Crypto keys are somehow not exist! Please submit a bug report.`);
		}
		return this.#cryptoKeysStorage;
	}
	async #decrypt(data: Uint8Array): Promise<Uint8Array> {
		const cryptoKeys: readonly SymmetricCryptoService[] = await this.#getCryptoKeys();
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
			return new TextDecoder().decode(await this.#decrypt(await this.#cipherTextDecoder(data)));
		}
		return await this.#decrypt(data);
	}
	async #encrypt(data: Uint8Array): Promise<Uint8Array> {
		const cryptoKeys: readonly SymmetricCryptoService[] = await this.#getCryptoKeys();
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
			return await this.#cipherTextEncoder(await this.#encrypt(new TextEncoder().encode(data)));
		}
		return await this.#encrypt(data);
	}
}
export default SymmetricCryptorBasic;
