import {
	createCipheriv,
	createDecipheriv,
	createSecretKey,
	getCipherInfo,
	getCiphers,
	randomBytes,
	type BinaryLike,
	type CipherCCM,
	type CipherCCMOptions,
	type CipherGCM,
	type CipherGCMOptions,
	type CipherInfo,
	type Cipheriv,
	type CipherMode,
	type CipherOCB,
	type CipherOCBOptions,
	type DecipherCCM,
	type DecipherGCM,
	type Decipheriv,
	type DecipherOCB,
	type KeyObject,
	type ScryptOptions
} from "node:crypto";
import { CPCEPBin } from "./_cpcep_bin.ts";
import {
	scrypt,
	scryptSync
} from "./_scrypt.ts";
export type SymmetricCryptoAlgorithm =
	| "aes-128-cbc"
	| "aes-128-ccm"
	| "aes-128-cfb"
	| "aes-128-cfb1"
	| "aes-128-cfb8"
	| "aes-128-ctr"
	| "aes-128-ecb"
	| "aes-128-gcm"
	| "aes-128-ocb"
	| "aes-128-ofb"
	| "aes-128-xts"
	| "aes-192-cbc"
	| "aes-192-ccm"
	| "aes-192-cfb"
	| "aes-192-cfb1"
	| "aes-192-cfb8"
	| "aes-192-ctr"
	| "aes-192-ecb"
	| "aes-192-gcm"
	| "aes-192-ocb"
	| "aes-192-ofb"
	| "aes-256-cbc"
	| "aes-256-ccm"
	| "aes-256-cfb"
	| "aes-256-cfb1"
	| "aes-256-cfb8"
	| "aes-256-ctr"
	| "aes-256-ecb"
	| "aes-256-gcm"
	| "aes-256-ocb"
	| "aes-256-ofb"
	| "aes-256-xts"
	| "aes128"
	| "aes192"
	| "aes256"
	| "aria-128-cbc"
	| "aria-128-ccm"
	| "aria-128-cfb"
	| "aria-128-cfb1"
	| "aria-128-cfb8"
	| "aria-128-ctr"
	| "aria-128-ecb"
	| "aria-128-gcm"
	| "aria-128-ofb"
	| "aria-192-cbc"
	| "aria-192-ccm"
	| "aria-192-cfb"
	| "aria-192-cfb1"
	| "aria-192-cfb8"
	| "aria-192-ctr"
	| "aria-192-ecb"
	| "aria-192-gcm"
	| "aria-192-ofb"
	| "aria-256-cbc"
	| "aria-256-ccm"
	| "aria-256-cfb"
	| "aria-256-cfb1"
	| "aria-256-cfb8"
	| "aria-256-ctr"
	| "aria-256-ecb"
	| "aria-256-gcm"
	| "aria-256-ofb"
	| "aria128"
	| "aria192"
	| "aria256"
	| "bf-cbc"
	| "bf-cfb"
	| "bf-ecb"
	| "camellia-128-cbc"
	| "camellia-128-cfb"
	| "camellia-128-cfb1"
	| "camellia-128-cfb8"
	| "camellia-128-ctr"
	| "camellia-128-ecb"
	| "camellia-128-ofb"
	| "camellia-192-cbc"
	| "camellia-192-cfb"
	| "camellia-192-cfb1"
	| "camellia-192-cfb8"
	| "camellia-192-ctr"
	| "camellia-192-ecb"
	| "camellia-192-ofb"
	| "camellia-256-cbc"
	| "camellia-256-cfb"
	| "camellia-256-cfb1"
	| "camellia-256-cfb8"
	| "camellia-256-ctr"
	| "camellia-256-ecb"
	| "camellia-256-ofb"
	| "camellia128"
	| "camellia192"
	| "camellia256"
	| "des-cbc"
	| "des-ecb"
	| "des-ede"
	| "des-ede-cbc"
	| "des-ede-cfb"
	| "des-ede-ecb"
	| "des-ede-ofb"
	| "des-ede3"
	| "des-ede3-cbc"
	| "des-ede3-cfb"
	| "des-ede3-cfb1"
	| "des-ede3-cfb8"
	| "des-ede3-ecb"
	| "des-ede3-ofb"
	| "des3"
	| "id-aes128-ccm"
	| "id-aes128-gcm"
	| "id-aes192-ccm"
	| "id-aes192-gcm"
	| "id-aes256-ccm"
	| "id-aes256-gcm"
	| "rc2-cbc"
	| "sm4"
	| "sm4-cbc"
	| "sm4-cfb"
	| "sm4-ctr"
	| "sm4-ecb"
	| "sm4-ofb";
interface SymmetricCryptoAlgorithmInfo {
	authTagLength: number;
	ivLength: number;
	keyLength: number;
	mode: CipherMode;
}
function getSymmetricCryptoAlgorithmInfoSafe(algorithm: string): SymmetricCryptoAlgorithmInfo | undefined {
	const info: CipherInfo | undefined = getCipherInfo(algorithm.toLowerCase());
	if (typeof info === "undefined") {
		return;
	}
	const {
		ivLength = 0,
		keyLength,
		mode
	}: CipherInfo = info;
	if (!(
		mode === "cbc" ||
		mode === "ccm" ||
		mode === "cfb" ||
		mode === "ctr" ||
		mode === "ecb" ||
		mode === "gcm" ||
		mode === "ocb" ||
		mode === "ofb" ||
		mode === "xts"
	)) {
		return;
	}
	return {
		authTagLength: (
			mode === "ccm" ||
			mode === "gcm" ||
			mode === "ocb"
		) ? 16 : 0,
		ivLength,
		keyLength,
		mode
	};
}
/**
 * Determine whether the cipher algorithm is support with symmetric crypto.
 * @param {string} algorithm Algorithm of the cipher.
 * @returns {boolean} Determine result.
 */
export function isSymmetricCryptoAlgorithmSupport(algorithm: string): boolean {
	return (typeof getSymmetricCryptoAlgorithmInfoSafe(algorithm) !== "undefined");
}
const algorithmsSupport: readonly string[] = getCiphers().map((algorithm: string): string => {
	return algorithm.toLowerCase();
}).filter((algorithm: string): boolean => {
	return isSymmetricCryptoAlgorithmSupport(algorithm as SymmetricCryptoAlgorithm);
}).sort();
function getSymmetricCryptoAlgorithmInfo(algorithm: SymmetricCryptoAlgorithm): SymmetricCryptoAlgorithmInfo {
	const info: SymmetricCryptoAlgorithmInfo | undefined = getSymmetricCryptoAlgorithmInfoSafe(algorithm);
	if (typeof info === "undefined") {
		throw new Error(`\`${algorithm}\` is not a cipher algorithm which support by the runtime, or not a valid cipher algorithm! Only accept these values: ${algorithmsSupport.join(", ")}.`);
	}
	return info;
}
/**
 * Get the list of the symmetric crypto algorithms.
 * @returns {readonly string[]}
 */
export function getSymmetricCryptoAlgorithms(): readonly string[] {
	return structuredClone(algorithmsSupport);
}
interface SymmetricCryptorPayload {
	algorithm: SymmetricCryptoAlgorithm;
	authTagLength: number;
	ivLength: number;
	key: KeyObject;
	mode: CipherMode;
}
const binCPCEPSymmetricCryptor: CPCEPBin<SymmetricCryptorPayload> = new CPCEPBin<SymmetricCryptorPayload>({
	errorGetUndefined: new ReferenceError(`Unknown Symmetric Cryptor payload!`)
});
/**
 * Symmetric cryptor decrypt stream; Only able to create new instance from {@linkcode SymmetricCryptor.decryptStream}.
 */
export class SymmetricCryptorDecryptStream extends TransformStream<Uint8Array, Uint8Array> {
	get [Symbol.toStringTag](): string {
		return "SymmetricCryptorDecryptStream";
	}
	#algorithm: SymmetricCryptoAlgorithm;
	#bin: number[] = [];
	#decipher?: Decipheriv;
	#ivLength: number;
	#key: KeyObject;
	/**
	 * Initialize; Only able to create new instance from {@linkcode SymmetricCryptor.decryptStream}.
	 * @param {symbol} s CPCEP symbol.
	 */
	private constructor(s: symbol) {
		const {
			algorithm,
			ivLength,
			key
		}: SymmetricCryptorPayload = binCPCEPSymmetricCryptor.get(s);
		super({
			transform: (chunk: Uint8Array, controller: TransformStreamDefaultController<Uint8Array>): void => {
				if (this.#decipher) {
					controller.enqueue(Uint8Array.from(this.#decipher.update(chunk)));
				} else {
					this.#bin.push(...Array.from(chunk));
					if (this.#bin.length >= this.#ivLength) {
						const iv: Uint8Array = Uint8Array.from(this.#bin.splice(0, this.#ivLength));
						this.#decipher = createDecipheriv(this.#algorithm, this.#key, iv);
						if (this.#bin.length > 0) {
							controller.enqueue(Uint8Array.from(this.#decipher.update(Uint8Array.from(this.#bin.splice(0, this.#bin.length)))));
						}
					}
				}
			},
			flush: (controller: TransformStreamDefaultController<Uint8Array>): void => {
				if (this.#decipher) {
					controller.enqueue(Uint8Array.from(this.#decipher.final()));
				} else {
					controller.error(`Unable to decrypt data due to unexpectedly less! Maybe cause by broken stream.`);
				}
			}
		});
		this.#algorithm = algorithm;
		this.#ivLength = ivLength;
		this.#key = key;
		if (this.#ivLength === 0) {
			// Shortcut for no IV, to prevent data get push to bin first.
			this.#decipher = createDecipheriv(this.#algorithm, this.#key, null);
		}
	}
}
/**
 * Symmetric cryptor decrypt stream with authentication tag mode (i.e.: GCM mode, OCB mode); Only able to create new instance from {@linkcode SymmetricCryptor.decryptStream}.
 */
export class SymmetricCryptorDecryptStreamAuthTag extends TransformStream<Uint8Array, Uint8Array> {
	get [Symbol.toStringTag](): string {
		return "SymmetricCryptorDecryptStreamAuthTag";
	}
	#algorithm: SymmetricCryptoAlgorithm;
	#authTagLength: number;
	#bin: number[] = [];
	#decipher?: DecipherGCM | DecipherOCB;
	#ivLength: number;
	#key: KeyObject;
	/**
	 * Initialize; Only able to create new instance from {@linkcode SymmetricCryptor.decryptStream}.
	 * @param {symbol} s CPCEP symbol.
	 */
	private constructor(s: symbol) {
		const {
			algorithm,
			authTagLength,
			ivLength,
			key
		}: SymmetricCryptorPayload = binCPCEPSymmetricCryptor.get(s);
		super({
			transform: (chunk: Uint8Array, controller: TransformStreamDefaultController<Uint8Array>): void => {
				this.#bin.push(...Array.from(chunk));
				if (this.#decipher) {
					this.#update(controller);
				} else {
					if (this.#bin.length >= this.#ivLength) {
						const iv: Uint8Array = Uint8Array.from(this.#bin.splice(0, this.#ivLength));
						this.#decipher = createDecipheriv(this.#algorithm, this.#key, iv, {
							//@ts-expect-error Overload.
							authTagLength: this.#authTagLength
						} satisfies CipherGCMOptions | CipherOCBOptions);
						this.#update(controller);
					}
				}
			},
			flush: (controller: TransformStreamDefaultController<Uint8Array>): void => {
				if (this.#decipher && this.#bin.length === this.#authTagLength) {
					this.#decipher.setAuthTag(Uint8Array.from(this.#bin.splice(0, this.#bin.length)));
					controller.enqueue(Uint8Array.from(this.#decipher.final()));
				} else {
					controller.error(`Unable to decrypt data due to unexpectedly less! Maybe cause by broken stream.`);
				}
			}
		});
		this.#algorithm = algorithm;
		this.#authTagLength = authTagLength;
		this.#ivLength = ivLength;
		this.#key = key;
	}
	#update(controller: TransformStreamDefaultController<Uint8Array>): void {
		if (this.#bin.length >= this.#authTagLength) {
			controller.enqueue(Uint8Array.from(this.#decipher!.update(Uint8Array.from(this.#bin.splice(0, this.#bin.length - 16)))));
		}
	}
}
/**
 * Symmetric cryptor decrypt stream with CCM mode; Only able to create new instance from {@linkcode SymmetricCryptor.decryptStream}.
 */
export class SymmetricCryptorDecryptStreamCCM extends TransformStream<Uint8Array, Uint8Array> {
	get [Symbol.toStringTag](): string {
		return "SymmetricCryptorDecryptStreamCCM";
	}
	#algorithm: SymmetricCryptoAlgorithm;
	#authTagLength: number;
	#bin: number[] = [];
	#ivLength: number;
	#key: KeyObject;
	/**
	 * Initialize; Only able to create new instance from {@linkcode SymmetricCryptor.decryptStream}.
	 * @param {symbol} s CPCEP symbol.
	 */
	private constructor(s: symbol) {
		const {
			algorithm,
			authTagLength,
			ivLength,
			key
		}: SymmetricCryptorPayload = binCPCEPSymmetricCryptor.get(s);
		super({
			transform: (chunk: Uint8Array, _controller: TransformStreamDefaultController<Uint8Array>): void => {
				this.#bin.push(...Array.from(chunk));
			},
			flush: (controller: TransformStreamDefaultController<Uint8Array>): void => {
				if (this.#bin.length >= this.#ivLength + this.#authTagLength) {
					const iv: Uint8Array | null = (this.#ivLength > 0) ? Uint8Array.from(this.#bin.splice(0, this.#ivLength)) : null;
					const authTag: Uint8Array = Uint8Array.from(this.#bin.splice(-this.#authTagLength, this.#authTagLength));
					const decipher: DecipherCCM = createDecipheriv(this.#algorithm, this.#key, iv, {
						//@ts-expect-error Overload.
						authTagLength: this.#authTagLength
					} satisfies CipherCCMOptions);
					decipher.setAuthTag(authTag);
					controller.enqueue(Uint8Array.from(decipher.update(Uint8Array.from(this.#bin.splice(0, this.#bin.length)))));
					controller.enqueue(Uint8Array.from(decipher.final()));
				} else {
					controller.error(`Unable to decrypt data due to unexpectedly less! Maybe cause by broken stream.`);
				}
			}
		});
		this.#algorithm = algorithm;
		this.#authTagLength = authTagLength;
		this.#ivLength = ivLength;
		this.#key = key;
	}
}
/**
 * Symmetric cryptor encrypt stream; Only able to create new instance from {@linkcode SymmetricCryptor.encryptStream}.
 */
export class SymmetricCryptorEncryptStream extends TransformStream<Uint8Array, Uint8Array> {
	get [Symbol.toStringTag](): string {
		return "SymmetricCryptorEncryptStream";
	}
	#authTagLength: number;
	#cipher: Cipheriv;
	/**
	 * Initialize; Only able to create new instance from {@linkcode SymmetricCryptor.encryptStream}.
	 * @param {symbol} s CPCEP symbol.
	 */
	private constructor(s: symbol) {
		const {
			algorithm,
			authTagLength,
			ivLength,
			key
		}: SymmetricCryptorPayload = binCPCEPSymmetricCryptor.get(s);
		const iv: Uint8Array | null = (ivLength > 0) ? randomBytes(ivLength) : null;
		super({
			start: (controller: TransformStreamDefaultController<Uint8Array>) => {
				if (iv !== null) {
					controller.enqueue(iv);
				}
			},
			transform: (chunk: Uint8Array, controller: TransformStreamDefaultController<Uint8Array>): void => {
				controller.enqueue(Uint8Array.from(this.#cipher.update(chunk)));
			},
			flush: (controller: TransformStreamDefaultController<Uint8Array>): void => {
				controller.enqueue(Uint8Array.from(this.#cipher.final()));
				if (this.#authTagLength > 0) {
					controller.enqueue(Uint8Array.from((this.#cipher as CipherGCM | CipherOCB).getAuthTag()));
				}
			}
		});
		this.#authTagLength = authTagLength;
		this.#cipher = createCipheriv(algorithm, key, iv, {
			//@ts-expect-error Overload.
			authTagLength: (this.#authTagLength > 0) ? this.#authTagLength : undefined
		} satisfies CipherGCMOptions | CipherOCBOptions);
	}
}
/**
 * Symmetric cryptor encrypt stream with CCM mode; Only able to create new instance from {@linkcode SymmetricCryptor.encryptStream}.
 */
export class SymmetricCryptorEncryptStreamCCM extends TransformStream<Uint8Array, Uint8Array> {
	get [Symbol.toStringTag](): string {
		return "SymmetricCryptorEncryptStreamCCM";
	}
	#bin: number[] = [];
	#cipher: CipherCCM;
	/**
	 * Initialize; Only able to create new instance from {@linkcode SymmetricCryptor.encryptStream}.
	 * @param {symbol} s CPCEP symbol.
	 */
	private constructor(s: symbol) {
		const {
			algorithm,
			authTagLength,
			ivLength,
			key
		}: SymmetricCryptorPayload = binCPCEPSymmetricCryptor.get(s);
		const iv: Uint8Array | null = (ivLength > 0) ? randomBytes(ivLength) : null;
		super({
			start: (controller: TransformStreamDefaultController<Uint8Array>) => {
				if (iv !== null) {
					controller.enqueue(iv);
				}
			},
			transform: (chunk: Uint8Array, _controller: TransformStreamDefaultController<Uint8Array>): void => {
				this.#bin.push(...Array.from(chunk));
			},
			flush: (controller: TransformStreamDefaultController<Uint8Array>): void => {
				controller.enqueue(Uint8Array.from(this.#cipher.update(Uint8Array.from(this.#bin.splice(0, this.#bin.length)))));
				controller.enqueue(Uint8Array.from(this.#cipher.final()));
				controller.enqueue(Uint8Array.from(this.#cipher.getAuthTag()));
			}
		});
		this.#cipher = createCipheriv(algorithm, key, iv, {
			//@ts-expect-error Overload.
			authTagLength
		} satisfies CipherCCMOptions);
	}
}
export interface SymmetricCryptorOptions {
	/**
	 * Algorithm of the symmetric crypto.
	 * 
	 * Availability of the symmetric crypto algorithms are depend on the runtime, use {@linkcode getSymmetricCryptoAlgorithms} for the support symmetric crypto algorithms list.
	 * @default {"aes-256-cbc"}
	 */
	algorithm?: SymmetricCryptoAlgorithm;
	/**
	 * Options of the scrypt.
	 */
	scrypt?: ScryptOptions;
}
/**
 * Symmetric cryptor, a password based cryptor.
 */
export class SymmetricCryptor {
	get [Symbol.toStringTag](): string {
		return "SymmetricCryptor";
	}
	#algorithm: SymmetricCryptoAlgorithm;
	#authTagLength: number;
	#ivLength: number;
	#key: KeyObject;
	#mode: CipherMode;
	#s: symbol;
	/**
	 * Initialize; Only able to create new instance from {@linkcode createSymmetricCryptor} or {@linkcode createSymmetricCryptorSync}.
	 * @param {symbol} s CPCEP symbol.
	 */
	private constructor(s: symbol) {
		this.#s = s;
		const {
			algorithm,
			authTagLength,
			ivLength,
			key,
			mode
		}: SymmetricCryptorPayload = binCPCEPSymmetricCryptor.get(s);
		this.#algorithm = algorithm;
		this.#authTagLength = authTagLength;
		this.#ivLength = ivLength;
		this.#key = key;
		this.#mode = mode;
	}
	/**
	 * Decrypt the data.
	 * @param {Uint8Array} data Data that need to decrypt.
	 * @returns {Uint8Array} The decrypted data.
	 */
	decrypt(data: Uint8Array): Uint8Array {
		if (!(data.length >= this.#ivLength + this.#authTagLength)) {
			throw new Error(`Unable to decrypt data due to unexpectedly less!`);
		}
		const iv: Uint8Array | null = (this.#ivLength > 0) ? data.slice(0, this.#ivLength) : null;
		const context: Uint8Array = data.slice(this.#ivLength, (this.#authTagLength > 0) ? -this.#authTagLength : undefined);
		const authTag: Uint8Array | null = (this.#authTagLength > 0) ? data.slice(-this.#authTagLength) : null;
		const decipher: Decipheriv = createDecipheriv(this.#algorithm, this.#key, iv, {
			//@ts-expect-error Overload.
			authTagLength: (this.#authTagLength > 0) ? this.#authTagLength : undefined
		} satisfies CipherCCMOptions | CipherGCMOptions | CipherOCBOptions);
		if (authTag !== null) {
			(decipher as DecipherCCM | DecipherGCM | DecipherOCB).setAuthTag(authTag);
		}
		const resultUpdate: Uint8Array = Uint8Array.from(decipher.update(context));
		const resultFinal: Uint8Array = Uint8Array.from(decipher.final());
		return Uint8Array.from([...resultUpdate, ...resultFinal]);
	}
	/**
	 * Create new instance of the symmetric cryptor decrypt stream to decrypt the data in the stream.
	 * @returns {SymmetricCryptorDecryptStream | SymmetricCryptorDecryptStreamAuthTag | SymmetricCryptorDecryptStreamCCM}
	 */
	decryptStream(): SymmetricCryptorDecryptStream | SymmetricCryptorDecryptStreamAuthTag | SymmetricCryptorDecryptStreamCCM {
		if (this.#mode === "ccm") {
			//@ts-expect-error Private constructor.
			return new SymmetricCryptorDecryptStreamCCM(this.#s);
		}
		if (this.#authTagLength > 0) {
			//@ts-expect-error Private constructor.
			return new SymmetricCryptorDecryptStreamAuthTag(this.#s);
		}
		//@ts-expect-error Private constructor.
		return new SymmetricCryptorDecryptStream(this.#s);
	}
	/**
	 * Encrypt the data.
	 * @param {Uint8Array} data Data that need to encrypt.
	 * @returns {Uint8Array} The encrypted data.
	 */
	encrypt(data: Uint8Array): Uint8Array {
		const iv: Uint8Array | null = (this.#ivLength > 0) ? Uint8Array.from(randomBytes(this.#ivLength)) : null;
		const cipher: Cipheriv = createCipheriv(this.#algorithm, this.#key, iv, {
			//@ts-expect-error Overload.
			authTagLength: (this.#authTagLength > 0) ? this.#authTagLength : undefined
		} satisfies CipherCCMOptions | CipherGCMOptions | CipherOCBOptions);
		const resultUpdate: Uint8Array = Uint8Array.from(cipher.update(data));
		const resultFinal: Uint8Array = Uint8Array.from(cipher.final());
		const resultAuthTag: Uint8Array | null = (this.#authTagLength > 0) ? Uint8Array.from((cipher as CipherCCM | CipherGCM | CipherOCB).getAuthTag()) : null;
		return Uint8Array.from([...(iv ?? []), ...resultUpdate, ...resultFinal, ...(resultAuthTag ?? [])]);
	}
	/**
	 * Create new instance of the symmetric cryptor encrypt stream to encrypt the data in the stream.
	 * @returns {SymmetricCryptorEncryptStream | SymmetricCryptorEncryptStreamCCM}
	 */
	encryptStream(): SymmetricCryptorEncryptStream | SymmetricCryptorEncryptStreamCCM {
		if (this.#mode === "ccm") {
			//@ts-expect-error Private constructor.
			return new SymmetricCryptorEncryptStreamCCM(this.#s);
		}
		//@ts-expect-error Private constructor.
		return new SymmetricCryptorEncryptStream(this.#s);
	}
}
/**
 * Create new instance of the {@link SymmetricCryptor symmetric cryptor}, asynchronously.
 * @param {BinaryLike} key Key.
 * @param {SymmetricCryptorOptions} [options={}] Options.
 * @returns {Promise<SymmetricCryptor>}
 */
export async function createSymmetricCryptor(key: BinaryLike, options: SymmetricCryptorOptions = {}): Promise<SymmetricCryptor> {
	const {
		algorithm = "aes-256-cbc",
		scrypt: scryptOptions
	}: SymmetricCryptorOptions = options;
	const {
		keyLength,
		...info
	}: SymmetricCryptoAlgorithmInfo = getSymmetricCryptoAlgorithmInfo(algorithm);
	//deno-lint-ignore hugoalh/symbol-description -- Private symbol.
	const s: symbol = Symbol();
	const keyScrypt: Uint8Array = await scrypt(key, key, keyLength, scryptOptions);
	binCPCEPSymmetricCryptor.set(s, {
		algorithm,
		key: createSecretKey(keyScrypt),
		...info
	});
	//@ts-expect-error Private constructor.
	return new SymmetricCryptor(s);
}
/**
 * Create new instance of the {@link SymmetricCryptor symmetric cryptor}, synchronously.
 * @param {BinaryLike} key Key.
 * @param {SymmetricCryptorOptions} [options={}] Options.
 * @returns {SymmetricCryptor}
 */
export function createSymmetricCryptorSync(key: BinaryLike, options: SymmetricCryptorOptions = {}): SymmetricCryptor {
	const {
		algorithm = "aes-256-cbc",
		scrypt: scryptOptions
	}: SymmetricCryptorOptions = options;
	const {
		keyLength,
		...info
	}: SymmetricCryptoAlgorithmInfo = getSymmetricCryptoAlgorithmInfo(algorithm);
	//deno-lint-ignore hugoalh/symbol-description -- Private symbol.
	const s: symbol = Symbol();
	const keyScrypt: Uint8Array = scryptSync(key, key, keyLength, scryptOptions);
	binCPCEPSymmetricCryptor.set(s, {
		algorithm,
		key: createSecretKey(keyScrypt),
		...info
	});
	//@ts-expect-error Private constructor.
	return new SymmetricCryptor(s);
}
