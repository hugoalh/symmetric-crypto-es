import {
	createCipheriv,
	createDecipheriv,
	createSecretKey,
	getCipherInfo,
	getCiphers,
	randomBytes,
	type BinaryLike,
	type CipherGCM,
	type CipherGCMOptions,
	type CipherInfo,
	type Cipheriv,
	type CipherMode,
	type DecipherGCM,
	type Decipheriv,
	type KeyObject,
	type ScryptOptions
} from "node:crypto";
import {
	scrypt,
	scryptSync
} from "./_scrypt.ts";
export type SymmetricCryptoAlgorithm =
	| "aes-128-cbc"
	| "aes-128-ctr"
	| "aes-128-ecb"
	| "aes-128-gcm"
	| "aes-192-ctr"
	| "aes-192-ecb"
	| "aes-256-cbc"
	| "aes-256-ctr"
	| "aes-256-ecb"
	| "aes-256-gcm"
	| "des-ede3-cbc";
const algorithmsSelect: readonly SymmetricCryptoAlgorithm[] = [/* UNIQUE */
	"aes-128-cbc",
	"aes-128-ctr",
	"aes-128-ecb",
	"aes-128-gcm",
	"aes-192-ctr",
	"aes-192-ecb",
	"aes-256-cbc",
	"aes-256-ctr",
	"aes-256-ecb",
	"aes-256-gcm",
	"des-ede3-cbc"
];
const algorithmsFinal: readonly string[] = getCiphers().filter((algorithm: string): boolean => {
	return algorithmsSelect.includes(algorithm as SymmetricCryptoAlgorithm);
}).sort();
interface CPCEP_SymmetricCryptor {
	algorithm: SymmetricCryptoAlgorithm;
	ivLength: number;
	key: KeyObject;
	mode: CipherMode | undefined;
}
const binCPCEPSymmetricCryptor: Map<symbol, CPCEP_SymmetricCryptor> = new Map<symbol, CPCEP_SymmetricCryptor>();
function getCPCEPSymmetricCryptor(s: symbol): CPCEP_SymmetricCryptor {
	const payload: CPCEP_SymmetricCryptor | undefined = binCPCEPSymmetricCryptor.get(s);
	if (typeof payload === "undefined") {
		throw new ReferenceError(`Unknown Symmetric Cryptor payload!`);
	}
	return payload;
}
function setCPCEPSymmetricCryptor(s: symbol, payload: CPCEP_SymmetricCryptor): void {
	binCPCEPSymmetricCryptor.set(s, payload);
}
/**
 * Decrypt pipe of the {@link SymmetricCryptor Symmetric Cryptor}; Only able to create new instance from {@linkcode SymmetricCryptor.decryptPipe}.
 */
export class SymmetricCryptorDecryptPipe extends TransformStream<Uint8Array, Uint8Array> {
	get [Symbol.toStringTag](): string {
		return "SymmetricCryptorDecryptPipe";
	}
	#algorithm: SymmetricCryptoAlgorithm;
	#bin: number[] = [];
	#decipher?: Decipheriv;
	#ivLength: number;
	#key: KeyObject;
	/**
	 * Initialize; Only able to create new instance from {@linkcode SymmetricCryptor.decryptPipe}.
	 * @param {symbol} s CPCEP symbol.
	 */
	private constructor(s: symbol) {
		const {
			algorithm,
			ivLength,
			key,
			mode
		}: CPCEP_SymmetricCryptor = getCPCEPSymmetricCryptor(s);
		super(
			(mode === "gcm") ? {
				transform: (chunk: Uint8Array, controller: TransformStreamDefaultController<Uint8Array>): void => {
					this.#bin.push(...Array.from(chunk));
					if (this.#decipher) {
						this.#updateGCM(controller);
					} else {
						if (this.#bin.length >= this.#ivLength) {
							const iv: Uint8Array = Uint8Array.from(this.#bin.splice(0, this.#ivLength));
							this.#decipher = createDecipheriv(this.#algorithm, this.#key, iv, {
								//@ts-expect-error Overload.
								authTagLength: 16
							} satisfies CipherGCMOptions);
							this.#updateGCM(controller);
						}
					}
				},
				flush: (controller: TransformStreamDefaultController<Uint8Array>): void => {
					if (this.#decipher && this.#bin.length === 16) {
						(this.#decipher as DecipherGCM).setAuthTag(Uint8Array.from(this.#bin.splice(0, 16)));
						controller.enqueue(this.#decipher.final());
					} else {
						controller.error(`Unable to decrypt data due to unexpectedly less! Maybe cause by broken stream.`);
					}
				}
			} : {
				transform: (chunk: Uint8Array, controller: TransformStreamDefaultController<Uint8Array>): void => {
					if (this.#decipher) {
						controller.enqueue(this.#decipher.update(chunk));
					} else {
						this.#bin.push(...Array.from(chunk));
						if (this.#bin.length >= this.#ivLength) {
							const iv: Uint8Array = Uint8Array.from(this.#bin.splice(0, this.#ivLength));
							this.#decipher = createDecipheriv(this.#algorithm, this.#key, iv);
							if (this.#bin.length > 0) {
								controller.enqueue(this.#decipher.update(Uint8Array.from(this.#bin.splice(0, this.#bin.length))));
							}
						}
					}
				},
				flush: (controller: TransformStreamDefaultController<Uint8Array>): void => {
					if (this.#decipher) {
						controller.enqueue(this.#decipher.final());
					} else {
						controller.error(`Unable to decrypt data due to unexpectedly less! Maybe cause by broken stream.`);
					}
				}
			}
		);
		this.#algorithm = algorithm;
		this.#ivLength = ivLength;
		this.#key = key;
		if (this.#ivLength === 0) {
			// Shortcut for no IV, to prevent data get push to bin first.
			this.#decipher = createDecipheriv(this.#algorithm, this.#key, null);
		}
	}
	#updateGCM(controller: TransformStreamDefaultController<Uint8Array>): void {
		if (this.#bin.length >= 16) {
			controller.enqueue(this.#decipher!.update(Uint8Array.from(this.#bin.splice(0, this.#bin.length - 16))));
		}
	}
}
/**
 * Encrypt pipe of the {@link SymmetricCryptor Symmetric Cryptor}; Only able to create new instance from {@linkcode SymmetricCryptor.encryptPipe}.
 */
export class SymmetricCryptorEncryptPipe extends TransformStream<Uint8Array, Uint8Array> {
	get [Symbol.toStringTag](): string {
		return "SymmetricCryptorEncryptPipe";
	}
	#cipher: Cipheriv;
	#iv: Uint8Array;
	#ivLock: boolean = false;
	#mode: CipherMode | undefined;
	/**
	 * Initialize; Only able to create new instance from {@linkcode SymmetricCryptor.encryptPipe}.
	 * @param {symbol} s CPCEP symbol.
	 */
	private constructor(s: symbol) {
		const {
			algorithm,
			ivLength,
			key,
			mode
		}: CPCEP_SymmetricCryptor = getCPCEPSymmetricCryptor(s);
		super({
			transform: (chunk: Uint8Array, controller: TransformStreamDefaultController<Uint8Array>): void => {
				// NOTE: Use `TransformStream.start` with `this` will cause error.
				if (!this.#ivLock) {
					controller.enqueue(this.#iv);
					this.#ivLock = true;
				}
				controller.enqueue(Uint8Array.from(this.#cipher.update(chunk)));
			},
			flush: (controller: TransformStreamDefaultController<Uint8Array>): void => {
				controller.enqueue(Uint8Array.from(this.#cipher.final()));
				if (this.#mode === "gcm") {
					controller.enqueue(Uint8Array.from((this.#cipher as CipherGCM).getAuthTag()));
				}
				this.#ivLock = false;
			}
		});
		this.#mode = mode;
		this.#iv = (ivLength > 0) ? randomBytes(ivLength) : Uint8Array.from([]);;
		this.#cipher = (this.#mode === "gcm") ? createCipheriv(algorithm, key, this.#iv, {
			//@ts-expect-error Overload.
			authTagLength: 16
		} satisfies CipherGCMOptions) : createCipheriv(algorithm, key, this.#iv);;
	}
}
export interface SymmetricCryptorOptions {
	/**
	 * Algorithm of the cipher.
	 * 
	 * Availability of the cipher algorithms are depend on the runtime.
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
	#ivLength: number;
	#key: KeyObject;
	#mode: CipherMode | undefined;
	#s: symbol;
	/**
	 * Initialize; Only able to create new instance from {@linkcode createSymmetricCrypto} or {@linkcode createSymmetricCryptoSync}.
	 * @param {symbol} s CPCEP symbol.
	 */
	private constructor(s: symbol) {
		this.#s = s;
		const {
			algorithm,
			ivLength,
			key,
			mode
		}: CPCEP_SymmetricCryptor = getCPCEPSymmetricCryptor(s);
		this.#algorithm = algorithm;
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
		const iv: Uint8Array | null = (this.#ivLength > 0) ? data.slice(0, this.#ivLength) : null;
		const context: Uint8Array = data.slice(this.#ivLength, (this.#mode === "gcm") ? -16 : undefined);
		const decipher: Decipheriv = createDecipheriv(this.#algorithm, this.#key, iv, {
			//@ts-expect-error Overload.
			authTagLength: (this.#mode === "gcm") ? 16 : undefined
		} satisfies CipherGCMOptions);
		const resultUpdate: Uint8Array = Uint8Array.from(decipher.update(context));
		if (this.#mode === "gcm") {
			const authTag: Uint8Array = data.slice(-16);
			(decipher as DecipherGCM).setAuthTag(authTag);
		}
		const resultFinal: Uint8Array = Uint8Array.from(decipher.final());
		return Uint8Array.from([...resultUpdate, ...resultFinal]);
	}
	/**
	 * Create new instance of the {@link SymmetricCryptorDecryptPipe symmetric cryptor decrypt pipe} to decrypt the data in the stream.
	 * @returns {SymmetricCryptorDecryptPipe} New instance of the symmetric cryptor decrypt pipe.
	 */
	decryptPipe(): SymmetricCryptorDecryptPipe {
		//@ts-expect-error Private constructor.
		return new SymmetricCryptorDecryptPipe(this.#s);
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
			authTagLength: (this.#mode === "gcm") ? 16 : undefined
		} satisfies CipherGCMOptions);
		const resultUpdate: Uint8Array = Uint8Array.from(cipher.update(data));
		const resultFinal: Uint8Array = Uint8Array.from(cipher.final());
		const resultAuthTag: Uint8Array = Uint8Array.from((this.#mode === "gcm") ? (cipher as CipherGCM).getAuthTag() : []);
		return Uint8Array.from([...(iv ?? []), ...resultUpdate, ...resultFinal, ...resultAuthTag]);
	}
	/**
	 * Create new instance of the {@link SymmetricCryptorEncryptPipe symmetric cryptor encrypt pipe} to encrypt the data in the stream.
	 * @returns {SymmetricCryptorEncryptPipe} New instance of the symmetric cryptor encrypt pipe.
	 */
	encryptPipe(): SymmetricCryptorEncryptPipe {
		//@ts-expect-error Private constructor.
		return new SymmetricCryptorEncryptPipe(this.#s);
	}
}
interface SymmetricCryptoAlgorithmInfo {
	ivLength: number;
	keyLength: number;
	mode: CipherMode | undefined;
}
function getSymmetricCryptoAlgorithmInfo(algorithm: SymmetricCryptoAlgorithm): SymmetricCryptoAlgorithmInfo {
	if (!algorithmsSelect.includes(algorithm.toLowerCase() as SymmetricCryptoAlgorithm)) {
		throw new Error(`\`${algorithm}\` is not a valid cipher algorithm! Only accept these values: ${algorithmsSelect.join(", ")}`);
	}
	if (!algorithmsFinal.includes(algorithm.toLowerCase())) {
		throw new Error(`\`${algorithm}\` is not a cipher algorithm which support by the runtime! Only accept these values: ${algorithmsFinal.join(", ")}`);
	}
	const info: CipherInfo | undefined = getCipherInfo(algorithm);
	if (typeof info === "undefined") {
		throw new Error(`Unable to get the information of the cipher algorithm \`${algorithm}\`!`);
	}
	// NOTE: In Deno, some of the algorithms return property `mode` with `""`.
	let mode: CipherMode | undefined = info.mode;
	if ((mode as string) === "") {
		mode = undefined;
	}
	return {
		ivLength: info.ivLength ?? 0,
		keyLength: info.keyLength,
		mode
	};
}
/**
 * Create new instance of the {@link SymmetricCryptor symmetric cryptor}, asynchronously.
 * @param {BinaryLike} key Key.
 * @param {SymmetricCryptorOptions} [options={}] Options.
 * @returns {Promise<SymmetricCryptor>} New instance of the symmetric cryptor.
 */
export async function createSymmetricCrypto(key: BinaryLike, options: SymmetricCryptorOptions = {}): Promise<SymmetricCryptor> {
	const {
		algorithm = "aes-256-cbc",
		scrypt: scryptOptions
	}: SymmetricCryptorOptions = options;
	const {
		ivLength,
		keyLength,
		mode
	}: SymmetricCryptoAlgorithmInfo = getSymmetricCryptoAlgorithmInfo(algorithm);
	//deno-lint-ignore hugoalh/symbol-description -- Private symbol.
	const s: symbol = Symbol();
	const keyScrypt: Uint8Array = await scrypt(key, key, keyLength, scryptOptions);
	setCPCEPSymmetricCryptor(s, {
		algorithm,
		ivLength,
		key: createSecretKey(keyScrypt),
		mode
	});
	//@ts-expect-error Private constructor.
	return new SymmetricCryptor(s);
}
/**
 * Create new instance of the {@link SymmetricCryptor symmetric cryptor}, synchronously.
 * @param {BinaryLike} key Key.
 * @param {SymmetricCryptorOptions} [options={}] Options.
 * @returns {SymmetricCryptor} New instance of the symmetric cryptor.
 */
export function createSymmetricCryptoSync(key: BinaryLike, options: SymmetricCryptorOptions = {}): SymmetricCryptor {
	const {
		algorithm = "aes-256-cbc",
		scrypt: scryptOptions
	}: SymmetricCryptorOptions = options;
	const {
		ivLength,
		keyLength,
		mode
	}: SymmetricCryptoAlgorithmInfo = getSymmetricCryptoAlgorithmInfo(algorithm);
	//deno-lint-ignore hugoalh/symbol-description -- Private symbol.
	const s: symbol = Symbol();
	const keyScrypt: Uint8Array = scryptSync(key, key, keyLength, scryptOptions);
	setCPCEPSymmetricCryptor(s, {
		algorithm,
		ivLength,
		key: createSecretKey(keyScrypt),
		mode
	});
	//@ts-expect-error Private constructor.
	return new SymmetricCryptor(s);
}
