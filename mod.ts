import {
	createCipheriv,
	createDecipheriv,
	createSecretKey,
	getCipherInfo,
	getCiphers,
	randomBytes,
	scrypt,
	scryptSync,
	type BinaryLike,
	type CipherInfo,
	type Cipheriv,
	type Decipheriv,
	type KeyObject,
	type ScryptOptions
} from "node:crypto";
export type SymmetricCryptoAlgorithm =
	| "aes-128-cbc"
	| "aes-128-ctr"
	| "aes-128-ecb"
	/* | "aes-128-gcm" */
	| "aes-192-ctr"
	| "aes-192-ecb"
	| "aes-256-cbc"
	| "aes-256-ctr"
	| "aes-256-ecb"
	/* | "aes-256-gcm" */;
const algorithmsSelect: readonly SymmetricCryptoAlgorithm[] = [/* UNIQUE */
	"aes-128-cbc",
	"aes-128-ctr",
	"aes-128-ecb",
	// "aes-128-gcm",
	"aes-192-ctr",
	"aes-192-ecb",
	"aes-256-cbc",
	"aes-256-ctr",
	"aes-256-ecb",
	// "aes-256-gcm"
];
const algorithmsSupport: readonly string[] = getCiphers();
const algorithmsFinal: readonly string[] = algorithmsSupport.filter((algorithm: string): boolean => {
	return algorithmsSelect.includes(algorithm as SymmetricCryptoAlgorithm);
}).sort();
class SymmetricCryptorDecryptPipe extends TransformStream<Uint8Array, Uint8Array> {
	#algorithm: SymmetricCryptoAlgorithm;
	#bin: Uint8Array = new Uint8Array();
	#decipher?: Decipheriv;
	#ivLength: number;
	#key: KeyObject;
	constructor(algorithm: SymmetricCryptoAlgorithm, ivLength: number, key: KeyObject) {
		super({
			transform: (chunk: Uint8Array, controller: TransformStreamDefaultController<Uint8Array>): void => {
				if (this.#decipher) {
					controller.enqueue(this.#decipher.update(chunk));
				} else {
					this.#bin = Uint8Array.from([...this.#bin, ...chunk]);
					if (this.#bin.length >= this.#ivLength) {
						const iv: Uint8Array = this.#bin.slice(0, this.#ivLength);
						const context: Uint8Array = this.#bin.slice(this.#ivLength);
						this.#decipher = createDecipheriv(this.#algorithm, this.#key, iv);
						if (context.length > 0) {
							controller.enqueue(this.#decipher.update(context));
						}
					}
				}
			},
			flush: (controller: TransformStreamDefaultController<Uint8Array>): void => {
				if (this.#decipher) {
					controller.enqueue(this.#decipher.final());
				}
			}
		});
		this.#algorithm = algorithm;
		this.#ivLength = ivLength;
		this.#key = key;
	}
}
class SymmetricCryptorEncryptPipe extends TransformStream<Uint8Array, Uint8Array> {
	#cipher: Cipheriv;
	#iv: Uint8Array;
	constructor(algorithm: SymmetricCryptoAlgorithm, ivLength: number, key: KeyObject) {
		super({
			start: (controller: TransformStreamDefaultController<Uint8Array>): void => {
				controller.enqueue(this.#iv);
			},
			transform: (chunk: Uint8Array, controller: TransformStreamDefaultController<Uint8Array>): void => {
				controller.enqueue(Uint8Array.from(this.#cipher.update(chunk)));
			},
			flush: (controller: TransformStreamDefaultController<Uint8Array>): void => {
				controller.enqueue(Uint8Array.from(this.#cipher.final()));
			}
		});
		this.#iv = randomBytes(ivLength);
		this.#cipher = createCipheriv(algorithm, key, this.#iv);
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
export interface SymmetricCryptorInterface {
	createDecryptPipe(): TransformStream<Uint8Array>;
	createEncryptPipe(): TransformStream<Uint8Array>;
	decrypt(data: Uint8Array): Uint8Array;
	encrypt(data: Uint8Array): Uint8Array;
}
class SymmetricCryptor implements SymmetricCryptorInterface {
	get [Symbol.toStringTag](): string {
		return "SymmetricCryptor";
	}
	#algorithm: SymmetricCryptoAlgorithm;
	#ivLength: number;
	#key: KeyObject;
	constructor(algorithm: SymmetricCryptoAlgorithm, ivLength: number, key: KeyObject) {
		this.#algorithm = algorithm;
		this.#ivLength = ivLength;
		this.#key = key;
	}
	createDecryptPipe(): TransformStream<Uint8Array> {
		return new SymmetricCryptorDecryptPipe(this.#algorithm, this.#ivLength, this.#key);
	}
	createEncryptPipe(): TransformStream<Uint8Array> {
		return new SymmetricCryptorEncryptPipe(this.#algorithm, this.#ivLength, this.#key);
	}
	decrypt(data: Uint8Array): Uint8Array {
		const iv: Uint8Array = data.slice(0, this.#ivLength);
		const context: Uint8Array = data.slice(this.#ivLength);
		const decipher: Decipheriv = createDecipheriv(this.#algorithm, this.#key, iv);
		const resultUpdate: Uint8Array = Uint8Array.from(decipher.update(context));
		const resultFinal: Uint8Array = Uint8Array.from(decipher.final());
		return Uint8Array.from([...resultUpdate, ...resultFinal]);
	}
	encrypt(data: Uint8Array): Uint8Array {
		const iv: Uint8Array = randomBytes(this.#ivLength);
		const cipher: Cipheriv = createCipheriv(this.#algorithm, this.#key, iv);
		const resultUpdate: Uint8Array = Uint8Array.from(cipher.update(data));
		const resultFinal: Uint8Array = Uint8Array.from(cipher.final());
		return Uint8Array.from([...iv, ...resultUpdate, ...resultFinal]);
	}
}
function resolveSymmetricCryptorInfo(algorithm: SymmetricCryptoAlgorithm): CipherInfo {
	if (!algorithmsSelect.includes(algorithm.toLowerCase() as SymmetricCryptoAlgorithm)) {
		throw new Error(`\`${algorithm}\` is not a valid cipher algorithm! Only accept these values: ${algorithmsSelect.join(", ")}`);
	}
	if (!algorithmsSupport.includes(algorithm.toLowerCase())) {
		throw new Error(`\`${algorithm}\` is not a cipher algorithm which support by the runtime! Only accept these values: ${algorithmsFinal.join(", ")}`);
	}
	const info: CipherInfo | undefined = getCipherInfo(algorithm);
	if (typeof info === "undefined") {
		throw new Error(`Unable to get the information of the cipher algorithm \`${algorithm}\`!`);
	}
	return info;
}
function scryptPromise(...params: Parameters<typeof scryptSync>): Promise<ReturnType<typeof scryptSync>> {
	return new Promise((resolve, reject): void => {
		//@ts-ignore Overload.
		scrypt(...params, (err, derivedKey): void => {
			if ((err ?? null) === null) {
				resolve(derivedKey);
			} else {
				reject(err);
			}
		});
	});
}
export async function createSymmetricCrypto(key: BinaryLike, options: SymmetricCryptorOptions = {}): Promise<SymmetricCryptor> {
	const {
		algorithm = "aes-256-cbc",
		scrypt: scryptOptions
	}: SymmetricCryptorOptions = options;
	const info: CipherInfo = resolveSymmetricCryptorInfo(algorithm);
	const ivLength: number = info.ivLength ?? 16;
	const keyScrypt: Uint8Array = Uint8Array.from(await scryptPromise(key, key, info.keyLength, scryptOptions));
	const keyObject: KeyObject = createSecretKey(keyScrypt);
	return new SymmetricCryptor(algorithm, ivLength, keyObject);
}
export function createSymmetricCryptoSync(key: BinaryLike, options: SymmetricCryptorOptions = {}): SymmetricCryptor {
	const {
		algorithm = "aes-256-cbc",
		scrypt: scryptOptions
	}: SymmetricCryptorOptions = options;
	const info: CipherInfo = resolveSymmetricCryptorInfo(algorithm);
	const ivLength: number = info.ivLength ?? 16;
	const keyScrypt: Uint8Array = Uint8Array.from(scryptSync(key, key, info.keyLength, scryptOptions));
	const keyObject: KeyObject = createSecretKey(keyScrypt);
	return new SymmetricCryptor(algorithm, ivLength, keyObject);
}
