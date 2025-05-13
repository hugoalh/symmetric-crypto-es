import {
	decodeAscii85,
	encodeAscii85
} from "jsr:@std/encoding@^1.0.10";
export type SymmetricCryptorAlgorithm =
	| "AES-CBC"
	| "AES-CTR"
	| "AES-GCM";
const algorithms: Readonly<Record<string, SymmetricCryptorAlgorithm>> = {
	"AES-CBC": "AES-CBC",
	"AES-CTR": "AES-CTR",
	"AES-GCM": "AES-GCM",
	AESCBC: "AES-CBC",
	AESCTR: "AES-CTR",
	AESGCM: "AES-GCM"
};
export type SymmetricCryptorCipherTextDecoder = (input: string) => Uint8Array | Promise<Uint8Array>;
export type SymmetricCryptorCipherTextEncoder = (input: Uint8Array) => string | Promise<string>;
/**
 * Type of the key of the symmetric cryptor.
 */
export type SymmetricCryptorKeyType = string | ArrayBuffer | DataView | Uint8Array | Uint16Array | Uint32Array | BigUint64Array;
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
interface SymmetricCryptorKey {
	algorithm: `${SymmetricCryptorAlgorithm}`;
	key: CryptoKey;
}
interface SymmetricCryptorFileIO {
	context: Uint8Array;
	filePath: string | URL;
}
/**
 * A password based cryptor.
 */
export class SymmetricCryptor {
	get [Symbol.toStringTag](): string {
		return "SymmetricCryptor";
	}
	#cryptors: readonly SymmetricCryptorKey[];
	#decoder: SymmetricCryptorCipherTextDecoder;
	#encoder: SymmetricCryptorCipherTextEncoder;
	private constructor(cryptors: readonly SymmetricCryptorKey[], decoder: SymmetricCryptorCipherTextDecoder, encoder: SymmetricCryptorCipherTextEncoder) {
		this.#cryptors = cryptors;
		this.#decoder = decoder;
		this.#encoder = encoder;
	}
	async #decrypt(data: Uint8Array): Promise<Uint8Array> {
		if (data.length === 0) {
			return data;
		}
		let storage: Uint8Array = new Uint8Array(data);
		for (const {
			algorithm,
			key
		} of [...this.#cryptors].reverse()) {
			let decryptParameterAlgorithm: AlgorithmIdentifier | AesCbcParams | AesCtrParams | AesGcmParams;
			let decryptParameterData: BufferSource;
			switch (algorithm) {
				case "AES-CBC":
					decryptParameterAlgorithm = {
						name: algorithm,
						iv: storage.slice(0, 16)
					};
					decryptParameterData = storage.slice(16);
					break;
				case "AES-CTR":
					decryptParameterAlgorithm = {
						name: algorithm,
						counter: storage.slice(0, 16),
						length: 64
					};
					decryptParameterData = storage.slice(16);
					break;
				case "AES-GCM":
					decryptParameterAlgorithm = {
						name: algorithm,
						iv: storage.slice(0, 12)
					};
					decryptParameterData = storage.slice(12);
					break;
				default:
					throw new Error(`\`${algorithm}\` is not a symmetric crypto algorithm which able to process! How did you get to here?`);
			}
			storage = new Uint8Array(await crypto.subtle.decrypt(decryptParameterAlgorithm, key, decryptParameterData));
		}
		return storage;
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
			return new TextDecoder().decode(await this.#decrypt(await this.#decoder(data)));
		}
		return this.#decrypt(data);
	}
	/**
	 * Decrypt the files in place. All of the files will not decrypted if any file fail to decrypt.
	 * 
	 * > **🛡️ Runtime Permissions**
	 * > 
	 * > - **File System - Read (Deno: `read`; NodeJS: `fs-read`):**
	 * >   - *Resources*
	 * > - **File System - Write (Deno: `write`; NodeJS: `fs-write`):**
	 * >   - *Resources*
	 * @param {...(string | URL)} filesPath Path of the files.
	 * @returns {Promise<this>}
	 */
	async decryptFile(...filesPath: (string | URL)[]): Promise<this> {
		const result: SymmetricCryptorFileIO[] = await Promise.all(filesPath.map(async (filePath: string | URL): Promise<SymmetricCryptorFileIO> => {
			try {
				return {
					context: await this.#decrypt(await Deno.readFile(filePath)),
					filePath
				};
			} catch (error) {
				throw new Error(`Unable to decrypt the file \`${filePath}\`: ${(error as Error)?.message ?? error}`);
			}
		}));
		await Promise.all(result.map(({
			context,
			filePath
		}: SymmetricCryptorFileIO): Promise<void> => {
			return Deno.writeFile(filePath, context, { create: false });
		}));
		return this;
	}
	/**
	 * Decrypt the files in place. All of the files will not decrypted if any file fail to decrypt.
	 * 
	 * > **🛡️ Runtime Permissions**
	 * > 
	 * > - **File System - Read (Deno: `read`; NodeJS: `fs-read`):**
	 * >   - *Resources*
	 * > - **File System - Write (Deno: `write`; NodeJS: `fs-write`):**
	 * >   - *Resources*
	 * @deprecated Migrate to {@linkcode SymmetricCryptor.decryptFile}.
	 */
	decryptFiles: (...filesPath: (string | URL)[]) => Promise<this> = this.decryptFile;
	async #encrypt(data: Uint8Array): Promise<Uint8Array> {
		if (data.length === 0) {
			return data;
		}
		let storage: Uint8Array = new Uint8Array(data);
		for (const {
			algorithm,
			key
		} of this.#cryptors) {
			let encryptParameterAlgorithm: AlgorithmIdentifier | AesCbcParams | AesCtrParams | AesGcmParams;
			let token: Uint8Array;
			switch (algorithm) {
				case "AES-CBC":
					token = crypto.getRandomValues(new Uint8Array(16));
					encryptParameterAlgorithm = {
						name: algorithm,
						iv: token
					};
					break;
				case "AES-CTR":
					token = crypto.getRandomValues(new Uint8Array(16));
					encryptParameterAlgorithm = {
						name: algorithm,
						counter: token,
						length: 64
					};
					break;
				case "AES-GCM":
					token = crypto.getRandomValues(new Uint8Array(12));
					encryptParameterAlgorithm = {
						name: algorithm,
						iv: token
					};
					break;
				default:
					throw new Error(`\`${algorithm}\` is not a symmetric crypto algorithm which able to process! How did you get to here?`);
			}
			storage = Uint8Array.from([...token, ...new Uint8Array(await crypto.subtle.encrypt(encryptParameterAlgorithm, key, storage))]);
		}
		return storage;
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
			return this.#encoder(await this.#encrypt(new TextEncoder().encode(data)));
		}
		return this.#encrypt(data);
	}
	/**
	 * Encrypt the files in place. All of the files will not encrypted if any file fail to encrypt.
	 * 
	 * > **🛡️ Runtime Permissions**
	 * > 
	 * > - **File System - Read (Deno: `read`; NodeJS: `fs-read`):**
	 * >   - *Resources*
	 * > - **File System - Write (Deno: `write`; NodeJS: `fs-write`):**
	 * >   - *Resources*
	 * @param {...(string | URL)} filesPath Path of the files.
	 * @returns {Promise<this>}
	 */
	async encryptFile(...filesPath: (string | URL)[]): Promise<this> {
		const result: SymmetricCryptorFileIO[] = await Promise.all(filesPath.map(async (filePath: string | URL): Promise<SymmetricCryptorFileIO> => {
			try {
				return {
					context: await this.#encrypt(await Deno.readFile(filePath)),
					filePath
				};
			} catch (error) {
				throw new Error(`Unable to encrypt the file \`${filePath}\`: ${(error as Error)?.message ?? error}`);
			}
		}));
		await Promise.all(result.map(({
			context,
			filePath
		}: SymmetricCryptorFileIO): Promise<void> => {
			return Deno.writeFile(filePath, context, { create: false });
		}));
		return this;
	}
	/**
	 * Encrypt the files in place. All of the files will not encrypted if any file fail to encrypt.
	 * 
	 * > **🛡️ Runtime Permissions**
	 * > 
	 * > - **File System - Read (Deno: `read`; NodeJS: `fs-read`):**
	 * >   - *Resources*
	 * > - **File System - Write (Deno: `write`; NodeJS: `fs-write`):**
	 * >   - *Resources*
	 * @deprecated Migrate to {@linkcode SymmetricCryptor.encryptFile}.
	 */
	encryptFiles: (...filesPath: (string | URL)[]) => Promise<this> = this.encryptFile;
	/**
	 * Read the encrypted file.
	 * 
	 * > **🛡️ Runtime Permissions**
	 * > 
	 * > - **File System - Read (Deno: `read`; NodeJS: `fs-read`):**
	 * >   - *Resources*
	 * @param {string | URL} filePath Path of the file.
	 * @param {Deno.ReadFileOptions} [options={}] Options.
	 * @returns {Promise<Uint8Array>} Decrypted data of the file.
	 */
	async readEncryptedFile(filePath: string | URL, options?: Deno.ReadFileOptions): Promise<Uint8Array> {
		return this.#decrypt(await Deno.readFile(filePath, options));
	}
	/**
	 * Read the encrypted text file.
	 * 
	 * > **🛡️ Runtime Permissions**
	 * > 
	 * > - **File System - Read (Deno: `read`; NodeJS: `fs-read`):**
	 * >   - *Resources*
	 * @param {string | URL} filePath Path of the file.
	 * @param {Deno.ReadFileOptions} [options={}] Options.
	 * @returns {Promise<string>} Decrypted text data of the file.
	 */
	async readEncryptedTextFile(filePath: string | URL, options?: Deno.ReadFileOptions): Promise<string> {
		return new TextDecoder().decode(await this.readEncryptedFile(filePath, options));
	}
	/**
	 * Write the encrypted file.
	 * 
	 * > **🛡️ Runtime Permissions**
	 * > 
	 * > - **File System - Write (Deno: `write`; NodeJS: `fs-write`):**
	 * >   - *Resources*
	 * @param {string | URL} filePath Path of the file.
	 * @param {Uint8Array} data Data of the file.
	 * @param {Omit<Deno.WriteFileOptions, "append">} [options={}] Options.
	 * @returns {Promise<this>}
	 */
	async writeEncryptedFile(filePath: string | URL, data: Uint8Array, options?: Omit<Deno.WriteFileOptions, "append">): Promise<this> {
		await Deno.writeFile(filePath, await this.#encrypt(data), {
			...options,
			append: false
		});
		return this;
	}
	/**
	 * Write the encrypted text file.
	 * 
	 * > **🛡️ Runtime Permissions**
	 * > 
	 * > - **File System - Write (Deno: `write`; NodeJS: `fs-write`):**
	 * >   - *Resources*
	 * @param {string | URL} filePath Path of the file.
	 * @param {string} data Text data of the file.
	 * @param {Omit<Deno.WriteFileOptions, "append">} [options={}] Options.
	 * @returns {Promise<this>}
	 */
	async writeEncryptedTextFile(filePath: string | URL, data: string, options?: Omit<Deno.WriteFileOptions, "append">): Promise<this> {
		await this.writeEncryptedFile(filePath, new TextEncoder().encode(data), options);
		return this;
	}
}
async function createCryptorKey(input: SymmetricCryptorKeyInput | SymmetricCryptorKeyType): Promise<SymmetricCryptorKey> {
	let algorithm: SymmetricCryptorAlgorithm;
	let key: SymmetricCryptorKeyType;
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
		const algorithmFmt: SymmetricCryptorAlgorithm | undefined = algorithms[input.algorithm ?? "AES-CBC"];
		if (typeof algorithmFmt === "undefined") {
			throw new RangeError(`\`${input.algorithm}\` is not a valid symmetric crypto algorithm! Only accept these values: ${Object.keys(algorithms).sort().join(", ")}`);
		}
		algorithm = algorithmFmt;
		key = input.key;
	}
	return {
		algorithm,
		key: await crypto.subtle.importKey("raw", await crypto.subtle.digest("SHA-256", (typeof key === "string") ? new TextEncoder().encode(key) : key), { name: algorithm }, false, ["decrypt", "encrypt"])
	};
}
export interface SymmetricCryptorOptions {
	/**
	 * Decoder of the stringify cipher text, must also define and exchangeable with property {@linkcode encoder}. Default to use the ASCII85 decoder.
	 */
	decoder?: SymmetricCryptorCipherTextDecoder;
	/**
	 * Encoder of the stringify cipher text, must also define and exchangeable with property {@linkcode decoder}. Default to use the ASCII85 encoder.
	 */
	encoder?: SymmetricCryptorCipherTextEncoder;
	/**
	 * Times of the crypto.
	 * @default {1}
	 */
	times?: number;
}
/**
 * Create an instance of the class {@linkcode SymmetricCryptor}.
 * @param {SymmetricCryptorKeyInput | SymmetricCryptorKeyType} key Key of the symmetric cryptor.
 * @param {SymmetricCryptorOptions} [options={}] Options of the symmetric cryptor.
 * @returns {Promise<SymmetricCryptor>} An instance of the class {@linkcode SymmetricCryptor}.
 */
export async function createSymmetricCryptor(key: SymmetricCryptorKeyInput | SymmetricCryptorKeyType, options?: SymmetricCryptorOptions): Promise<SymmetricCryptor>;
/**
 * Create an instance of the class {@linkcode SymmetricCryptor}.
 * @param {(SymmetricCryptorKeyInput | SymmetricCryptorKeyType)[]} keys Keys of the symmetric cryptor.
 * @param {Omit<SymmetricCryptorOptions, "times">} [options={}] Options of the symmetric cryptor.
 * @returns {Promise<SymmetricCryptor>} An instance of the class {@linkcode SymmetricCryptor}.
 */
export async function createSymmetricCryptor(keys: (SymmetricCryptorKeyInput | SymmetricCryptorKeyType)[], options?: Omit<SymmetricCryptorOptions, "times">): Promise<SymmetricCryptor>;
export async function createSymmetricCryptor(param0: SymmetricCryptorKeyInput | SymmetricCryptorKeyType | (SymmetricCryptorKeyInput | SymmetricCryptorKeyType)[], options: SymmetricCryptorOptions = {}): Promise<SymmetricCryptor> {
	if (!(
		(typeof options.decoder !== "undefined" && typeof options.encoder !== "undefined") ||
		(typeof options.decoder === "undefined" && typeof options.encoder === "undefined")
	)) {
		throw new ReferenceError(`Parameters \`options.decoder\` and \`options.encoder\` are not all defined or all undefined!`);
	}
	const decoder: SymmetricCryptorCipherTextDecoder = options.decoder ?? decodeAscii85;
	const encoder: SymmetricCryptorCipherTextEncoder = options.encoder ?? encodeAscii85;
	const cryptors: SymmetricCryptorKey[] = [];
	if (Array.isArray(param0)) {
		cryptors.push(...await Promise.all(param0.map((input: SymmetricCryptorKeyInput | SymmetricCryptorKeyType): Promise<SymmetricCryptorKey> => {
			return createCryptorKey(input);
		})));
	} else {
		const cryptor: SymmetricCryptorKey = await createCryptorKey(param0);
		if (typeof options.times === "undefined") {
			cryptors.push(cryptor);
		} else {
			if (!(Number.isSafeInteger(options.times) && options.times >= 1)) {
				throw new TypeError(`\`${options.times}\` (parameter \`options.times\`) is not a number which is integer, safe, and >= 1!`);
			}
			for (let index: number = 0; index < options.times; index += 1) {
				cryptors.push(cryptor);
			}
		}
	}
	if (cryptors.length > 0) {
		//@ts-ignore Access private constructor.
		return new SymmetricCryptor(cryptors, decoder, encoder);
	}
	throw new ReferenceError(`Parameter \`keys\` is not defined!`);
}
export default createSymmetricCryptor;
