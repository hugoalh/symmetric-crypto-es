import { SymmetricCryptorBasic } from "./basic.ts";
/**
 * A password based cryptor, with additional functions.
 */
export class SymmetricCryptorEnhance extends SymmetricCryptorBasic {
	override get [Symbol.toStringTag](): string {
		return "SymmetricCryptorEnhance";
	}
	/**
	 * Decrypt the file in place. File will not decrypted if fail to decrypt.
	 * 
	 * > **🛡️ Runtime Permissions**
	 * > 
	 * > - **File System - Read (Deno: `read`; NodeJS: `fs-read`):**
	 * >   - *Resources*
	 * > - **File System - Write (Deno: `write`; NodeJS: `fs-write`):**
	 * >   - *Resources*
	 * @param {string | URL} filePath Path of the file.
	 * @returns {Promise<void>}
	 */
	async decryptFileInPlace(filePath: string | URL): Promise<void> {
		return await Deno.writeFile(filePath, await this.decrypt(await Deno.readFile(filePath)), { create: false });
	}
	/**
	 * Encrypt the file in place. File will not encrypted if fail to encrypt.
	 * 
	 * > **🛡️ Runtime Permissions**
	 * > 
	 * > - **File System - Read (Deno: `read`; NodeJS: `fs-read`):**
	 * >   - *Resources*
	 * > - **File System - Write (Deno: `write`; NodeJS: `fs-write`):**
	 * >   - *Resources*
	 * @param {string | URL} filePath Path of the file.
	 * @returns {Promise<void>}
	 */
	async encryptFileInPlace(filePath: string | URL): Promise<void> {
		return await Deno.writeFile(filePath, await this.encrypt(await Deno.readFile(filePath)), { create: false });
	}
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
		return await this.decrypt(await Deno.readFile(filePath, options));
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
	 * @returns {Promise<void>}
	 */
	async writeEncryptedFile(filePath: string | URL, data: Uint8Array, options?: Omit<Deno.WriteFileOptions, "append">): Promise<void> {
		return await Deno.writeFile(filePath, await this.encrypt(data), {
			...options,
			append: false
		});
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
	 * @returns {Promise<void>}
	 */
	async writeEncryptedTextFile(filePath: string | URL, data: string, options?: Omit<Deno.WriteFileOptions, "append">): Promise<void> {
		return await this.writeEncryptedFile(filePath, new TextEncoder().encode(data), options);
	}
}
export default SymmetricCryptorEnhance;
