import { SymmetricCryptorBasic } from "./basic.ts";
/**
 * A password based cryptor, with standard functions.
 */
export class SymmetricCryptor extends SymmetricCryptorBasic {
	override get [Symbol.toStringTag](): string {
		return "SymmetricCryptor";
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
		const context: Uint8Array = await Deno.readFile(filePath);
		const decrypted: Uint8Array = await this.decrypt(context);
		return await Deno.writeFile(filePath, decrypted, { create: false });
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
		const context: Uint8Array = await Deno.readFile(filePath);
		const encrypted: Uint8Array = await this.encrypt(context);
		return await Deno.writeFile(filePath, encrypted, { create: false });
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
		const context: Uint8Array = await Deno.readFile(filePath, options);
		return await this.decrypt(context);
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
		const encrypted: Uint8Array = await this.encrypt(data);
		return await Deno.writeFile(filePath, encrypted, {
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
export default SymmetricCryptor;
