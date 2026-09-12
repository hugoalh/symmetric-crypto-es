import {
	createDecipheriv,
	createHash,
	type Decipheriv
} from "node:crypto";
/**
 * **\[LEGACY\]**
 * 
 * Symmetric cryptor, a password based cryptor.
 * 
 * **Edition:** symencdec.1
 */
export class SymmetricCryptor {
	get [Symbol.toStringTag](): string {
		return "SymmetricCryptor";
	}
	#passphrase: Uint8Array;
	/**
	 * Initialize.
	 * @param {string} key Key.
	 */
	constructor(key: string) {
		this.#passphrase = Uint8Array.from(createHash("sha256").update(key).digest()).slice(0, 32);
	}
	#decrypt(data: string): string {
		const encrypted: Uint8Array = Uint8Array.fromBase64(data);
		const iv: Uint8Array = encrypted.slice(0, 16);
		const context: Uint8Array = encrypted.slice(16);
		const decipher: Decipheriv = createDecipheriv("aes-256-cbc", this.#passphrase, iv);
		const resultUpdate: Uint8Array = Uint8Array.from(decipher.update(context));
		const resultFinal: Uint8Array = Uint8Array.from(decipher.final());
		const result: Uint8Array = Uint8Array.from([...resultUpdate, ...resultFinal]);
		const resultString: string = new TextDecoder().decode(result);
		return resultString.slice(0, -(resultString.charCodeAt(resultString.length - 1)));
	}
	/**
	 * Decrypt the data.
	 * @param {string} data Data that need to decrypt.
	 * @returns {string} The decrypted data.
	 */
	decrypt(data: string): string {
		return this.#decrypt(data.replaceAll("\r\n", "\n").replaceAll("\r", "\n"));
	}
	/**
	 * Decrypt the data.
	 * @param {string} data Data that need to decrypt.
	 * @returns {string} The decrypted data.
	 */
	decryptMultipleLine(data: string): string {
		return data.replaceAll("\r\n", "\n").replaceAll("\r", "\n").split("\n").map((value: string): string => {
			return this.#decrypt(value);
		}).join("\n");
	}
}
export default SymmetricCryptor;
