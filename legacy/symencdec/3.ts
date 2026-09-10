import {
	createDecipheriv,
	createHash,
	type Decipheriv
} from "node:crypto";
function checkTimes(times: number): void {
	if (!(Number.isSafeInteger(times) && times >= 1)) {
		throw new TypeError(`Parameter \`times\` is not a number which is integer, safe, and >= 1!`);
	}
}
/**
 * \[LEGACY: symencdec.3\]
 * 
 * Symmetric cryptor, a password based cryptor.
 */
export class SymmetricCryptorLegacy {
	get [Symbol.toStringTag](): string {
		return "SymmetricCryptorLegacy";
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
	 * @param {number} [times=1] Times of the crypto.
	 * @returns {string} The decrypted data.
	 */
	decrypt(data: string, times: number = 1): string {
		checkTimes(times);
		let result: string = data;
		for (let index: number = 0; index < times; index += 1) {
			result = this.#decrypt(result);
		}
		return result;
	}
	/**
	 * Decrypt the data.
	 * @param {string} data Data that need to decrypt.
	 * @param {number} [times=1] Times of the crypto.
	 * @returns {string} The decrypted data.
	 */
	decryptMultipleLine(data: string, times: number = 1): string {
		checkTimes(times);
		let result: string = data;
		for (let index: number = 0; index < times; index += 1) {
			result = result.split("\r\n").map((valueRN: string): string => {
				return valueRN.split("\n").map((valueN: string): string => {
					return (valueN.length > 0) ? this.#decrypt(valueN) : "";
				}).join("\n");
			}).join("\r\n");
		}
		return result;
	}
}
export default SymmetricCryptorLegacy;
