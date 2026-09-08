import {
	scrypt as scryptOriginal,
	scryptSync as scryptSyncOriginal,
	type BinaryLike,
	type ScryptOptions
} from "node:crypto";
export function scrypt(password: BinaryLike, salt: BinaryLike, keyLength: number, options: ScryptOptions = {}): Promise<Uint8Array> {
	return new Promise((resolve, reject): void => {
		scryptOriginal(password, salt, keyLength, options, (err: Error | null | undefined, derivedKey: Uint8Array): void => {
			if ((err ?? null) === null) {
				resolve(Uint8Array.from(derivedKey));
			} else {
				reject(err);
			}
		});
	});
}
export function scryptSync(password: BinaryLike, salt: BinaryLike, keyLength: number, options: ScryptOptions = {}): Uint8Array {
	return Uint8Array.from(scryptSyncOriginal(password, salt, keyLength, options));
}
