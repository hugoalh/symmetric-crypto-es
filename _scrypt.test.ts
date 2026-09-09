import {
	deepStrictEqual,
	doesNotReject,
	doesNotThrow,
	ok
} from "node:assert";
import {
	randomBytes,
	timingSafeEqual,
	type BinaryLike,
	type ScryptOptions
} from "node:crypto";
import {
	scrypt,
	scryptSync
} from "./_scrypt.ts";
async function tester(t: Deno.TestContext, password: BinaryLike, salt: BinaryLike, keyLength: number, options?: ScryptOptions): Promise<void> {
	let resultAsync: Uint8Array = new Uint8Array();
	await t.step("Async", async () => {
		await doesNotReject(async () => {
			resultAsync = await scrypt(password, salt, keyLength, options);
		});
	});
	let resultSync: Uint8Array = new Uint8Array();
	await t.step("Sync", () => {
		doesNotThrow(() => {
			resultSync = scryptSync(password, salt, keyLength, options);
		});
	});
	await t.step("Assert", () => {
		deepStrictEqual(resultAsync.length, keyLength);
		deepStrictEqual(resultSync.length, keyLength);
	});
	await t.step("Compare", () => {
		ok(timingSafeEqual(resultAsync, resultSync));
	});
}
Deno.test("I:0; O:12", { permissions: "none" }, async (t) => {
	await tester(t, "", "", 12);
});
Deno.test("I:0; O:16", { permissions: "none" }, async (t) => {
	await tester(t, "", "", 16);
});
Deno.test("I:0; O:24", { permissions: "none" }, async (t) => {
	await tester(t, "", "", 24);
});
Deno.test("I:0; O:32", { permissions: "none" }, async (t) => {
	await tester(t, "", "", 32);
});
Deno.test("Random", { permissions: "none" }, async (t) => {
	for (let index = 0; index < 500; index += 1) {
		const key = randomBytes(Math.ceil(Math.random() * 512));
		const keyLength = Math.ceil(Math.random() * 32) * 4;
		await t.step(`I:${key.length}; O:${keyLength}`, async (tt) => {
			await tester(tt, key, key, keyLength);
		});
	}
});
