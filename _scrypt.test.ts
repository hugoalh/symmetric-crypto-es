import {
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
	await t.step("Compare", () => {
		console.log(resultAsync);
		console.log(resultSync);
		ok(timingSafeEqual(resultAsync, resultSync));
	});
}
Deno.test("Empty 16", { permissions: "none" }, async (t) => {
	await tester(t, "", "", 16);
});
Deno.test("Empty 32", { permissions: "none" }, async (t) => {
	await tester(t, "", "", 32);
});
Deno.test("Empty 64", { permissions: "none" }, async (t) => {
	await tester(t, "", "", 64);
});
Deno.test("Empty 128", { permissions: "none" }, async (t) => {
	await tester(t, "", "", 128);
});
Deno.test("Random", { permissions: "none" }, async (t) => {
	for (let index = 0; index < 1000; index += 1) {
		const key = randomBytes(Math.ceil(Math.random() * 512));
		const keyLength = Math.ceil(Math.random() * 32) * 4;
		await t.step(`${key.length}:${keyLength}`, async (tt) => {
			await tester(tt, key, key, keyLength);
		});
	}
});
