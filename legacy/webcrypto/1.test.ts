import { decodeAscii85 } from "jsr:@std/encoding@^1.0.11";
import { deepStrictEqual } from "node:assert";
import { createSymmetricCryptor } from "./1.ts";
Deno.test("Main", { permissions: "none" }, async () => {
	const sample = `qwertyuiop`;
	const cryptor = await createSymmetricCryptor("<PassWord123456>!!");
	deepStrictEqual(new TextDecoder().decode(await cryptor.decrypt(decodeAscii85("lST)L-9$J[MPqk)3Pe1qa(;,i)Wi]\"4oD9+OE(Hc"))), sample);
});
