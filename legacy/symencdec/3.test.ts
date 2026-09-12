import { deepStrictEqual } from "node:assert";
import { SymmetricCryptor } from "./3.ts";
Deno.test("1", { permissions: "none" }, async (t) => {
	const sample = `Hello, world!\nFoo.\nBar.`;
	const cryptor = new SymmetricCryptor("githubnode");
	await t.step("Single Line", () => {
		deepStrictEqual(cryptor.decrypt("TIdMOTTeor6q79ilfKkcInvWqQ/U4UUK5oXRSXxWhTbNpL88i/QDly9NFCt1d6JwkDWJ0nkLGKwsWbcA6tM2yg=="), sample);
	});
	await t.step("Multiple Line", () => {
		deepStrictEqual(cryptor.decryptMultipleLine(`LO1uspz3yPXlbDdi20Xk5kYPc06kZO3h0SH6mN+gCI/+xTRpeanWPNat17ufGpxE
NdLVDbUWDAeBK1MdXoO4rIbpBbwiCyaPU0ut8HOCCLXnidGM9EEbevuL8EGjQVSS
nh3fuCzHOXWhtBLHuIZyiz5n9/Om0uPZdHdEikei8ydjnpaVLaCT2p78Uamxc3m1`), sample);
	});
});
