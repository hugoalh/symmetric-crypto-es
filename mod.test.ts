import { deepStrictEqual } from "node:assert";
import {
	createSymmetricCrypto,
	type SymmetricCryptoAlgorithm
} from "./mod.ts";
const algorithms: readonly SymmetricCryptoAlgorithm[] = [/* UNIQUE */
	"aes-128-cbc",
	"aes-128-ctr",
	"aes-128-ecb",
	"aes-128-gcm",
	"aes-192-ctr",
	"aes-192-ecb",
	"aes-256-cbc",
	"aes-256-ctr",
	"aes-256-ecb",
	"aes-256-gcm",
	"des-ede3-cbc"
];
async function testerRaw(t: Deno.TestContext, key: string, context: Uint8Array): Promise<void> {
	for (const algorithm of algorithms) {
		await t.step(algorithm, async () => {
			const cryptor = await createSymmetricCrypto(key, { algorithm });
			const encrypted = cryptor.encrypt(context);
			console.log(encrypted);
			deepStrictEqual(cryptor.decrypt(encrypted), context);
		});
	}
}
Deno.test("Key Empty Raw Empty", { permissions: "none" }, async (t) => {
	await testerRaw(t, "", Uint8Array.from([]));
});
Deno.test("Raw Empty", { permissions: "none" }, async (t) => {
	await testerRaw(t, "QwErTyUiOp", Uint8Array.from([]));
});
Deno.test("Raw 1", { permissions: "none" }, async (t) => {
	await testerRaw(t, "QwErTyUiOp", new TextEncoder().encode("qwertyuiop"));
});
Deno.test("Raw 2", { permissions: "none" }, async (t) => {
	await testerRaw(t, "QwErTyUiOp", new TextEncoder().encode(`Accusam lorem nisl amet feugait commodo liber et. Diam sed amet et kasd et id lorem accusam voluptua elitr eirmod et justo diam clita consequat consetetur. Odio nonumy sadipscing dolor minim voluptua gubergren dolore vulputate vero dolor at sed lorem vero stet. Accusam justo ut lorem invidunt justo invidunt lobortis nobis. Erat duo ipsum sit eirmod lorem stet dolore dolor ipsum. Ipsum consetetur sit elitr et sit eum amet dolor et ut sanctus praesent sed et sed et.

Sanctus veniam rebum eleifend magna amet est sanctus no accusam rebum in nisl ea nulla takimata at nulla. Zzril et minim lorem aliquip sea amet clita consequat gubergren et voluptua dolor sed dolore sed consequat dolores stet. No labore sed molestie stet dolore diam amet diam ut. Sed ipsum gubergren velit eos duis takimata nulla invidunt justo accusam justo. Invidunt nulla iriure clita accumsan vero voluptua dolor. Gubergren tempor dolore minim sed sed aliquam consequat eleifend eirmod clita te eu. Feugiat justo dolore dolor eum takimata diam sit iusto delenit feugiat ipsum dolore exerci et nonumy et vel elitr. Eirmod in placerat consequat dolor ea est. Eirmod dolore facilisis invidunt eirmod. Kasd diam takimata imperdiet dolor illum elitr elitr autem vel. Augue sadipscing rebum sit amet eos aliquyam praesent tempor diam nonumy feugiat dolores kasd sed dolor. Consectetuer vulputate nonumy iriure gubergren et vel consetetur dolore esse magna diam dolore delenit. Sanctus stet eirmod. Eros vulputate elitr no.

Sit minim accusam elitr vulputate adipiscing vero consectetuer sea no no consequat facilisis ipsum consetetur. Diam clita ipsum duis sea esse vel sit at erat. Et vel quod velit nonummy dolore eirmod diam erat in sit hendrerit ipsum sea consetetur duis dignissim labore feugiat. Ut stet elitr lorem aliquyam euismod clita sit. Justo vero praesent. Tation ut nonumy et nonumy sit ut euismod consetetur diam sea nonumy aliquyam ea ut ad et velit. Et tempor eirmod nostrud ipsum dolor ullamcorper sanctus rebum et duis ex dolores ipsum possim sanctus sanctus sanctus aliquyam. Lobortis mazim no at dolor gubergren no ullamcorper diam et sit. No clita invidunt et erat kasd ex velit augue sanctus et labore minim molestie sed odio amet eirmod. Iusto tincidunt vero vero eos sed stet justo invidunt adipiscing sit aliquyam nibh at aliquam.

Accusam dolores et eirmod erat sadipscing lorem illum erat commodo vero gubergren. Ipsum facilisis et elit nonumy amet clita nonumy duis eirmod lorem dolores aliquip in sed at. Vero eirmod duo laoreet magna duo consetetur et et takimata. Dolore dignissim erat dolore accumsan stet diam diam gubergren eirmod aliquyam accusam et accusam et nulla et stet. Illum ut quod dolor magna ut elitr elit ullamcorper duis. Erat diam sed hendrerit vero sed ut eos veniam sanctus magna. Ea lorem iriure enim ut suscipit possim labore et volutpat. Placerat qui nisl at ipsum dolor diam dolor accusam. Diam sadipscing diam gubergren vulputate dolor dolore eirmod lorem gubergren blandit duo aliquyam. Rebum consetetur invidunt takimata voluptua et no voluptua aliquyam vel. Vero ut dolores. Feugait erat et. Sanctus dolor takimata lorem et clita sea accusam labore iusto et. Esse eirmod sed facilisis kasd. Diam elitr eos diam.

Takimata sea takimata est sit kasd et est lorem nibh in est diam. Ipsum vulputate erat amet invidunt justo te ipsum eos ipsum sed dolor. Amet no et diam. Amet ut et gubergren amet ut sed accusam duis et. Iriure kasd amet amet. In dolor sit hendrerit gubergren nulla et sea autem sanctus diam eos. Magna nonummy labore delenit clita lorem vero eirmod et nonumy sadipscing et ipsum elitr vel consetetur nonumy. Praesent eum at lobortis consequat dolor ut sanctus sadipscing sit. Accusam consetetur no velit aliquam et lorem assum in illum sed sea et et aliquip sea quod amet. Dolor zzril ut et sadipscing vero ut id dolore eu veniam velit kasd. Erat lorem sit consequat feugiat tation at sed dolore dolor sea autem in sadipscing dolore sed.`));
});
