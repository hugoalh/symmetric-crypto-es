import {
	decodeAscii85,
	encodeAscii85
} from "jsr:@std/encoding@^1.0.10/ascii85";
import { deepStrictEqual } from "node:assert";
import { SymmetricCryptor } from "./mod.ts";
const ignore = !(
	Deno.args.includes("--force") ||
	Deno.env.get("GITHUB_ACTIONS") === "true"
);
const sample1String = "qwertyuiop";
const sample1UInt8 = new TextEncoder().encode(sample1String);
const sample2String = `Accusam lorem nisl amet feugait commodo liber et. Diam sed amet et kasd et id lorem accusam voluptua elitr eirmod et justo diam clita consequat consetetur. Odio nonumy sadipscing dolor minim voluptua gubergren dolore vulputate vero dolor at sed lorem vero stet. Accusam justo ut lorem invidunt justo invidunt lobortis nobis. Erat duo ipsum sit eirmod lorem stet dolore dolor ipsum. Ipsum consetetur sit elitr et sit eum amet dolor et ut sanctus praesent sed et sed et.

Sanctus veniam rebum eleifend magna amet est sanctus no accusam rebum in nisl ea nulla takimata at nulla. Zzril et minim lorem aliquip sea amet clita consequat gubergren et voluptua dolor sed dolore sed consequat dolores stet. No labore sed molestie stet dolore diam amet diam ut. Sed ipsum gubergren velit eos duis takimata nulla invidunt justo accusam justo. Invidunt nulla iriure clita accumsan vero voluptua dolor. Gubergren tempor dolore minim sed sed aliquam consequat eleifend eirmod clita te eu. Feugiat justo dolore dolor eum takimata diam sit iusto delenit feugiat ipsum dolore exerci et nonumy et vel elitr. Eirmod in placerat consequat dolor ea est. Eirmod dolore facilisis invidunt eirmod. Kasd diam takimata imperdiet dolor illum elitr elitr autem vel. Augue sadipscing rebum sit amet eos aliquyam praesent tempor diam nonumy feugiat dolores kasd sed dolor. Consectetuer vulputate nonumy iriure gubergren et vel consetetur dolore esse magna diam dolore delenit. Sanctus stet eirmod. Eros vulputate elitr no.

Sit minim accusam elitr vulputate adipiscing vero consectetuer sea no no consequat facilisis ipsum consetetur. Diam clita ipsum duis sea esse vel sit at erat. Et vel quod velit nonummy dolore eirmod diam erat in sit hendrerit ipsum sea consetetur duis dignissim labore feugiat. Ut stet elitr lorem aliquyam euismod clita sit. Justo vero praesent. Tation ut nonumy et nonumy sit ut euismod consetetur diam sea nonumy aliquyam ea ut ad et velit. Et tempor eirmod nostrud ipsum dolor ullamcorper sanctus rebum et duis ex dolores ipsum possim sanctus sanctus sanctus aliquyam. Lobortis mazim no at dolor gubergren no ullamcorper diam et sit. No clita invidunt et erat kasd ex velit augue sanctus et labore minim molestie sed odio amet eirmod. Iusto tincidunt vero vero eos sed stet justo invidunt adipiscing sit aliquyam nibh at aliquam.

Accusam dolores et eirmod erat sadipscing lorem illum erat commodo vero gubergren. Ipsum facilisis et elit nonumy amet clita nonumy duis eirmod lorem dolores aliquip in sed at. Vero eirmod duo laoreet magna duo consetetur et et takimata. Dolore dignissim erat dolore accumsan stet diam diam gubergren eirmod aliquyam accusam et accusam et nulla et stet. Illum ut quod dolor magna ut elitr elit ullamcorper duis. Erat diam sed hendrerit vero sed ut eos veniam sanctus magna. Ea lorem iriure enim ut suscipit possim labore et volutpat. Placerat qui nisl at ipsum dolor diam dolor accusam. Diam sadipscing diam gubergren vulputate dolor dolore eirmod lorem gubergren blandit duo aliquyam. Rebum consetetur invidunt takimata voluptua et no voluptua aliquyam vel. Vero ut dolores. Feugait erat et. Sanctus dolor takimata lorem et clita sea accusam labore iusto et. Esse eirmod sed facilisis kasd. Diam elitr eos diam.

Takimata sea takimata est sit kasd et est lorem nibh in est diam. Ipsum vulputate erat amet invidunt justo te ipsum eos ipsum sed dolor. Amet no et diam. Amet ut et gubergren amet ut sed accusam duis et. Iriure kasd amet amet. In dolor sit hendrerit gubergren nulla et sea autem sanctus diam eos. Magna nonummy labore delenit clita lorem vero eirmod et nonumy sadipscing et ipsum elitr vel consetetur nonumy. Praesent eum at lobortis consequat dolor ut sanctus sadipscing sit. Accusam consetetur no velit aliquam et lorem assum in illum sed sea et et aliquip sea quod amet. Dolor zzril ut et sadipscing vero ut id dolore eu veniam velit kasd. Erat lorem sit consequat feugiat tation at sed dolore dolor sea autem in sadipscing dolore sed.`;
const sample2UInt8 = new TextEncoder().encode(sample2String);
Deno.test("Decrypt String 1 Base64", { permissions: "none" }, async () => {
	const cryptor = new SymmetricCryptor("<PassWord123456>!!");
	deepStrictEqual(await cryptor.decrypt("6zUMUyY3gQaKqCZZOcFGucdlpnQa5i97PfypJpByA+Y="), sample1String);
});
Deno.test("Decrypt String 1 Base64URL", { permissions: "none" }, async () => {
	const cryptor = new SymmetricCryptor("<PassWord123456>!!", { cipherTextCoder: "base64url" });
	deepStrictEqual(await cryptor.decrypt("6zUMUyY3gQaKqCZZOcFGucdlpnQa5i97PfypJpByA-Y="), sample1String);
});
Deno.test("Decrypt String 1 ASCII85", { permissions: "none" }, async () => {
	const cryptor = new SymmetricCryptor("<PassWord123456>!!", {
		cipherTextCoder: {
			decoder(data) {
				return decodeAscii85(data);
			},
			encoder(data) {
				return encodeAscii85(data);
			}
		}
	});
	deepStrictEqual(await cryptor.decrypt("lST)L-9$J[MPqk)3Pe1qa(;,i)Wi]\"4oD9+OE(Hc"), sample1String);
});
Deno.test("Full String AES-CBC 1", { permissions: "none" }, async () => {
	const cryptor = new SymmetricCryptor("<PassWord123456>!!");
	const encrypted = await cryptor.encrypt(sample1String);
	console.log(encrypted);
	deepStrictEqual(await cryptor.decrypt(encrypted), sample1String);
});
Deno.test("Full String AES-CBC 100", { permissions: "none" }, async () => {
	const cryptor = new SymmetricCryptor("<PassWord123456>!!", { times: 100 });
	const encrypted = await cryptor.encrypt(sample1String);
	console.log(encrypted);
	deepStrictEqual(await cryptor.decrypt(encrypted), sample1String);
});
Deno.test("Full UInt8 AES-CBC 1", { permissions: "none" }, async () => {
	const cryptor = new SymmetricCryptor("<PassWord123456>!!");
	const encrypted = await cryptor.encrypt(sample1UInt8);
	console.log(encrypted);
	deepStrictEqual(await cryptor.decrypt(encrypted), sample1UInt8);
});
Deno.test("Full UInt8 AES-CBC 100", { permissions: "none" }, async () => {
	const cryptor = new SymmetricCryptor("<PassWord123456>!!", { times: 100 });
	const encrypted = await cryptor.encrypt(sample1UInt8);
	console.log(encrypted);
	deepStrictEqual(await cryptor.decrypt(encrypted), sample1UInt8);
});
Deno.test("Full String AES-CTR 1", { permissions: "none" }, async () => {
	const cryptor = new SymmetricCryptor({
		algorithm: "AES-CTR",
		key: "<PassWord123456>!!"
	});
	const encrypted = await cryptor.encrypt(sample1String);
	console.log(encrypted);
	deepStrictEqual(await cryptor.decrypt(encrypted), sample1String);
});
Deno.test("Full String AES-CTR 100", { permissions: "none" }, async () => {
	const cryptor = new SymmetricCryptor({
		algorithm: "AES-CTR",
		key: "<PassWord123456>!!"
	}, { times: 100 });
	const encrypted = await cryptor.encrypt(sample1String);
	console.log(encrypted);
	deepStrictEqual(await cryptor.decrypt(encrypted), sample1String);
});
Deno.test("Full UInt8 AES-CTR 1", { permissions: "none" }, async () => {
	const cryptor = new SymmetricCryptor({
		algorithm: "AES-CTR",
		key: "<PassWord123456>!!"
	});
	const encrypted = await cryptor.encrypt(sample1UInt8);
	console.log(encrypted);
	deepStrictEqual(await cryptor.decrypt(encrypted), sample1UInt8);
});
Deno.test("Full UInt8 AES-CTR 100", { permissions: "none" }, async () => {
	const cryptor = new SymmetricCryptor({
		algorithm: "AES-CTR",
		key: "<PassWord123456>!!"
	}, { times: 100 });
	const encrypted = await cryptor.encrypt(sample1UInt8);
	console.log(encrypted);
	deepStrictEqual(await cryptor.decrypt(encrypted), sample1UInt8);
});
Deno.test("Full String AES-GCM 1", { permissions: "none" }, async () => {
	const cryptor = new SymmetricCryptor({
		algorithm: "AES-GCM",
		key: "<PassWord123456>!!"
	});
	const encrypted = await cryptor.encrypt(sample1String);
	console.log(encrypted);
	deepStrictEqual(await cryptor.decrypt(encrypted), sample1String);
});
Deno.test("Full String AES-GCM 100", { permissions: "none" }, async () => {
	const cryptor = new SymmetricCryptor({
		algorithm: "AES-GCM",
		key: "<PassWord123456>!!"
	}, { times: 100 });
	const encrypted = await cryptor.encrypt(sample1String);
	console.log(encrypted);
	deepStrictEqual(await cryptor.decrypt(encrypted), sample1String);
});
Deno.test("Full UInt8 AES-GCM 1", { permissions: "none" }, async () => {
	const cryptor = new SymmetricCryptor({
		algorithm: "AES-GCM",
		key: "<PassWord123456>!!"
	});
	const encrypted = await cryptor.encrypt(sample1UInt8);
	console.log(encrypted);
	deepStrictEqual(await cryptor.decrypt(encrypted), sample1UInt8);
});
Deno.test("Full UInt8 AES-GCM 100", { permissions: "none" }, async () => {
	const cryptor = new SymmetricCryptor({
		algorithm: "AES-GCM",
		key: "<PassWord123456>!!"
	}, { times: 100 });
	const encrypted = await cryptor.encrypt(sample1UInt8);
	console.log(encrypted);
	deepStrictEqual(await cryptor.decrypt(encrypted), sample1UInt8);
});
Deno.test("Full String AES-CBC,AES-CTR,AES-GCM", { permissions: "none" }, async () => {
	const cryptor = new SymmetricCryptor([
		{ algorithm: "AES-CBC", key: "<PassWord123456>!!" },
		{ algorithm: "AES-CTR", key: "<PassWord123456>!!" },
		{ algorithm: "AES-GCM", key: "<PassWord123456>!!" }
	]);
	const encrypted = await cryptor.encrypt(sample1String);
	console.log(encrypted);
	deepStrictEqual(await cryptor.decrypt(encrypted), sample1String);
});
Deno.test("Full UInt8 AES-CBC,AES-CTR,AES-GCM", { permissions: "none" }, async () => {
	const cryptor = new SymmetricCryptor([
		{ algorithm: "AES-CBC", key: "<PassWord123456>!!" },
		{ algorithm: "AES-CTR", key: "<PassWord123456>!!" },
		{ algorithm: "AES-GCM", key: "<PassWord123456>!!" }
	]);
	const encrypted = await cryptor.encrypt(sample1UInt8);
	console.log(encrypted);
	deepStrictEqual(await cryptor.decrypt(encrypted), sample1UInt8);
});
Deno.test("Full String Large AES-CBC,AES-CTR,AES-GCM", { permissions: "none" }, async () => {
	const cryptor = new SymmetricCryptor([
		{ algorithm: "AES-CBC", key: "<PassWord123456>!!" },
		{ algorithm: "AES-CTR", key: "<PassWord987654>!!" },
		{ algorithm: "AES-GCM", key: "<PassWord123456>!!" }
	]);
	const encrypted = await cryptor.encrypt(sample2String);
	console.log(encrypted);
	deepStrictEqual(await cryptor.decrypt(encrypted), sample2String);
});
Deno.test("Full UInt8 Large AES-CBC,AES-CTR,AES-GCM", { permissions: "none" }, async () => {
	const cryptor = new SymmetricCryptor([
		{ algorithm: "AES-CBC", key: "<PassWord123456>!!" },
		{ algorithm: "AES-CTR", key: "<PassWord987654>!!" },
		{ algorithm: "AES-GCM", key: "<PassWord123456>!!" }
	]);
	const encrypted = await cryptor.encrypt(sample2UInt8);
	console.log(encrypted);
	deepStrictEqual(await cryptor.decrypt(encrypted), sample2UInt8);
});
Deno.test("Full File Large AES-CBC,AES-CTR,AES-GCM", {
	ignore,
	permissions: {
		read: true,
		write: true
	}
}, async () => {
	const tempfile = await Deno.makeTempFile();
	try {
		const cryptor = new SymmetricCryptor([
			{ algorithm: "AES-CBC", key: "<PassWord123456>!!" },
			{ algorithm: "AES-CTR", key: "<PassWord987654>!!" },
			{ algorithm: "AES-GCM", key: "<PassWord123456>!!" }
		]);
		await cryptor.writeEncryptedTextFile(tempfile, sample2String);
		deepStrictEqual(await cryptor.readEncryptedTextFile(tempfile), sample2String);
	} finally {
		await Deno.remove(tempfile);
	}
});
