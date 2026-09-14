import process from "node:process";
import {
	parseArgs,
	styleText
} from "node:util";
import { getSymmetricCryptoAlgorithms } from "./mod.ts";
if (!import.meta.main) {
	throw new Error(`This entrypoint is for command line only!`);
}
process.addListener("uncaughtException", (error: Error): void => {
	let message: string = error.message;
	if ((error.stack ?? "").length > 0) {
		message += `\n${error.stack}`;
	}
	console.error(`${styleText(["red"], "ERROR", { validateStream: false })}\t${message}`);
	process.exit(1);
});
const { positionals } = parseArgs({
	allowPositionals: true
});
if (positionals.length !== 1) {
	throw new SyntaxError(`Invalid arguments length! Expect: 1, Current: ${positionals.length}.`);
}
//deno-lint-ignore hugoalh/no-misuse-switch -- Pattern.
switch (positionals[0]) {
	case "algorithms":
		for (const algorithm of getSymmetricCryptoAlgorithms()) {
			console.log(algorithm);
		}
		break;
	default:
		throw new Error(`Unknown action \`${positionals[0]}\`!`);
}
