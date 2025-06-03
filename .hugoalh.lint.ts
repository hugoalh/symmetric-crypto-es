import { configurePlugin } from "HUGOALH_DENO_LINT_RULES";
export default configurePlugin({
	rules: {
		"max-complexity": true,
		"max-file-size": true,
		"no-alert": true,
		"no-character-ambiguous": true,
		"no-character-invisible": true,
		"no-confirm": true,
		"no-decorator": true,
		"no-iife": true,
		"no-import-dynamic": true,
		"no-import-npm": true,
		"no-prompt": true,
		"prefer-symbol-description": true
	}
}) satisfies Deno.lint.Plugin as Deno.lint.Plugin;
