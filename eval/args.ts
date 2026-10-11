/**
 * Command-line options for the eval scripts: `--name value` options and `--flag` switches, taken out of the
 * arguments as they are read, so what is left (`rest`) is the positional arguments (files, a filter).
 */
export class Args {
	/** What has not been taken: the positional arguments, once every option is read. */
	readonly rest: string[];

	constructor(argv: readonly string[] = process.argv.slice(2)) {
		this.rest = [...argv];
	}

	/** The value of `--name value`, or `def` if absent. */
	opt(name: string, def: string): string;
	opt(name: string): string | undefined;
	opt(name: string, def?: string): string | undefined {
		const i = this.rest.indexOf(`--${name}`);
		return i >= 0 ? (this.rest.splice(i, 2)[1] ?? def) : def;
	}

	/** The number in `--name value`, or `def` if absent. */
	num(name: string, def: number): number {
		return Number(this.opt(name, String(def)));
	}

	/** Whether the switch `--name` is given. */
	flag(name: string): boolean {
		const i = this.rest.indexOf(`--${name}`);
		if (i >= 0) this.rest.splice(i, 1);
		return i >= 0;
	}
}
