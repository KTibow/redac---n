/**
 * SQL `INSERT … VALUES` statements read into cells: each row's values under their table and column. One reader for
 * every rule that asks what a value in a row is: the name layer hides a credential column's values (named.ts sqlRows),
 * the random layer keeps the other columns' IDs and data (context.ts, `sqlCell`). A statement without a column list
 * (`INSERT INTO t VALUES …`, as mysqldump writes by default) names no column, so it isn't read.
 */
import { type Argument, callArguments, closingBracket } from "./calls.ts";
import { delimitedCells } from "./syntax.ts";

export interface SqlCell {
	/** The table, without its schema or quotes: `users` in `` `app`.`users` ``. */
	table: string;
	/** The column, without quotes: `password` in `"password"`, `` `password` ``, `[password]`. */
	column: string;
	/** The row's place among all the rows read, so cells of one row can be found together. */
	row: number;
	/** The value as an argument of the row: a string literal's content is its `literal`. */
	value: Argument;
}

/** An identifier as SQL dialects quote it: `"name"`, `` `name` ``, `[name]`. */
const unquote = (name: string) => name.trim().replace(/^["`[]|["`\]]$/g, "");

/**
 * `INSERT [INTO] <table> (<columns>) VALUES`, and the dialects' other forms (`INSERT IGNORE`, `INSERT OR REPLACE`,
 * `REPLACE INTO`), the table quoted as any dialect quotes it (`"my table"`, `` `app`.`users` ``, `[dbo].[users]`).
 */
const INSERT =
	/\b(?:INSERT(?:\s+IGNORE|\s+OR\s+(?:REPLACE|IGNORE|ABORT|FAIL|ROLLBACK))?|REPLACE)\s+(?:INTO\s+)?((?:"[^"\n]{1,100}"|`[^`\n]{1,100}`|\[[^\]\n]{1,100}\]|[\w.]){1,200})\s*\(([^()]{1,2000})\)\s*VALUES\s*/gi;

/** What may stand between two rows: blanks, comments and one comma. */
const BETWEEN_ROWS = /(?:\s|--[^\n]*|\/\*[\s\S]{0,2000}?\*\/)*,?(?:\s|--[^\n]*|\/\*[\s\S]{0,2000}?\*\/)*/y;

/**
 * The cells of every `INSERT` in `text`, row by row (up to 10,000 rows a statement); with `wants`, only of the
 * statements whose table and columns it accepts (so a dump's other tables cost no reading).
 */
export function* insertCells(text: string, wants?: (table: string, columns: string[]) => boolean): Generator<SqlCell> {
	if (!/\b(?:INSERT|REPLACE)\b/i.test(text)) return;
	const rows = { read: 0 };
	for (const m of text.matchAll(INSERT)) {
		const table = unquote(m[1].split(".").at(-1)!);
		const columns = delimitedCells(m[2], ",").map((c) => unquote(c.text));
		if (wants && !wants(table, columns)) continue;
		const at = m.index + m[0].length;
		// (A statement a program holds in a string, `cur.execute("INSERT … VALUES ('…')")`: the string's brackets aren't
		// read as brackets, so its line is read as the statement on its own.)
		if (text[at] === "(" && closingBracket(text, at + 1) < 0) {
			const end = text.indexOf("\n", at);
			const line = text.slice(m.index, end < 0 ? undefined : end);
			for (const cell of rowCells(line, at - m.index, table, columns, rows))
				yield { ...cell, value: shifted(cell.value, m.index) };
		} else yield* rowCells(text, at, table, columns, rows);
	}
}

/** The cells of the rows that start at `at` (`(…), (…)`), each value under its column. */
function* rowCells(
	text: string,
	at: number,
	table: string,
	columns: string[],
	rows: { read: number },
): Generator<SqlCell> {
	for (let row = 0; row < 10_000 && text[at] === "("; row++) {
		// (A row cut short, a dump's `head`, ends the rows. callArguments reads to the bracket closingBracket finds.)
		const values = callArguments(text, at + 1);
		if (!values) break;
		const close = closingBracket(text, at + 1);
		const n = rows.read++;
		for (const [k, value] of values.entries()) if (columns[k]) yield { table, column: columns[k], row: n, value };
		BETWEEN_ROWS.lastIndex = close + 1;
		at = close + 1 + BETWEEN_ROWS.exec(text)![0].length;
	}
}

/** An argument read from a piece of a text, placed where the piece starts in it. */
function shifted(a: Argument, by: number): Argument {
	return {
		...a,
		start: a.start + by,
		end: a.end + by,
		...(a.literal ? { literal: { ...a.literal, start: a.literal.start + by, end: a.literal.end + by } } : {}),
	};
}
