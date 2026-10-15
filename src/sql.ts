/**
 * SQL rows read into cells: each value of an `INSERT … VALUES` statement, or of a `COPY … FROM stdin` block as
 * pg_dump writes its data, under its table and column. One reader for every rule that asks what a value in a row is:
 * the name layer hides a credential column's values (named.ts sqlRows), the random layer keeps the other columns'
 * IDs and data (context.ts, `sqlCell`). A statement without a column list (`INSERT INTO t VALUES …`, as mysqldump
 * writes by default) names no column, so it isn't read.
 */
import { type Argument, callArguments, closingBracket, type Literal, literalAt } from "./calls.ts";
import { delimitedCells } from "./syntax.ts";

export interface SqlCell {
	/** The table, without its schema or quotes: `users` in `` `app`.`users` ``. */
	table: string;
	/** The column, without quotes: `password` in `"password"`, `` `password` ``, `[password]`. */
	column: string;
	/** The value as an argument of the row: the string it gives the column is its `literal` (sqlLiteral). */
	value: Argument;
	/** The row's columns and values, the cell's among them: what a key/value table's value is named by. */
	columns: readonly string[];
	row: readonly Argument[];
}

/** An identifier as SQL dialects quote it: `"name"`, `` `name` ``, `[name]`. */
const unquote = (name: string) => name.trim().replace(/^["`[]|["`\]]$/g, "");

/** A table's name as any dialect quotes it: `"my table"`, `` `app`.`users` ``, `[dbo].[users]`. */
const TABLE = String.raw`((?:"[^"\n]{1,100}"|\x60[^\x60\n]{1,100}\x60|\[[^\]\n]{1,100}\]|[\w.]){1,200})`;

/**
 * `INSERT [INTO] <table> (<columns>) VALUES`, and the dialects' other forms (`INSERT IGNORE`, `INSERT OR REPLACE`,
 * `REPLACE INTO`).
 */
const INSERT = new RegExp(
	String.raw`\b(?:INSERT(?:\s+IGNORE|\s+OR\s+(?:REPLACE|IGNORE|ABORT|FAIL|ROLLBACK))?|REPLACE)\s+(?:INTO\s+)?${TABLE}\s*\(([^()]{1,2000})\)\s*VALUES\s*`,
	"gi",
);

/** `COPY <table> (<columns>) FROM stdin;` and its line break: pg_dump's data, one tab-separated row a line after it. */
const COPY = new RegExp(
	String.raw`(?:^|\n)COPY\s+${TABLE}\s*\(([^()]{1,2000})\)\s+FROM\s+stdin\b[^;\n]{0,200};[ \t]*\r?\n`,
	"gi",
);

/** What may stand between two rows: blanks, comments and one comma. */
const BETWEEN_ROWS = /(?:\s|--[^\n]*|\/\*[\s\S]{0,2000}?\*\/)*,?(?:\s|--[^\n]*|\/\*[\s\S]{0,2000}?\*\/)*/y;

/**
 * The cells of every `INSERT` and `COPY` in `text`, row by row (up to 10,000 rows a statement); with `wants`, only of
 * the statements whose table and columns it accepts (so a dump's other tables cost no reading).
 */
export function* sqlCells(text: string, wants?: (table: string, columns: string[]) => boolean): Generator<SqlCell> {
	if (/\b(?:INSERT|REPLACE)\b/i.test(text)) yield* insertCells(text, wants);
	if (/\bCOPY\b/i.test(text)) yield* copyCells(text, wants);
}

function* insertCells(text: string, wants?: (table: string, columns: string[]) => boolean): Generator<SqlCell> {
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
			for (const cell of rowCells(line, at - m.index, table, columns)) {
				const row = cell.row.map((a) => shifted(a, m.index));
				yield { ...cell, value: row[cell.row.indexOf(cell.value)], row };
			}
		} else yield* rowCells(text, at, table, columns);
	}
}

/** The cells of the rows that start at `at` (`(…), (…)`), each value under its column. */
function* rowCells(text: string, at: number, table: string, columns: string[]): Generator<SqlCell> {
	for (let row = 0; row < 10_000 && text[at] === "("; row++) {
		// (A row cut short, a dump's `head`, ends the rows. callArguments reads to the bracket closingBracket finds.)
		const values = callArguments(text, at + 1)?.map((value) => withLiteral(text, value));
		if (!values) break;
		const close = closingBracket(text, at + 1);
		for (const [k, value] of values.entries())
			if (columns[k]) yield { table, column: columns[k], value, columns, row: values };
		BETWEEN_ROWS.lastIndex = close + 1;
		at = close + 1 + BETWEEN_ROWS.exec(text)![0].length;
	}
}

/**
 * The cells of `COPY … FROM stdin` blocks: tab-separated rows up to the `\.` line, each value as written (a `\N` is
 * NULL, no value). (Up to 10,000 rows a block, as for an INSERT's.)
 */
function* copyCells(text: string, wants?: (table: string, columns: string[]) => boolean): Generator<SqlCell> {
	for (const m of text.matchAll(COPY)) {
		const table = unquote(m[1].split(".").at(-1)!);
		const columns = delimitedCells(m[2], ",").map((c) => unquote(c.text));
		if (wants && !wants(table, columns)) continue;
		let at = m.index + m[0].length;
		for (let n = 0; n < 10_000 && at < text.length; n++) {
			const stop = text.indexOf("\n", at);
			const end = stop < 0 ? text.length : stop;
			const line = text.slice(at, end).replace(/\r$/, "");
			if (line === "\\." || !line.includes("\t")) break;
			const row: Argument[] = [];
			let start = at;
			for (const value of line.split("\t")) {
				const span = { value, start, end: start + value.length };
				row.push({
					text: value,
					start,
					end: span.end,
					...(value === "\\N" ? {} : { literal: { ...span, quote: "" } }),
				});
				start = span.end + 1;
			}
			for (const [k, value] of row.entries()) if (columns[k]) yield { table, column: columns[k], value, columns, row };
			at = end + 1;
		}
	}
}

/**
 * The string a row's value gives its column, read through SQL's own ways of writing one: a prefix (`N'…'`, `E'…'`,
 * calls.ts reads those), dollar quoting (`$$…$$`, `$body$…$body$`), a cast (`'…'::text`) and the functions a value is
 * stored through (`crypt('…', gen_salt('bf'))`, `MD5('…')`, `encode(digest('…', 'sha256'), 'hex')`), which are given it
 * first. Undefined for any other expression, and for a number.
 */
function sqlLiteral(text: string, value: Argument, depth = 0): Literal | undefined {
	if (value.literal) return value.literal;
	const literal = literalAt(text, value.start);
	if (literal && literal.end < value.end) {
		const rest = text.slice(literal.end + 1, value.end);
		return CAST_TAIL.test(rest) ? literal : undefined;
	}
	// (A function's first argument, read the same way, not too deep to stay cheap: the functions a value is stored
	// through, `encode(digest('…', 'sha256'), 'hex')`, are given it first.)
	const call = /^[A-Za-z_][\w.]{0,60}[ \t]*\(/.exec(value.text);
	if (
		!call ||
		depth >= 3 ||
		!CAST_TAIL.test(text.slice(closingBracket(text, value.start + call[0].length) + 1, value.end))
	)
		return undefined;
	const first = callArguments(text, value.start + call[0].length)?.[0];
	return first && sqlLiteral(text, first, depth + 1);
}

/** What may follow a string and leave it the value: Postgres' casts, `::text`, `::character varying(255)`, `::bytea[]`. */
const CAST_TAIL = /^(?:[ \t]*::[ \t]*[A-Za-z_][\w ."]{0,60}?(?:\([\d, ]{1,12}\))?(?:\[\])?)*[ \t]*$/;

/** A row's value with the string it gives its column as its literal (sqlLiteral). */
function withLiteral(text: string, value: Argument): Argument {
	const literal = sqlLiteral(text, value);
	return literal && !value.literal ? { ...value, literal } : value;
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
