/**
 * Aho-Corasick: which of many keywords occur in a text, in one linear pass. Used to decide which format
 * rules can match before running any of them (ASCII case folded, in the keywords as in the text), and to find
 * short known values (case-sensitive, every occurrence).
 */
/** The number of UTF-16 code units, which a character class table is indexed by. */
const CHAR_CODES = 0x10000;
/** A character code with ASCII upper case folded to lower case. */
const foldAscii = (c: number) => (c >= 65 && c <= 90 ? c + 32 : c);

export class KeywordSet {
	private next: Map<number, number>[] = [new Map()];
	private fail: number[] = [0];
	private out: number[][] = [[]];
	readonly keywords: string[];

	private fold: boolean;
	/** The character classes: 0 for a character in no keyword, else one per distinct character of the keywords. */
	private classOf!: Uint16Array;
	private width = 0;
	/** The next state for each state and class, `state * width + class`. */
	private table!: Int32Array;
	private hasOut!: Uint8Array;

	/** An empty keyword occurs everywhere, and indices are the callers' (a keyword can't be dropped), so it is refused. */
	constructor(keywords: string[], caseSensitive = false) {
		if (keywords.includes("")) throw new RangeError("KeywordSet: empty keyword");
		this.keywords = keywords;
		this.fold = !caseSensitive;
		keywords.forEach((k, i) => {
			let s = 0;
			for (let j = 0; j < k.length; j++) {
				const c = this.fold ? foldAscii(k.charCodeAt(j)) : k.charCodeAt(j);
				let t = this.next[s].get(c);
				if (t === undefined) {
					t = this.next.length;
					this.next.push(new Map());
					this.fail.push(0);
					this.out.push([]);
					this.next[s].set(c, t);
				}
				s = t;
			}
			this.out[s].push(i);
		});
		// Breadth-first failure links.
		const queue: number[] = [];
		for (const t of this.next[0].values()) queue.push(t);
		for (let qi = 0; qi < queue.length; qi++) {
			const s = queue[qi];
			for (const [c, t] of this.next[s]) {
				queue.push(t);
				let f = this.fail[s];
				while (f && !this.next[f].has(c)) f = this.fail[f];
				// (`f` is shallower than `s`, so its child is never `t` itself.)
				this.fail[t] = this.next[f].get(c) ?? 0;
				this.out[t] = this.out[t].concat(this.out[this.fail[t]]);
			}
		}
		this.tabulate(queue);
	}

	/**
	 * The automaton as a table, one read per character: for each state and each character that occurs in a keyword, the
	 * state after it (the failure links followed ahead of time); a character that occurs in none leads to the start. `order`
	 * is the states below the start, shallowest first, so a state's failure state is tabulated before it.
	 */
	private tabulate(order: number[]) {
		const classes = new Map<number, number>();
		for (const edges of this.next) for (const c of edges.keys()) if (!classes.has(c)) classes.set(c, classes.size + 1);
		this.width = classes.size + 1;
		this.classOf = new Uint16Array(CHAR_CODES);
		for (const [c, k] of classes) this.classOf[c] = k;
		// (Upper case reads as its lower case when folding: its class is the lower case letter's.)
		if (this.fold) for (let c = 65; c <= 90; c++) this.classOf[c] = this.classOf[c + 32];
		this.table = new Int32Array(this.next.length * this.width);
		const fill = (s: number) => {
			const base = s * this.width;
			if (s) this.table.copyWithin(base, this.fail[s] * this.width, this.fail[s] * this.width + this.width);
			for (const [c, t] of this.next[s]) this.table[base + classes.get(c)!] = t;
		};
		fill(0);
		for (const s of order) fill(s);
		this.hasOut = Uint8Array.from(this.out, (o) => (o.length ? 1 : 0));
	}

	/** Indices of the keywords that occur in `text`. */
	find(text: string): Set<number> {
		const found = new Set<number>();
		const { table, classOf, width, hasOut } = this;
		for (let i = 0, s = 0; i < text.length; i++) {
			s = table[s * width + classOf[text.charCodeAt(i)]];
			if (hasOut[s]) for (const k of this.out[s]) found.add(k);
		}
		return found;
	}

	/** Every occurrence of every keyword: [start, keyword index]. */
	*matches(text: string): Generator<[number, number]> {
		const { table, classOf, width, hasOut } = this;
		for (let i = 0, s = 0; i < text.length; i++) {
			s = table[s * width + classOf[text.charCodeAt(i)]];
			if (hasOut[s]) for (const k of this.out[s]) yield [i + 1 - this.keywords[k].length, k];
		}
	}
}
