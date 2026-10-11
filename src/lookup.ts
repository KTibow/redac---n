/**
 * A lookup table for keys that come from the text: no prototype, so a key like `constructor` or `toString` finds
 * nothing (`ENTITIES["constructor"]` on a plain object is `Object` itself), and frozen.
 */
export function lookup<T>(entries: Record<string, T>): Readonly<Record<string, T | undefined>> {
	return Object.freeze(Object.assign(Object.create(null) as Record<string, T>, entries));
}
