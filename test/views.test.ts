/**
 * Text as a viewer or a tool prints it: line numbers, grep prefixes, diffs, tables and listings are read as the text
 * they come from.
 *
 *   node --test test/views.test.ts
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { hidden, kept, r } from "./helpers.ts";

test("a psql name/value table hides the value of a credential row and keeps the others", () => {
	const table =
		" name        | value\n-------------+------------------\n db_password | Xq7Lm2Vb9Rt4Np8K\n host        | db.internal\n";
	hidden(table, "Xq7Lm2Vb9Rt4Np8K");
	kept(table, "host        | db.internal");
});

test("line numbers in front of .env lines do not hide their values", () => {
	hidden("     2→DB_PASSWORD=Tr0ub4dor&3horse\n     3→SECRET=p@ss;word123!x", "3horse");
	hidden("     2→DB_PASSWORD=Tr0ub4dor&3horse\n     3→SECRET=p@ss;word123!x", "word123");
});

test("line numbers in front of every line do not hide a rule's match", () => {
	hidden(
		"     1→# hostname:port:database:username:password\n     2→pg-prod.internal:5432:app:app_rw:432nMyoxFezQlw2aCf\n",
		"432nMyoxFezQlw2aCf",
		{ path: "/home/u/.pgpass" },
	);
	hidden(
		'    24→        - name: WORDPRESS_DB_PASSWORD\n    25→          value: "HarborGarden376"\n',
		"HarborGarden376",
	);
	kept("     1\tid\tname\n     2\t7\talice\n", "alice");
});

test("a password in a box-drawing table cell is hidden and the borders kept", () => {
	assert.equal(
		r().redact("┃ password ┃ Hx7mQ2pLw9zK ┃").text.replace(/#\w+/, "#"),
		"┃ password ┃ [REDACTED password #] ┃",
	);
});

test("a table's column header decides which cells hold a secret", () => {
	hidden("| REST API 키     | 6c38f1795d1f8e7d2610e3deb54688eb  |", "6c38f1795d1f8e7d2610e3deb54688eb");
	kept("| JavaScript 키   | 6c38f1795d1f8e7d2610e3deb54688eb  |", "6c38f1795d1f8e7d2610e3deb54688eb");
	hidden(
		"User Name,Access Key Id,Secret Access Key\nci_robot,S8OH2MKLQRB48HRISGYQ,fovQ2pQvStti6SiZRTySMOVCGDdWSHzTL9WhNTVd",
		"fovQ2pQvStti6SiZRTySMOVCGDdWSHzTL9WhNTVd",
	);
	kept(
		"$id,name\nhxfcwpcas5xokpwe,Diamond Mendez\ngw8nxwf6esn3tfwf,Michael Huff\nxb6bxg56lral1qy9,Alyssa Rodriguez",
		"xb6bxg56lral1qy9",
	);
	kept(
		"+----------------------+-------------+\n|          ID          |    NAME     |\n+----------------------+-------------+\n| b1g8nkw36yl7hsn7lg49 | default     |",
		"b1g8nkw36yl7hsn7lg49",
	);
});

test("a diff hunk or a grep -n line is read as the file it comes from", () => {
	hidden(
		"@@ -1,4 +1,4 @@\n database:\n   host: db\n-  password: |\n-    OldS3cret!x\n+  password: |\n+    NewS3cret!y\n",
		"OldS3cret!x",
	);
	hidden(
		"config/app.yml:11:smtp:\nconfig/app.yml:12:  user: mailer\nconfig/app.yml:13:  pass: dragonfly9X\n",
		"dragonfly9X",
	);
	hidden(
		'diff --git a/.env.production b/.env.production\n--- a/.env.production\n+++ b/.env.production\n@@ -28,3 +28,3 @@ [auth]\n CI_PIPELINE_ID="5034300445"\n-LUMEN_VALUE=m5f/LxNKtMqPJsnsQ0IqQO5KqPEygyJKG82cTlfZgfdQdZFci4fKVXTC0cjkzWFOzm0MNWeJaZBFmg+oEsg5Xg==\n+LUMEN_VALUE=ENC[AES256_GCM,data:abc,iv:def,tag:ghi,type:str]\n',
		"m5f/LxNKtMqPJsnsQ0IqQO5KqPEyg",
	);
});

test("a column of base64 ids in a data frame is kept", () => {
	const t =
		"                                             id  score\n0  q3J9fK2LxP8vR7tY1wZ5aB4cD6eF0gH2iJ8kL3mN9oA=   0.91";
	assert.equal(r().redact(t).text, t);
});

test("grep prefixes and a coloured diff are read as the file they come from", () => {
	const S = "Harbor#2291x";
	const E = "\x1b";
	for (const [t, v, hint] of [
		["k8s/deploy.yaml:40:        - name: DB_PASSWORD\nk8s/deploy.yaml-41-          value: Harbor#2291x", S],
		["/etc/redis/redis.conf:1043:requirepass Harbor#2291x", S],
		[
			`${E}[1mdiff --git a/.env b/.env${E}[m\n${E}[1m--- a/.env${E}[m\n${E}[1m+++ b/.env${E}[m\n${E}[36m@@ -1,2 +1,2 @@${E}[m\n NODE_ENV=production\n${E}[32m+API_TOKEN=Company.Password1${E}[m`,
			"Company.Password1",
		],
	] as [string, string, { command?: string }?][])
		hidden(t, v, hint);
});

test("a table's value cell under a credential column is hidden", () => {
	const S = "Harbor#2291x";
	for (const [t, v, hint] of [
		["Key            Value\n---            -----\ndb-password    Harbor-2291.x", "Harbor-2291.x"],
		["| Service | Variable | Value |\n|---|---|---|\n| Postgres | DB_PASSWORD | Harbor#2291x |", S],
		["| User | Hash | Password |\n|---|---|---|\n| bob | x | Harbor#2291x |", S],
	] as [string, string, { command?: string }?][])
		hidden(t, v, hint);
});

test("a joint across numbered lines and a blank line in a diff hunk are read through", () => {
	const plain = 'client = WebClient(\n    token=("\x78oxb-2048-8811-Zr8vK2mQ9x"\n           "W4tB7nL1pH6jF3dS")\n)';
	hidden(
		plain
			.split("\n")
			.map((l, i) => `${String(i + 10).padStart(6)}→${l}`)
			.join("\n"),
		"W4tB7nL1pH6jF3dS",
	);
	hidden(
		[
			"diff --git a/.env.production b/.env.production",
			"--- a/.env.production",
			"+++ b/.env.production",
			"@@ -1,4 +1,4 @@",
			" NODE_ENV=production",
			"",
			"-STRIPE=Tiger1103#xq",
			"+STRIPE=Harbor2291#zk",
		].join("\n"),
		"Harbor2291#zk",
	);
});

test("a table cut by a prompt keeps its token names", () => {
	kept(
		"NAME       SECRETS   AGE\ndefault    2         13d\n$ kubectl get secrets\nNAME                   TYPE   DATA   AGE\ndefault-token-6wnx5    kubernetes.io/service-account-token   3      44m",
		"default-token-6wnx5",
	);
});

test("a diff that deletes a secret file is that file", () => {
	hidden(
		"diff --git a/.env b/.env\ndeleted file mode 100644\n--- a/.env\n+++ /dev/null\n@@ -1,3 +0,0 @@\n-APP_ENV=production\n-OPENAI=Tiger1103#xQ\n-PORT=3000",
		"Tiger1103#xQ",
	);
});

test("a column of identifiers under a credential-named cell is a listing, not passwords", () => {
	kept(
		"bzless\t\t\t\t klist\t\t\ttabs\nbzmore\t\t\t\t kpasswd\t\ttclsh\nc_rehash\t\t\t krb5-config\t\ttclsh8.6\nctail\t\t\t ksu\t\t\ttestsolv",
		"testsolv",
	);
});

test("a column of passwords under a credential header is hidden", () => {
	hidden("NAME    PASSWORD\nalice   Kx9mQ2vL7p!\nbob     Hq3#mQ2vL9z", "Hq3#mQ2vL9z");
});

test("a numbered diff's hunk markers are read past the numbers", () => {
	hidden(
		"     1→--- a/application.properties\n     2→+++ b/application.properties\n     3→@@ -1,3 +1,3 @@\n     4→ server.port=8080\n     5→-spring.datasource.password=Maple2021*\n     6→+spring.datasource.password=${DB_PASSWORD}",
		"Maple2021*",
	);
});
