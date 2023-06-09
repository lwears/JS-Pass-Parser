// Readable stream
import { readLines } from "https://deno.land/std@0.101.0/io/bufio.ts";
import { parse } from "https://deno.land/std/flags/mod.ts";

const args = parse(Deno.args, {
  default: { all: false },
  boolean: ["all"],
});

const secretsFile = Deno.args[0];
const adminsFile = Deno.args[1];

const file = await Deno.open(secretsFile);
//.catch((error) => console.error("Error reading file", error));

const reader = readLines(file);

interface Stats {
  indexedHashes: Record<string, string[]>;
  totalHashes: number;
  enabledAccounts: number;
  disabledAccounts: number;
  computerAccounts: number;
  blankPasswords: number;
  domains: string[];
  lmHashes: string[][];
  mergedHashes: any[];
  ntlmCsvRecords: string[][];
}

const stats: Stats = {
  indexedHashes: {} as Record<string, string[]>,
  totalHashes: 0,
  enabledAccounts: 0,
  disabledAccounts: 0,
  computerAccounts: 0,
  blankPasswords: 0,
  domains: [],
  lmHashes: [],
  mergedHashes: [],
  ntlmCsvRecords: [],
};

// Looping over each line in the file.
// I then need to build some stats in the structure of the stats object above.
// at the moment it looks shitty, see below.
// Because the file could potentially be GigaBytes big we cannot risk loading every single line into memory and simply reducing over it which would be the easiest.
for await (const line of reader) {
  const h = parseLine(line);
  // This looks like shit.
  stats.totalHashes++;
  h.enabled ? stats.enabledAccounts++ : stats.disabledAccounts++;
  h.user?.includes("$") && stats.computerAccounts++;
}

function parseLine(line: string) {
  if (!line || !line.includes(":")) {
    console.error(`Line blank or incorrect format: ${line}`);
  }

  const s = line.split(":");

  if (s.length < 7 || s[3].length !== 32) {
    console.error(`Error reading line: ${line}`);
  }

  const upn = s[0].split("\\");

  return {
    lm: s[2],
    ntlm: s[3],
    enabled: s[6].includes("Enabled"),
    domain: upn.length > 1 ? upn[0] : null,
    user: upn.length > 1 ? upn[1] : null,
  };
}
