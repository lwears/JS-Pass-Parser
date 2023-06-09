import { createReadStream } from "node:fs";
import { Readable } from "node:stream";
import readline from "readline";

// const secretsFile = Readable.fromWeb(Bun.file("example.txt").stream()).setEncoding("utf8");

// allContents.split(/\r?\n/).forEach((line) => {
//     console.log('line: ', line);
// });

const rl = readline.createInterface({
  input: createReadStream("example.txt"),
  crlfDelay: Infinity,
});

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

rl.on("line", (line) => {
  const h = parseLine(line);

  stats.totalHashes++;
  h.enabled ? stats.enabledAccounts++ : stats.disabledAccounts++;
  h.user?.includes("$") && stats.computerAccounts++;
  h.ntlm.includes("31d6cfe0d16ae931b73c59d7e0c089c0") && stats.blankPasswords++;
  h.domain && stats.domains.includes(h.domain) && stats.domains.push(h.domain);
  stats.indexedHashes[h.ntlm] = [h.user];
  !h.lm.includes("aad3b435b51404eeaad3b435b51404ee") &&
    stats.lmHashes.push([h.lm, h.user]);

  console.log(line);
});

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
    domain: upn.length > 1 ? upn[0].toLowerCase() : null,
    user: (upn.length > 1 ? upn[1] : upn[0]).toLowerCase(),
  };
}
