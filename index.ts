import { createReadStream, readFileSync } from "node:fs";
import { writeFile } from "node:fs/promises";
import { stringify } from "csv";
import chalk from "chalk";
import readline from "readline";
import yargs from "yargs-parser";

import { HASHES_LATEX } from "./latex";
import {
  DuplicatedHashes,
  Hash,
  IndexedHashes,
  Stats,
  WriteCsvOpts,
} from "./types";
import { BLANK_LM, BLANK_NTLM } from "./constants";

const rawArgs = Bun.argv.slice(3);

const args = yargs(rawArgs);

const secretsFile = args._[0];

const adminsFile = args._[1];

const stats: Stats = {
  indexedHashes: {} as IndexedHashes,
  hashes: 0,
  enabledAccounts: 0,
  disabledAccounts: 0,
  computerAccounts: 0,
  blankPasswords: 0,
  domains: [],
  lmHashes: [],
  hashStat: [],
  admins: {},
};

// Admins need to be read first and won't ever be as big as secretsFile: safe to read into memory
let admins: string[] = [];
if (adminsFile) {
  admins = readFileSync(adminsFile, { encoding: "utf-8" })
    .trim()
    .toLowerCase()
    .split("\n");
}

// Read secrets dump
const secretsDump = readline.createInterface({
  input: createReadStream(secretsFile as string),
  crlfDelay: Infinity,
});

secretsDump.on("line", processHashLine);

secretsDump.on("close", onClose);

// Functions

function processHashLine(line: string) {
  const hl = parseHashLine(line);
  addToStats(hl);
}

function parseHashLine(line: string): Hash {
  if (!line || !line.includes(":")) {
    console.error(`Line blank or incorrect format: ${line}`);
  }

  const s = line.split(":");

  if (s.length < 7 || s[3].length !== 32) {
    console.error(`Error reading line: ${line}`);
  }

  const upn = s[0].split("\\");
  const domain = upn.length > 1 ? upn[0].toLowerCase() : null;
  const user = (upn.length > 1 ? upn[1] : upn[0]).toLowerCase();

  return {
    lm: s[2],
    ntlm: s[3],
    enabled: s[6].includes("Enabled"),
    domain,
    user,
    isComputer: user.includes("$"),
    isAdmin: admins.includes(user) ?? false,
  };
}

function addToStats(hash: Hash) {
  stats.hashes++;

  hash.enabled ? stats.enabledAccounts++ : stats.disabledAccounts++;

  hash.isComputer && stats.computerAccounts++;

  if (!args.all && !hash.enabled) return;

  hash.ntlm.includes(BLANK_NTLM) && stats.blankPasswords++;

  hash.domain &&
    !stats.domains.includes(hash.domain) &&
    stats.domains.push(hash.domain);

  Array.isArray(stats.indexedHashes[hash.ntlm])
    ? stats.indexedHashes[hash.ntlm].push(hash.user)
    : (stats.indexedHashes[hash.ntlm] = [hash.user]);

  !hash.lm.includes(BLANK_LM) && stats.lmHashes.push([hash.lm, hash.user]);

  if (hash.isAdmin) stats.admins[hash.user] = hash.ntlm;
}

function onClose() {
  const { duplicatedHashes, latexLines, ntlmCsvRecords } = mapIndexedHashes(
    stats.indexedHashes
  );

  const duplicatedAdmins = Object.entries(stats.admins).reduce<string[]>(
    (acc, [admin, hash]) => {
      if (hash in duplicatedHashes) {
        acc.push(admin);
      }
      return acc;
    },
    []
  );

  writeCSV({
    filename: "lm_hashes.csv",
    columns: ["hash", "user"],
    records: stats.lmHashes,
  });

  writeCSV({
    filename: "duplicate_hashes.csv",
    columns: ["Count", "Hash", "Users"],
    records: ntlmCsvRecords,
  });

  writeFile(
    "latex_table.txt",
    HASHES_LATEX.replace("%REPLACE_ME%", latexLines.join("").trim()),
    (err: Error) => err ?? console.error("Error Writing File", err)
  );

  printData({
    ...stats,
    totalDupHashes: Object.keys(duplicatedHashes).length,
    duplicatedAdmins,
  });
}

// Need Better Name
type ReduceReturnType = {
  latexLines: string[];
  ntlmCsvRecords: string[][];
  duplicatedHashes: DuplicatedHashes;
};

const mapIndexedHashes = (indexedHashes: IndexedHashes) =>
  Object.entries(indexedHashes)
    .map(([key, value]) => ({ count: value.length, hash: key, users: value }))
    .sort((a, b) => (a.count > b.count ? 1 : -1))
    .reduce<ReduceReturnType>(
      (acc, curr) => {
        if (curr.count > 1) {
          acc.duplicatedHashes[curr.hash] = curr;
          acc.ntlmCsvRecords.push([
            curr.count.toString(),
            curr.hash,
            curr.users.join(" - "),
          ]);
          const masked =
            curr.hash.slice(0, 4) + "*".repeat(14) + curr.hash.slice(28);
          acc.latexLines.push(`\t\t ${masked} & ${curr.count} \\\\\n`);
        }
        return acc;
      },
      { duplicatedHashes: {}, ntlmCsvRecords: [], latexLines: [] }
    );

const writeCSV = ({ records, columns, filename }: WriteCsvOpts) =>
  stringify(records, { header: true, columns }, (err, output) => {
    if (err) throw err;
    writeFile(
      filename,
      output,
      (err: Error) => err ?? console.error("Error Writing File", err)
    );
  });

const printData = (
  stats: Stats & { totalDupHashes: number; duplicatedAdmins: string[] }
) => {
  const red = chalk.bold.red;
  const green = chalk.bold.green;
  const yellow = chalk.bold.yellow;

  console.log("Total Hashes:\t\t", stats.hashes);
  console.log("Enabled Accounts:\t", stats.enabledAccounts);
  console.log("Disabled Accounts:\t", stats.disabledAccounts);
  console.log("Computer Accounts:\t", stats.computerAccounts);

  console.log(
    (stats.lmHashes.length > 0 ? red : green)(
      `\nLM Hashes:\t\t`,
      stats.lmHashes.length
    )
  );

  console.log(
    (stats.blankPasswords > 0 ? red : green)(
      `Blank Passwords:\t`,
      stats.blankPasswords
    )
  );

  console.log(
    (stats.totalDupHashes > 0 ? red : green)(
      `Duplicated Hashes:\t`,
      stats.totalDupHashes
    )
  );

  console.log(
    (stats.duplicatedAdmins.length > 0 ? red : green)(
      `Included Admins:\t`,
      stats.duplicatedAdmins
    )
  );

  console.log(`\nDomains:\t\t`, stats.domains);
  console.log(yellow("\nLatex Table output to latex_table.txt"));
  console.log(yellow("CSV output to duplicated_hashes.txt"));
};
