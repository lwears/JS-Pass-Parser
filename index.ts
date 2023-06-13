import { createReadStream, readFileSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
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

// Read Admins file and pass into var
const admins = readline.createInterface({
  input: createReadStream(adminsFile as string),
  crlfDelay: Infinity,
});

admins.on("line", (line: string) => {
  const admin = line.trim().toLowerCase();
  if (admin in stats.admins) {
    return;
  }
  stats.admins[admin] = "";
});

// Read secrets dump
const secretsDump = readline.createInterface({
  input: createReadStream(secretsFile as string),
  crlfDelay: Infinity,
});

secretsDump.on("line", processLine);

secretsDump.on("close", onClose);

function addToStats(hash: Hash) {
  hash.enabled && stats.enabledAccounts++;

  hash.isComputer && stats.computerAccounts++;

  if (args.all) return;

  hash.ntlm.includes(BLANK_NTLM) && stats.blankPasswords++;

  hash.domain &&
    !stats.domains.includes(hash.domain) &&
    stats.domains.push(hash.domain);

  Array.isArray(stats.indexedHashes[hash.ntlm])
    ? stats.indexedHashes[hash.ntlm].push(hash.user)
    : (stats.indexedHashes[hash.ntlm] = [hash.user]);

  // Not adding the last admins ntlm
  if (hash.user in stats.admins) {
    stats.admins[hash.user] = hash.ntlm;
  }

  !hash.lm.includes(BLANK_LM) && stats.lmHashes.push([hash.lm, hash.user]);
}

function processLine(line: string) {
  const pl = parseLine(line);
  stats.hashes++;
  addToStats(pl);
}

function onClose() {
  stats.disabledAccounts = stats.hashes - stats.enabledAccounts;

  const { duplicatedHashes, latexLines, ntlmCsvRecords } = mapIndexedHashes(
    stats.indexedHashes
  );

  console.log(stats.admins);

  const duplicatedAdmins = Object.entries(stats.admins).map(([admin, hash]) => {
    console.log(admin, hash);
    if (hash in duplicatedHashes) {
      return admin;
    }
  });

  console.log(duplicatedAdmins);

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

  printData({ ...stats, totalDupHashes: Object.keys(duplicatedHashes).length });
}

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

const printData = (stats: Stats & { totalDupHashes: number }) => {
  // finish printing stats
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

  console.log(`Domains:\t\t`, stats.domains);
  console.log(yellow("\nLatex Table output to latex_table.txt"));
  console.log(yellow("CSV output to duplicated_hashes.txt"));
};

function parseLine(line: string): Hash {
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
  };
}
