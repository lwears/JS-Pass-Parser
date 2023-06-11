import { createReadStream } from "node:fs";
import { writeFile } from "node:fs/promises";
import readline from "readline";
import { HASHES_LATEX } from "./latex";
import { stringify } from "csv";
import { TERM_COLOURS } from "./constants";
import chalk from "chalk";

const rl = readline.createInterface({
  input: createReadStream("example.txt"),
  crlfDelay: Infinity,
});

interface Stats {
  indexedHashes: Record<string, string[]>;
  hashes: number;
  enabledAccounts: number;
  disabledAccounts: number;
  computerAccounts: number;
  blankPasswords: number;
  domains: string[];
  lmHashes: string[][];
  mergedHashes: any[];
}

const stats: Stats = {
  indexedHashes: {} as Record<string, string[]>,
  hashes: 0,
  enabledAccounts: 0,
  disabledAccounts: 0,
  computerAccounts: 0,
  blankPasswords: 0,
  domains: [],
  lmHashes: [],
  mergedHashes: [],
};

const duplicatedHashes = {};
const duplicatedAdmins = [];
const ntlmCsvRecords: string[][] = [];

const addToStats = (pl: any) => {
  pl.enabled && stats.enabledAccounts++;

  pl.isComputer && stats.computerAccounts++;

  pl.ntlm.includes("31d6cfe0d16ae931b73c59d7e0c089c0") &&
    stats.blankPasswords++;

  pl.domain &&
    !stats.domains.includes(pl.domain) &&
    stats.domains.push(pl.domain);

  Array.isArray(stats.indexedHashes[pl.ntlm])
    ? stats.indexedHashes[pl.ntlm].push(pl.user)
    : (stats.indexedHashes[pl.ntlm] = [pl.user]);

  !pl.lm.includes("aad3b435b51404eeaad3b435b51404ee") &&
    stats.lmHashes.push([pl.lm, pl.user]);
};

rl.on("line", (line) => {
  const pl = parseLine(line);

  stats.hashes++;

  addToStats(pl);
});

rl.on("close", () => {
  //When done we can pass the data out to a function and not do everything in this.
  stats.disabledAccounts = stats.hashes - stats.enabledAccounts;

  const mergedHashes = Object.entries(stats.indexedHashes)
    .map(([key, value]) => ({ count: value.length, hash: key, users: value }))
    .sort((a, b) => (a.count > b.count ? 1 : -1));

  const latexLines: string[] = [];

  mergedHashes.forEach((mh) => {
    if (mh.count > 1) {
      duplicatedHashes[mh.hash] = mh;
      ntlmCsvRecords.push([mh.count.toString(), mh.hash, mh.users.join(" - ")]);
      const masked = mh.hash.slice(0, 4) + "*".repeat(14) + mh.hash.slice(28);
      latexLines.push(`\t\t ${masked} & ${mh.count} \\\\\n`);
    }
  });

  const latexString = HASHES_LATEX.replace(
    "%REPLACE_ME%",
    latexLines.join("").trim()
  );

  writeFile(
    "latex_table.txt",
    latexString,
    (err: Error) => err ?? console.error("Error Writing File", err)
  );

  const columns = ["Count", "Hash", "Users"];

  writeFile(
    "lm_hashes.csv",
    stats.lmHashes.join(","),
    (err: Error) => err ?? console.error("Error Writing File", err)
  );

  stringify(ntlmCsvRecords, { header: true, columns }, (err, output) => {
    if (err) throw err;
    writeFile(
      "duplicate_hashes.csv",
      output,
      (err: Error) => err ?? console.error("Error Writing File", err)
    );
  });

  function printData(stats: Stats) {
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
        `LM Hashes:\t\t`,
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
      (stats.blankPasswords > 0 ? red : green)(
        `Duplicated Hashes:\t`,
        stats.domains
      )
    );

    console.log(
      (stats.blankPasswords > 0 ? red : green)(`Domains:\t\t`, stats.domains)
    );
    console.log(yellow("\nLatex Table output to latex_table.txt"));
    console.log(yellow("CSV output to duplicated_hashes.txt"));
  }

  printData(stats);
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
