import { createReadStream } from "node:fs";
import { writeFile } from "node:fs/promises";
import { stringify } from "csv";
import chalk from "chalk";
import readline from "readline";

import { HASHES_LATEX } from "./latex";
import { DuplicatedHashes, IndexedHashes, Stats, WriteCsvOpts } from "./types";

const rl = readline.createInterface({
  input: createReadStream("example.txt"),
  crlfDelay: Infinity,
});

const stats: Stats = {
  indexedHashes: {} as Record<string, string[]>,
  hashes: 0,
  enabledAccounts: 0,
  disabledAccounts: 0,
  computerAccounts: 0,
  blankPasswords: 0,
  domains: [],
  lmHashes: [],
  hashStat: [],
};

const duplicatedAdmins = [];

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

const processLine = (line: string) => {
  const pl = parseLine(line);
  stats.hashes++;
  addToStats(pl);
};

rl.on("line", processLine);

const onClose = () => {
  stats.disabledAccounts = stats.hashes - stats.enabledAccounts;

  const { duplicatedHashes, latexLines, ntlmCsvRecords } = generateReport(
    stats.indexedHashes
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

  printData({ ...stats, totalDupHashes: Object.keys(duplicatedHashes).length });
};

rl.on("close", onClose);

const generateReport = (indexedHashes: IndexedHashes) => {
  type ReduceReturnType = {
    latexLines: string[];
    ntlmCsvRecords: string[][];
    duplicatedHashes: DuplicatedHashes;
  };

  const { duplicatedHashes, latexLines, ntlmCsvRecords } = Object.entries(
    indexedHashes
  )
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

  return {
    duplicatedHashes,
    ntlmCsvRecords,
    latexLines,
  };
};

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
    (stats.totalDupHashes > 0 ? red : green)(
      `Duplicated Hashes:\t`,
      stats.totalDupHashes
    )
  );

  console.log(
    (stats.blankPasswords > 0 ? red : green)(`Domains:\t\t`, stats.domains)
  );
  console.log(yellow("\nLatex Table output to latex_table.txt"));
  console.log(yellow("CSV output to duplicated_hashes.txt"));
};

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
