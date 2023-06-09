import { Readable } from "node:stream";
import readline from "readline";

const secretsFile = Readable.fromWeb(Bun.file("example.txt").stream())
  .setEncoding("utf8");

// const allContents = await secretsFile.text()
// const allContentsStream = secretsFile.stream()
// const allContentsStream2 = fs.createReadStream('broadband.sql')

// allContents.split(/\r?\n/).forEach((line) => {
//     console.log('line: ', line);
// });

const rl = readline.createInterface({
  input: secretsFile,
  crlfDelay: Infinity,
});

rl.on("line", (line) => {
  console.log(line);
});
