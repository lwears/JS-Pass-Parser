const secretsFile = Bun.file('repos.txt')
const allContents = await secretsFile.text()

allContents.split(/\r?\n/).forEach((line) => {
    console.log('line: ', line);
});