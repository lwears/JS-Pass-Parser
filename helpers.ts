const groupBy = (list: Record<string, any>[], key: string) =>
  list.reduce((rv, x) => {
    (rv[x[key]] = rv[x[key]] || []).push(x);
    return rv;
  }, {});

export const maskHash = (hash: string) =>
  hash.slice(0, 4) + "*".repeat(14) + hash.slice(28);
