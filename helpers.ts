const groupBy = (list: Record<string, any>[], key: string) =>
  list.reduce((rv, x) => {
    (rv[x[key]] = rv[x[key]] || []).push(x);
    return rv;
  }, {});
