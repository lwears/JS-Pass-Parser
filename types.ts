export type IndexedHashes = Record<string, string[]>;

export interface Stats {
  indexedHashes: IndexedHashes;
  hashes: number;
  enabledAccounts: number;
  disabledAccounts: number;
  computerAccounts: number;
  blankPasswords: number;
  domains: string[];
  lmHashes: string[][];
  hashStat: HashStat[];
}

export interface HashStat {
  users: string[];
  count: number;
  hash: string;
}

export interface Hash {
  domain: string;
  user: string;
  lm: string;
  ntlm: string;
  enabled: boolean;
}

export interface WriteCsvOpts {
  records: string[][];
  columns: string[];
  filename: string;
}

export type DuplicatedHashes = Record<string, HashStat>;
