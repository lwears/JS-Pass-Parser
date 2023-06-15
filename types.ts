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
  admins: Record<string, string>;
}

export interface HashStat {
  users: string[];
  count: number;
  hash: string;
}

export interface Hash {
  domain: string | null;
  user: string;
  lm: string;
  ntlm: string;
  enabled: boolean;
  isComputer: boolean;
  isAdmin: boolean;
}

export interface WriteCsvOpts {
  records: string[][];
  columns: string[];
  filename: string;
}

export type DuplicatedHashes = Record<string, HashStat>;
