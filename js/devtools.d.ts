import type { Finding, OwaspCategoryInfo } from './index.js';

export type ScanLang = 'java' | 'js' | 'template' | 'config';
export type ScanSeverity = 'HIGH' | 'MEDIUM' | 'LOW';

export interface ScanRule {
  id: string;
  langs: Set<ScanLang>;
  severity: ScanSeverity;
  owasp: OwaspCategoryInfo;
  maskStrings: boolean;
  pattern: RegExp;
  unless: RegExp | null;
  unlessFile: RegExp | null;
  message: string;
  fix: string;
}

export interface ScanFinding {
  rule: ScanRule;
  file: string;
  /** 1-based */
  line: number;
  /** 1-based */
  column: number;
  source: string;
}

export interface ScanReport {
  findings: ScanFinding[];
  filesScanned: number;
  ruleCount: number;
}

export declare const DEFAULT_EXCLUDED_DIRS: Set<string>;
export declare function parseRules(text: string): ScanRule[];
export declare function defaultRules(): ScanRule[];
export declare function langOf(fileName: string): ScanLang | null;
export declare function maskStrings(line: string, lang: ScanLang): string;
export declare function atLeast(findings: ScanFinding[], minimum: ScanSeverity): ScanFinding[];
export declare function toText(report: ScanReport, options?: { base?: string; withFix?: boolean }): string;
export declare function toJson(report: ScanReport, options?: { base?: string }): string;
export declare function toSarif(report: ScanReport, options?: { base?: string }): string;

export declare class SourceScanner {
  constructor(options?: { rules?: ScanRule[]; excludedDirs?: Iterable<string> });
  scan(...paths: string[]): ScanReport;
  scanText(fileName: string, content: string): ScanFinding[];
}

export interface Explanation {
  input: string;
  decoded: string;
  stripped: string;
  verdict: string;
  score: number;
  threshold: number;
  malicious: boolean;
  findings: Finding[];
}

export declare function explain(value: string): Explanation;

export interface ProbeTarget {
  /** URL with FUZZ where the payload goes, e.g. http://localhost:3000/search?q=FUZZ */
  url: string;
  method?: string;
  /** Form or JSON body, may contain FUZZ */
  body?: string;
  headers?: Record<string, string>;
  baseline?: string;
  only?: string[];
  /** Allow non-local targets. Only for systems you own or are authorized to test. */
  allowRemote?: boolean;
  timeoutMs?: number;
}

export interface ProbeResult {
  check: string;
  payload: string;
  status: number;
  millis: number;
  severity: ScanSeverity | null;
  verdict: string;
  vulnerable: boolean;
}

export declare const DB_ERROR: RegExp;
export declare function probePayloads(): Array<[check: string, payload: string]>;
export declare function checkTargetAllowed(target: ProbeTarget): Promise<void>;
export declare function probe(
  target: ProbeTarget,
  onResult?: (result: ProbeResult, context: { baseline: { status: number; body: string }; baseMillis: number }) => void,
): Promise<ProbeResult[]>;

export declare function checkHostAllowed(url: string, allowRemote?: boolean): Promise<void>;

export interface IdorTarget {
  /** The object's URL, e.g. http://localhost:3000/api/orders/42 */
  url: string;
  /** Headers that authenticate the object's owner, e.g. { Authorization: 'Bearer ...' } or { Cookie: 'sid=...' } */
  owner: Record<string, string>;
  /** Headers that authenticate a different ordinary user */
  other: Record<string, string>;
  method?: string;
  body?: string;
  /** Text only the owner's data contains (an email, order number...). Makes the verdict exact. */
  marker?: string;
  /** Also try without credentials (default true) */
  anonymous?: boolean;
  /** Allow non-local targets. Only for systems you own or are authorized to test. */
  allowRemote?: boolean;
  timeoutMs?: number;
}

export interface IdorResult {
  as: 'owner' | 'other user' | 'no credentials';
  status: number;
  severity: ScanSeverity | null;
  verdict: string;
  vulnerable: boolean;
}

export declare function idorProbe(target: IdorTarget): Promise<IdorResult[]>;
