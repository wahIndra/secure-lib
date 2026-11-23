import fs from 'node:fs';
import path from 'node:path';
import { decode } from './normalize.js';
import { OwaspCategory, SecurityViolationError } from './owasp.js';

export class PathTraversalError extends SecurityViolationError {
  constructor(message) {
    super(OwaspCategory.BROKEN_ACCESS_CONTROL, message);
    this.name = 'PathTraversalError';
  }
}

const within = (base, p) => p !== base && p.startsWith(base.endsWith(path.sep) ? base : base + path.sep);

/**
 * Resolves user-supplied relative paths inside a fixed base directory and refuses anything
 * that escapes it: ../ segments, encoded traversal, absolute and UNC paths, drive letters,
 * NTFS streams, null bytes and symlinks pointing outside the base.
 *
 * @example
 * const uploads = PathTraversalGuard.forBaseDirectory('/srv/app/uploads');
 * const file = uploads.resolve(req.query.name);   // throws PathTraversalError
 */
export class PathTraversalGuard {
  /** The base directory must exist; its real path (symlinks resolved) becomes the boundary. */
  static forBaseDirectory(baseDirectory) {
    const real = fs.realpathSync.native(path.resolve(baseDirectory));
    if (!fs.statSync(real).isDirectory()) throw new Error(`Base path is not a directory: ${real}`);
    return new PathTraversalGuard(real);
  }

  constructor(realBase) {
    this.base = realBase;
  }

  resolve(userPath) {
    validateRelative(userPath);
    const segments = String(userPath).split(/[/\\]+/).filter((s) => s && s !== '.');
    const resolved = path.resolve(this.base, ...segments);
    if (!within(this.base, resolved)) throw new PathTraversalError('path escapes base directory');
    this.#assertNoSymlinkEscape(resolved);
    return resolved;
  }

  isSafe(userPath) {
    try {
      this.resolve(userPath);
      return true;
    } catch (e) {
      if (e instanceof PathTraversalError) return false;
      throw e;
    }
  }

  #assertNoSymlinkEscape(resolved) {
    // Walk up to the deepest part of the path that exists and check its real location.
    let existing = resolved;
    while (!fs.existsSync(existing)) {
      const parent = path.dirname(existing);
      if (parent === existing) throw new PathTraversalError('path escapes base directory');
      existing = parent;
    }
    let real;
    try {
      real = fs.realpathSync.native(existing);
    } catch {
      throw new PathTraversalError('cannot resolve real path');
    }
    if (real !== this.base && !within(this.base, real)) throw new PathTraversalError('symlink escapes base directory');
  }
}

function validateRelative(userPath) {
  if (typeof userPath !== 'string' || userPath.trim() === '') throw new PathTraversalError('empty path');
  if (userPath.length > 4096) throw new PathTraversalError('path too long');
  // Check the decoded form too: a layer below (proxy, framework, file API) may decode
  // %2e%2e%2f before the file system sees it.
  for (const candidate of [userPath, decode(userPath)]) {
    if (candidate.includes('\0')) throw new PathTraversalError('null byte in path');
    if (candidate.includes(':')) throw new PathTraversalError('drive letter, scheme or alternate data stream in path');
    if (/^[/\\~]/.test(candidate)) throw new PathTraversalError('absolute path');
    for (const seg of candidate.split(/[/\\]+/)) {
      if (seg.length >= 2 && seg.replace(/\./g, '').trim() === '') throw new PathTraversalError('traversal segment');
    }
  }
}

const WINDOWS_RESERVED = /^(?:con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\..*)?$/i;

/** Validation and sanitizing of single file names, e.g. for uploads. */
export const SafeFileName = {
  isSafe(name) {
    return (
      typeof name === 'string' &&
      /^[A-Za-z0-9][A-Za-z0-9._ -]{0,254}$/.test(name) &&
      !name.includes('..') &&
      !/[. ]$/.test(name) &&
      !WINDOWS_RESERVED.test(name)
    );
  },

  require(name) {
    if (!SafeFileName.isSafe(name)) throw new PathTraversalError('unsafe file name');
    return name;
  },

  /** Path components dropped, disallowed characters become '_', reserved names prefixed. Never empty. */
  sanitize(name) {
    let s = String(name ?? '');
    s = s.slice(Math.max(s.lastIndexOf('/'), s.lastIndexOf('\\')) + 1);
    s = s.replace(/[^A-Za-z0-9._ -]/g, '_').replace(/\.{2,}/g, '.');
    s = s.replace(/^[. _-]+/, '').replace(/[. ]+$/, '');
    if (s.length > 255) {
      const dot = s.lastIndexOf('.');
      const ext = dot > 0 && s.length - dot <= 16 ? s.slice(dot) : '';
      s = s.slice(0, 255 - ext.length) + ext;
    }
    if (!s) s = 'file';
    if (WINDOWS_RESERVED.test(s)) s = `_${s}`;
    return s;
  },

  extension(name) {
    const dot = typeof name === 'string' ? name.lastIndexOf('.') : -1;
    return dot < 0 ? '' : name.slice(dot + 1).toLowerCase();
  },
};
