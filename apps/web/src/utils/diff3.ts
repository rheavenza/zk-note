/**
 * Three-Way Text Diff3 and Structured Note Merge Engine (ZK-068).
 *
 * Implements deterministic three-way merge semantics according to MASTER_SPEC.md § 10.2 & 10.3:
 * - Non-overlapping line edits auto-merge cleanly.
 * - Identical concurrent edits merge without conflict.
 * - Overlapping divergent line edits become explicit conflicts with standard diff3 markers:
 *   <<<<<<< LOCAL
 *   =======
 *   >>>>>>> REMOTE
 * - Deterministic set-based tag merging (sorted, deduplicated, lowercase).
 * - Preserves all sides completely without silent data loss.
 */

import { PlaintextNoteDto } from "../worker/protocol.js";

export interface BodyConflict {
  baseLineStart: number;
  baseLines: string[];
  localLines: string[];
  remoteLines: string[];
}

export interface Diff3Result {
  mergedText: string;
  isClean: boolean;
  conflicts: BodyConflict[];
}

/**
 * Computes Longest Common Subsequence (LCS) matched line index pairs between slices a and b.
 * Uses prefix/suffix trimming before DP table computation.
 */
export function lcsMatchedPairs(a: string[], b: string[]): Array<[number, number]> {
  if (a.length === 0 || b.length === 0) {
    return [];
  }

  // 1. Trim common prefix
  let prefixLen = 0;
  while (prefixLen < a.length && prefixLen < b.length && a[prefixLen] === b[prefixLen]) {
    prefixLen++;
  }

  // 2. Trim common suffix
  let suffixLen = 0;
  while (
    suffixLen < a.length - prefixLen &&
    suffixLen < b.length - prefixLen &&
    a[a.length - 1 - suffixLen] === b[b.length - 1 - suffixLen]
  ) {
    suffixLen++;
  }

  const aMid = a.slice(prefixLen, a.length - suffixLen);
  const bMid = b.slice(prefixLen, b.length - suffixLen);

  const midPairs: Array<[number, number]> = [];

  if (aMid.length > 0 && bMid.length > 0) {
    const n = aMid.length;
    const m = bMid.length;

    if (n * m <= 4000000) {
      const stride = m + 1;
      const dp = new Int32Array((n + 1) * stride);

      for (let i = n - 1; i >= 0; i--) {
        for (let j = m - 1; j >= 0; j--) {
          if (aMid[i] === bMid[j]) {
            dp[i * stride + j] = 1 + (dp[(i + 1) * stride + (j + 1)] ?? 0);
          } else {
            const down = dp[(i + 1) * stride + j] ?? 0;
            const right = dp[i * stride + (j + 1)] ?? 0;
            dp[i * stride + j] = Math.max(down, right);
          }
        }
      }

      let i = 0;
      let j = 0;
      while (i < n && j < m) {
        if (aMid[i] === bMid[j]) {
          midPairs.push([prefixLen + i, prefixLen + j]);
          i++;
          j++;
        } else {
          const down = dp[(i + 1) * stride + j] ?? 0;
          const right = dp[i * stride + (j + 1)] ?? 0;
          if (down >= right) {
            i++;
          } else {
            j++;
          }
        }
      }
    }
  }

  const result: Array<[number, number]> = [];
  for (let k = 0; k < prefixLen; k++) {
    result.push([k, k]);
  }
  for (const p of midPairs) {
    result.push(p);
  }
  for (let k = 0; k < suffixLen; k++) {
    result.push([a.length - suffixLen + k, b.length - suffixLen + k]);
  }

  return result;
}

/**
 * Line-based three-way text merge (diff3).
 */
export function diff3Merge(base: string, local: string, remote: string): Diff3Result {
  // Fast path: if local equals remote, both made the exact same change
  if (local === remote) {
    return {
      mergedText: local,
      isClean: true,
      conflicts: [],
    };
  }

  // Fast path: if remote equals base, keep local
  if (remote === base) {
    return {
      mergedText: local,
      isClean: true,
      conflicts: [],
    };
  }

  // Fast path: if local equals base, keep remote
  if (local === base) {
    return {
      mergedText: remote,
      isClean: true,
      conflicts: [],
    };
  }

  // Normalize newlines to \n
  const baseNorm = base.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  const localNorm = local.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  const remoteNorm = remote.replace(/\r\n/g, "\n").replace(/\r/g, "\n");

  const baseLines = baseNorm.length === 0 ? [] : baseNorm.split("\n");
  const localLines = localNorm.length === 0 ? [] : localNorm.split("\n");
  const remoteLines = remoteNorm.length === 0 ? [] : remoteNorm.split("\n");

  const pairsBL = lcsMatchedPairs(baseLines, localLines);
  const pairsBR = lcsMatchedPairs(baseLines, remoteLines);

  const brMap = new Map<number, number>(pairsBR);

  // Common anchors: lines present in base that were matched in both local and remote
  const commonAnchors: Array<[number, number, number]> = [];
  for (const [b, l] of pairsBL) {
    const r = brMap.get(b);
    if (r !== undefined) {
      commonAnchors.push([b, l, r]);
    }
  }

  const outputLines: string[] = [];
  const conflicts: BodyConflict[] = [];

  let prevB = 0;
  let prevL = 0;
  let prevR = 0;

  const processChunk = (
    bStart: number,
    bEnd: number,
    lStart: number,
    lEnd: number,
    rStart: number,
    rEnd: number
  ) => {
    const chunkBase = baseLines.slice(bStart, bEnd);
    const chunkLocal = localLines.slice(lStart, lEnd);
    const chunkRemote = remoteLines.slice(rStart, rEnd);

    const localEqualBase =
      chunkLocal.length === chunkBase.length &&
      chunkLocal.every((val, idx) => val === chunkBase[idx]);

    const remoteEqualBase =
      chunkRemote.length === chunkBase.length &&
      chunkRemote.every((val, idx) => val === chunkBase[idx]);

    if (localEqualBase && remoteEqualBase) {
      // Unchanged in both
      for (const line of chunkBase) {
        outputLines.push(line);
      }
    } else if (!localEqualBase && remoteEqualBase) {
      // Changed only locally
      for (const line of chunkLocal) {
        outputLines.push(line);
      }
    } else if (localEqualBase && !remoteEqualBase) {
      // Changed only remotely
      for (const line of chunkRemote) {
        outputLines.push(line);
      }
    } else {
      // Both changed
      const localEqualRemote =
        chunkLocal.length === chunkRemote.length &&
        chunkLocal.every((val, idx) => val === chunkRemote[idx]);

      if (localEqualRemote) {
        // Identical concurrent edit
        for (const line of chunkLocal) {
          outputLines.push(line);
        }
      } else {
        // Overlapping divergent conflict
        conflicts.push({
          baseLineStart: bStart + 1,
          baseLines: chunkBase,
          localLines: chunkLocal,
          remoteLines: chunkRemote,
        });

        outputLines.push("<<<<<<< LOCAL");
        for (const line of chunkLocal) {
          outputLines.push(line);
        }
        outputLines.push("=======");
        for (const line of chunkRemote) {
          outputLines.push(line);
        }
        outputLines.push(">>>>>>> REMOTE");
      }
    }
  };

  for (const [b, l, r] of commonAnchors) {
    processChunk(prevB, b, prevL, l, prevR, r);

    // Emit the anchor line itself
    const anchorLine = baseLines[b];
    if (anchorLine !== undefined) {
      outputLines.push(anchorLine);
    }

    prevB = b + 1;
    prevL = l + 1;
    prevR = r + 1;
  }

  // Process final region after last anchor
  processChunk(prevB, baseLines.length, prevL, localLines.length, prevR, remoteLines.length);

  const mergedText = outputLines.join("\n");
  const isClean = conflicts.length === 0;

  return {
    mergedText,
    isClean,
    conflicts,
  };
}

/**
 * Three-way tag set merge.
 * - Tags in base are kept unless deleted by local or remote.
 * - Tags not in base are added if added by local or remote.
 * - Canonical output: lowercase, trimmed, deduplicated, sorted.
 */
export function mergeTags(
  baseTags: string[],
  localTags: string[],
  remoteTags: string[]
): string[] {
  const baseSet = new Set(baseTags.map((t) => t.trim().toLowerCase()).filter(Boolean));
  const localSet = new Set(localTags.map((t) => t.trim().toLowerCase()).filter(Boolean));
  const remoteSet = new Set(remoteTags.map((t) => t.trim().toLowerCase()).filter(Boolean));

  const allTags = new Set<string>([...baseSet, ...localSet, ...remoteSet]);
  const merged: string[] = [];

  for (const tag of allTags) {
    const inBase = baseSet.has(tag);
    const inLocal = localSet.has(tag);
    const inRemote = remoteSet.has(tag);

    if (inBase) {
      // Kept unless removed by either side
      if (inLocal && inRemote) {
        merged.push(tag);
      }
    } else {
      // Added if added by either side
      if (inLocal || inRemote) {
        merged.push(tag);
      }
    }
  }

  merged.sort((a, b) => a.localeCompare(b));
  return merged;
}

export interface ThreeWayNoteMergeResult {
  candidate: PlaintextNoteDto;
  isClean: boolean;
  hasTitleConflict: boolean;
  hasBodyConflict: boolean;
  diffResult: Diff3Result;
}

/**
 * Executes a full 3-way structured merge between BASE, LOCAL, and REMOTE notes.
 */
export function threeWayMergeNotes(
  baseNote: PlaintextNoteDto | null,
  localNote: PlaintextNoteDto,
  remoteNote: PlaintextNoteDto
): ThreeWayNoteMergeResult {
  const baseTitle = baseNote?.title || "";
  const baseBody = baseNote?.body || "";
  const baseTags = baseNote?.tags || [];

  // 1. Title merge
  let mergedTitle = localNote.title;
  let hasTitleConflict = false;

  const localTitleChanged = localNote.title !== baseTitle;
  const remoteTitleChanged = remoteNote.title !== baseTitle;

  if (!localTitleChanged && !remoteTitleChanged) {
    mergedTitle = baseTitle;
  } else if (localTitleChanged && !remoteTitleChanged) {
    mergedTitle = localNote.title;
  } else if (!localTitleChanged && remoteTitleChanged) {
    mergedTitle = remoteNote.title;
  } else {
    // Both changed
    if (localNote.title === remoteNote.title) {
      mergedTitle = localNote.title;
    } else {
      hasTitleConflict = true;
      mergedTitle = localNote.title; // Default candidate to local title
    }
  }

  // 2. Body merge (diff3)
  const diffResult = diff3Merge(baseBody, localNote.body, remoteNote.body);

  // 3. Tags merge
  const mergedTags = mergeTags(baseTags, localNote.tags, remoteNote.tags);

  // 4. Attachments merge (3-way set merge)
  const baseAttachments = baseNote?.attachments || [];
  const localAttachments = localNote.attachments || [];
  const remoteAttachments = remoteNote.attachments || [];
  const mergedAttachments = mergeTags(baseAttachments, localAttachments, remoteAttachments);

  const isClean = !hasTitleConflict && diffResult.isClean;

  const candidate: PlaintextNoteDto = {
    id: localNote.id,
    title: mergedTitle,
    body: diffResult.mergedText,
    tags: mergedTags,
    attachments: mergedAttachments,
    createdAt: localNote.createdAt || remoteNote.createdAt || new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  return {
    candidate,
    isClean,
    hasTitleConflict,
    hasBodyConflict: !diffResult.isClean,
    diffResult,
  };
}
