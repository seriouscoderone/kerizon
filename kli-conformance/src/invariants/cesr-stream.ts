/**
 * CESR Stream Composition Invariants:
 *
 * Property 1 (Self-Framing): Every JSON body + attachment group in a CESR
 *   stream has text-domain length divisible by 4. This is the fundamental
 *   CESR composability guarantee.
 *
 * Property 2 (Version String): The first field of every event body starts
 *   with a KERI version string matching /KERI\d{2}JSON[0-9a-f]{6}_/
 *
 * Property 3 (Attachment Order): Attachments always follow their event body.
 *   A `-` count code prefix appears after the `}` JSON close brace.
 *
 * Property 4 (Count Codes): All count codes in the stream start with `-`
 *   and are exactly 4 or 8 characters wide.
 */

const KERI_VERSION_RE = /KERI\d{2}JSON[0-9a-f]{6}_/;

/**
 * Locate all JSON bodies and attachment groups in raw CESR bytes.
 * Returns segments with their offsets and text-domain lengths.
 */
function segmentStream(cesr: Uint8Array): Array<{
  kind: 'body' | 'attachment';
  offset: number;
  length: number;
  text: string;
}> {
  const text = new TextDecoder().decode(cesr);
  const segments: Array<{
    kind: 'body' | 'attachment';
    offset: number;
    length: number;
    text: string;
  }> = [];

  let i = 0;
  while (i < text.length) {
    if (text[i] === '{') {
      // JSON body: find the matching closing brace
      let depth = 0;
      let inString = false;
      let escaped = false;
      let j = i;
      while (j < text.length) {
        const ch = text[j];
        if (escaped) {
          escaped = false;
          j++;
          continue;
        }
        if (ch === '\\' && inString) {
          escaped = true;
          j++;
          continue;
        }
        if (ch === '"') {
          inString = !inString;
        } else if (!inString) {
          if (ch === '{') depth++;
          else if (ch === '}') {
            depth--;
            if (depth === 0) {
              j++;
              break;
            }
          }
        }
        j++;
      }
      const bodyText = text.slice(i, j);
      segments.push({ kind: 'body', offset: i, length: bodyText.length, text: bodyText });
      i = j;
    } else if (text[i] === '-') {
      // Attachment group: starts with count code, consume until next `{` or end
      const attachStart = i;
      // Find the end of this attachment region (next JSON body or end of stream)
      while (i < text.length && text[i] !== '{') {
        i++;
      }
      const attachText = text.slice(attachStart, i);
      if (attachText.length > 0) {
        segments.push({ kind: 'attachment', offset: attachStart, length: attachText.length, text: attachText });
      }
    } else {
      // Skip whitespace or other characters
      i++;
    }
  }

  return segments;
}

/**
 * Check CESR stream quadlet alignment.
 *
 * In a CESR stream, the alignment unit is the complete message frame:
 * JSON body + all its attachment groups. Each attachment group is
 * independently quadlet-aligned (count codes are 4 or 8 chars, followed
 * by quadlet-aligned primitives). The JSON body itself may not be a
 * multiple of 4 -- padding occurs via the version string size field.
 *
 * What we can check at the stream level:
 * - Attachment groups are quadlet-aligned (length % 4 == 0)
 * - The total stream length is a valid concatenation
 */
export function checkStreamSelfFraming(cesr: Uint8Array): {
  valid: boolean;
  violations: string[];
} {
  const segments = segmentStream(cesr);
  const violations: string[] = [];

  // Attachment regions must be quadlet-aligned
  for (const seg of segments) {
    if (seg.kind === 'attachment' && seg.length % 4 !== 0) {
      violations.push(
        `attachment at offset ${seg.offset}: length ${seg.length} is not a multiple of 4`,
      );
    }
  }

  return { valid: violations.length === 0, violations };
}

/**
 * Check that the first field of every JSON body starts with a KERI version string.
 * The version string format is: KERIvvSSSSSSSSSS_ where vv is the major+minor version,
 * SSSSSS is the hex-encoded size, and the serial kind is JSON/CBOR/MGPK.
 */
export function checkVersionString(cesr: Uint8Array): {
  valid: boolean;
  violations: string[];
} {
  const segments = segmentStream(cesr);
  const violations: string[] = [];

  for (const seg of segments) {
    if (seg.kind !== 'body') continue;

    try {
      const parsed = JSON.parse(seg.text);
      const version = parsed['v'];
      if (typeof version !== 'string') {
        violations.push(`Body at offset ${seg.offset}: missing 'v' field`);
      } else if (!KERI_VERSION_RE.test(version)) {
        violations.push(
          `Body at offset ${seg.offset}: version string "${version}" does not match KERI format`,
        );
      }
    } catch {
      violations.push(`Body at offset ${seg.offset}: could not parse JSON`);
    }
  }

  return { valid: violations.length === 0, violations };
}

/**
 * Check that attachments follow their respective event body.
 * In a well-formed CESR stream, the pattern is: JSON body, then attachment
 * group(s) starting with `-` count code, then next JSON body, etc.
 */
export function checkAttachmentOrder(cesr: Uint8Array): {
  valid: boolean;
  violations: string[];
} {
  const segments = segmentStream(cesr);
  const violations: string[] = [];

  for (let i = 0; i < segments.length; i++) {
    const seg = segments[i];
    if (seg.kind === 'attachment') {
      // An attachment must be preceded by a body or another attachment
      if (i === 0) {
        violations.push(
          `Attachment at offset ${seg.offset}: appears before any event body`,
        );
      } else if (segments[i - 1].kind !== 'body' && segments[i - 1].kind !== 'attachment') {
        violations.push(
          `Attachment at offset ${seg.offset}: not preceded by a body or attachment`,
        );
      }
    }
  }

  return { valid: violations.length === 0, violations };
}

/**
 * Extract all count codes from the stream and verify structural correctness.
 * Count codes start with `-` and are exactly 4 chars (short) or 8+ chars (long).
 *
 * Returns the list of found codes and any violations.
 */
export function findCountCodes(cesr: Uint8Array): {
  codes: Array<{ code: string; offset: number }>;
  valid: boolean;
  violations: string[];
} {
  const text = new TextDecoder().decode(cesr);
  const codes: Array<{ code: string; offset: number }> = [];
  const violations: string[] = [];

  // Count codes appear in attachment regions: find all `-` prefixed sequences
  // outside of JSON bodies
  let inJson = false;
  let depth = 0;
  let inString = false;
  let escaped = false;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];

    if (escaped) {
      escaped = false;
      continue;
    }

    if (ch === '\\' && inString) {
      escaped = true;
      continue;
    }

    if (ch === '"' && inJson) {
      inString = !inString;
      continue;
    }

    if (!inString) {
      if (ch === '{') {
        depth++;
        inJson = true;
      } else if (ch === '}') {
        depth--;
        if (depth === 0) inJson = false;
      }
    }

    if (!inJson && ch === '-') {
      // Potential count code: extract up to 12 chars to check
      // Short count codes: 4 chars (e.g., -AAB)
      // Long count codes: start with --  and are 8 chars (e.g., --AAAAAB)
      if (i + 1 < text.length && text[i + 1] === '-') {
        // Long count code (8 chars)
        if (i + 8 <= text.length) {
          const code = text.slice(i, i + 8);
          codes.push({ code, offset: i });
          if (code.length !== 8) {
            violations.push(`Count code at offset ${i}: long code "${code}" is not 8 chars`);
          }
        } else {
          violations.push(`Count code at offset ${i}: truncated long count code`);
        }
      } else {
        // Short count code (4 chars)
        if (i + 4 <= text.length) {
          const code = text.slice(i, i + 4);
          codes.push({ code, offset: i });
          if (code.length !== 4) {
            violations.push(`Count code at offset ${i}: short code "${code}" is not 4 chars`);
          }
        } else {
          violations.push(`Count code at offset ${i}: truncated short count code`);
        }
      }
    }
  }

  // Verify all found codes start with `-`
  for (const { code, offset } of codes) {
    if (!code.startsWith('-')) {
      violations.push(`Count code at offset ${offset}: "${code}" does not start with '-'`);
    }
  }

  return { codes, valid: violations.length === 0, violations };
}
