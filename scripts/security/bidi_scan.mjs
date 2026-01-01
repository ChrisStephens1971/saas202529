#!/usr/bin/env node
/**
 * Scan git-tracked files for unsafe bidirectional and hidden Unicode control characters
 *
 * Unsafe characters scanned (security/review-integrity risk):
 * - Bidi controls: U+202A, U+202B, U+202C, U+202D, U+202E, U+2066, U+2067, U+2068, U+2069
 * - Zero-width/invisible: U+200B, U+200C, U+200D, U+200E, U+200F, U+FEFF
 */

import { execSync } from 'child_process';
import { readFileSync, writeFileSync } from 'fs';
import { join } from 'path';

// Unsafe character codepoints to detect
const UNSAFE_CHARS = {
  // Bidi controls
  '\u202A': 'LRE (Left-to-Right Embedding)',
  '\u202B': 'RLE (Right-to-Left Embedding)',
  '\u202C': 'PDF (Pop Directional Formatting)',
  '\u202D': 'LRO (Left-to-Right Override)',
  '\u202E': 'RLO (Right-to-Left Override)',
  '\u2066': 'LRI (Left-to-Right Isolate)',
  '\u2067': 'RLI (Right-to-Left Isolate)',
  '\u2068': 'FSI (First Strong Isolate)',
  '\u2069': 'PDI (Pop Directional Isolate)',

  // Zero-width / invisible format chars
  '\u200B': 'ZWSP (Zero Width Space)',
  '\u200C': 'ZWNJ (Zero Width Non-Joiner)',
  '\u200D': 'ZWJ (Zero Width Joiner)',
  '\u200E': 'LRM (Left-to-Right Mark)',
  '\u200F': 'RLM (Right-to-Left Mark)',
  '\uFEFF': 'BOM/ZWNBSP (Zero Width No-Break Space)'
};

// Build regex pattern
const unsafePattern = new RegExp(
  Object.keys(UNSAFE_CHARS).join('|'),
  'g'
);

// Get git-tracked files
function getGitFiles() {
  try {
    const output = execSync('git ls-files', { encoding: 'utf-8' });
    return output.split('\n').filter(f => f.trim().length > 0);
  } catch (error) {
    console.error('Error getting git files:', error.message);
    process.exit(1);
  }
}

// Scan a single file
function scanFile(filePath) {
  try {
    const content = readFileSync(filePath, 'utf-8');
    const findings = [];
    let match;

    unsafePattern.lastIndex = 0; // Reset regex
    while ((match = unsafePattern.exec(content)) !== null) {
      const char = match[0];
      const codepoint = 'U+' + char.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0');
      const name = UNSAFE_CHARS[char];

      // Find line number
      const beforeMatch = content.substring(0, match.index);
      const lineNumber = beforeMatch.split('\n').length;

      findings.push({
        char,
        codepoint,
        name,
        position: match.index,
        line: lineNumber
      });
    }

    return findings;
  } catch (error) {
    // Likely binary file or encoding issue, skip
    return [];
  }
}

// Main scan function
function main() {
  console.log('Scanning git-tracked files for unsafe Unicode control characters...\n');

  const files = getGitFiles();
  const results = {};
  let totalFindings = 0;

  for (const file of files) {
    const findings = scanFile(file);
    if (findings.length > 0) {
      results[file] = findings;
      totalFindings += findings.length;
    }
  }

  // Output JSON report
  const jsonPath = 'docs/ops/reports/_tmp_bidi_scan.json';
  writeFileSync(jsonPath, JSON.stringify(results, null, 2), 'utf-8');

  // Output human-readable report
  if (totalFindings === 0) {
    console.log('✅ No unsafe Unicode control characters found.\n');
  } else {
    console.log(`⚠️  Found ${totalFindings} unsafe character(s) in ${Object.keys(results).length} file(s):\n`);

    for (const [file, findings] of Object.entries(results)) {
      console.log(`📄 ${file}:`);

      // Count occurrences by codepoint
      const counts = {};
      for (const finding of findings) {
        counts[finding.codepoint] = (counts[finding.codepoint] || 0) + 1;
      }

      for (const [codepoint, count] of Object.entries(counts)) {
        const example = findings.find(f => f.codepoint === codepoint);
        console.log(`   ${codepoint} (${example.name}): ${count}x`);
      }
      console.log('');
    }

    console.log(`📊 Summary: ${totalFindings} total findings`);
    console.log(`📁 JSON report: ${jsonPath}\n`);
  }

  // Exit with status
  process.exit(totalFindings > 0 ? 1 : 0);
}

main();
