"""
Prompt Injection via Malicious Filename — Detection Script
Tests whether filenames in a repo contain shell command injection patterns.
"""

import os
import re
import sys

# Patterns that indicate command injection in filenames
INJECTION_PATTERNS = [
    (r'\$\(', "Command substitution $()"),
    (r'`[^`]+`', "Backtick command substitution"),
    (r'\$\{IFS\}', "IFS substitution (evasion)"),
    (r';\s*(rm|curl|wget|bash|sh|python|nc|ncat)\b', "Command chaining with dangerous binary"),
    (r'\|\s*(sh|bash|zsh|python)\b', "Pipe to shell"),
    (r'\.\./\.\.',  "Path traversal"),
    (r'%[0-9a-fA-F]{2}', "URL encoding (possible evasion)"),
]

def scan_directory(root_dir: str) -> list[dict]:
    findings = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Don't skip hidden dirs — attackers hide there
        for filename in filenames:
            for pattern, label in INJECTION_PATTERNS:
                if re.search(pattern, filename):
                    findings.append({
                        "file": os.path.join(dirpath, filename),
                        "pattern": label,
                        "matched": re.search(pattern, filename).group(0),
                    })
                    break  # one finding per file is enough
    return findings


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"Scanning: {os.path.abspath(root)}\n")

    findings = scan_directory(root)

    if not findings:
        print("✓ No injection patterns detected in filenames.")
        return

    print(f"⚠️  {len(findings)} suspicious filename(s) found:\n")
    for f in findings:
        print(f"  FILE   : {f['file']}")
        print(f"  PATTERN: {f['pattern']}")
        print(f"  MATCHED: {f['matched']}")
        print()

    print("Recommendation: Do not let any AI agent or shell script process")
    print("these filenames without sanitization. Remove or quarantine them.")
    sys.exit(1)


if __name__ == "__main__":
    main()
