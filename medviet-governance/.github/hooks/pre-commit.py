"""
Cross-platform pre-commit secret scanner — thay thế git-secrets cho Windows.

Cách dùng:
  python .github/hooks/pre-commit.py           # quét staged files
  python .github/hooks/pre-commit.py --all     # quét toàn repo

Để cài làm git hook:
  copy .github\\hooks\\pre-commit.py .git\\hooks\\pre-commit
  (trên Windows, Git for Windows sẽ chạy file này nếu có shebang)
"""
from __future__ import annotations

import io
import re
import subprocess
import sys
from pathlib import Path

# Force UTF-8 output trên Windows (mặc định là cp1252 — không in được tiếng Việt)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
else:
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

SECRET_PATTERNS = [
    # Credentials
    (r"AWS_SECRET_ACCESS_KEY\s*=\s*['\"][A-Za-z0-9/+=]{30,}['\"]", "AWS secret access key"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key ID"),
    (r"AWS_SECRET_KEY\s*=\s*['\"][^'\"]+['\"]", "AWS secret key assignment"),
    (r"password\s*=\s*['\"][^'\"]{4,}['\"]", "Hardcoded password"),
    (r"secret_key\s*=\s*['\"][^'\"]{4,}['\"]", "Hardcoded secret_key"),
    (r"api[_-]?key\s*=\s*['\"][^'\"]{8,}['\"]", "Hardcoded API key"),
    (r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----", "Private key file"),
    # Vietnamese PII patterns
    (r"CCCD[:\s]+\d{12}", "Vietnamese CCCD number"),
    (r"cccd[:\s]+\d{12}", "Vietnamese CCCD number (lower)"),
]

COMPILED = [(re.compile(pat), label) for pat, label in SECRET_PATTERNS]

ALLOW_EXTENSIONS = {".py", ".js", ".ts", ".env", ".yml", ".yaml",
                    ".json", ".toml", ".ini", ".cfg", ".txt", ".md"}
SKIP_PATHS = {".git", "__pycache__", "node_modules", ".venv", "venv",
              "data/raw", "reports"}


def get_staged_files() -> list[Path]:
    try:
        out = subprocess.check_output(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            text=True,
        )
    except subprocess.CalledProcessError:
        return []
    return [Path(p) for p in out.splitlines() if p]


def get_all_files() -> list[Path]:
    files = []
    for path in Path(".").rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_PATHS for part in path.parts):
            continue
        files.append(path)
    return files


def scan_file(path: Path) -> list[tuple[int, str, str]]:
    if path.suffix and path.suffix not in ALLOW_EXTENSIONS:
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []
    findings = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for pattern, label in COMPILED:
            if pattern.search(line):
                findings.append((lineno, label, line.strip()[:120]))
    return findings


def main() -> int:
    files = get_all_files() if "--all" in sys.argv else get_staged_files()
    if not files:
        print("[pre-commit.py] No files to scan.")
        return 0

    total_issues = 0
    for f in files:
        if not f.exists():
            continue
        for lineno, label, snippet in scan_file(f):
            total_issues += 1
            print(f"  [SECRET] {f}:{lineno} — {label}")
            print(f"           {snippet}")

    if total_issues:
        print(f"\n{total_issues} potential secret(s) detected. Commit blocked.")
        return 1
    print("[pre-commit.py] No secrets detected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
