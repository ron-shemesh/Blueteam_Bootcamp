"""Resolve the Anthropic API key from the environment or a project file.

Resolution order (first hit wins):
  1. ANTHROPIC_API_KEY environment variable
  2. apikey.txt at the project root        (gitignored; a raw key on its own line)
  3. .env at the project root              (gitignored; ANTHROPIC_API_KEY=... line)
  4. apikey.txt.example at the project root (committed template; works if a key is
     pasted into it after cloning, so the product runs straight from a fresh clone)

Only lines beginning with "sk-" count as a key, so placeholders/comments are
ignored. Drop your key into a file with an editor — no terminal needed — and the
server picks it up on the next request.
"""
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _key_from_file(path):
    if not os.path.exists(path):
        return None
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if line.startswith("sk-"):  # a real key; ignores comments/placeholder
            return line
        if line.startswith("ANTHROPIC_API_KEY"):
            val = line.split("=", 1)[1].strip().strip("\"'")
            if val.startswith("sk-"):
                return val
    return None


def load_api_key():
    env = os.environ.get("ANTHROPIC_API_KEY")
    if env and env.strip():
        return env.strip()
    for fname in ("apikey.txt", ".env", "apikey.txt.example"):
        key = _key_from_file(os.path.join(PROJECT_ROOT, fname))
        if key:
            return key
    return None
