"""Resolve the Anthropic API key from the environment or a project file.

Resolution order (first hit wins):
  1. ANTHROPIC_API_KEY environment variable
  2. apikey.txt at the project root  (a raw key on its own line; # comments ok)
  3. .env at the project root        (ANTHROPIC_API_KEY=... line)

Both files are gitignored. This lets a user drop their key into a file with an
editor — no terminal needed — and the server picks it up on the next request.
"""
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_api_key():
    env = os.environ.get("ANTHROPIC_API_KEY")
    if env and env.strip():
        return env.strip()

    txt = os.path.join(PROJECT_ROOT, "apikey.txt")
    if os.path.exists(txt):
        for line in open(txt, encoding="utf-8"):
            line = line.strip()
            if line.startswith("sk-"):  # a real key; ignores comments/placeholder
                return line

    dotenv = os.path.join(PROJECT_ROOT, ".env")
    if os.path.exists(dotenv):
        for line in open(dotenv, encoding="utf-8"):
            line = line.strip()
            if line.startswith("ANTHROPIC_API_KEY"):
                val = line.split("=", 1)[1].strip().strip("\"'")
                if val.startswith("sk-"):
                    return val

    return None
