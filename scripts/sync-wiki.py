#!/usr/bin/env python3
"""Publish docs/ to the GitHub wiki.

docs/ in the repository is the single source; the wiki is generated from it so
the two never drift. Pages are renamed to wiki titles and relative links are
rewritten (doc -> wiki page, repository files -> GitHub URLs).

Usage:
    git clone https://github.com/<owner>/cs-factory.wiki.git /tmp/wiki
    python3 scripts/sync-wiki.py /tmp/wiki [--ref v1.0.0]
    cd /tmp/wiki && git add -A && git commit -m "Sync from docs/" && git push

(GitHub creates the wiki repository only after its first page has been saved
in the web UI - create any page once, then this script replaces it.)
"""
import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPO_URL = "https://github.com/wd-ppisz/cs-factory"

# docs file -> wiki page name (the page title is the name with '-' as spaces)
PAGES = {
    "README.md": "Home",
    "installation.md": "Installation",
    "gui-guide.md": "Using-the-GUI",
    "configuration.md": "Configuration",
    "cloudstack.md": "CloudStack-prerequisites",
    "troubleshooting.md": "Troubleshooting",
}

LINK = re.compile(r"\]\(([^)\s]+)\)")


def rewrite(text: str, ref: str) -> str:
    def fix(m: re.Match) -> str:
        target = m.group(1)
        if re.match(r"^[a-z]+://|^#|^mailto:", target):
            return m.group(0)
        path, _, anchor = target.partition("#")
        anchor = f"#{anchor}" if anchor else ""
        if path in PAGES:
            return f"]({PAGES[path]}{anchor})"
        if path.startswith("../"):
            return f"]({REPO_URL}/blob/{ref}/{path[3:]}{anchor})"
        return f"]({REPO_URL}/blob/{ref}/docs/{path}{anchor})"
    return LINK.sub(fix, text)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("wiki_dir", type=Path, help="clone of <repo>.wiki.git")
    ap.add_argument("--ref", default="main", help="git ref for links to repository files")
    a = ap.parse_args()
    if not (a.wiki_dir / ".git").exists():
        print(f"{a.wiki_dir} is not a git clone of the wiki", file=sys.stderr)
        return 1

    banner = (f"> Generated from [`docs/`]({REPO_URL}/tree/{a.ref}/docs) - edit there, "
              "not in the wiki.\n\n")
    for src, page in PAGES.items():
        body = rewrite((ROOT / "docs" / src).read_text(encoding="utf-8"), a.ref)
        if page == "Home":
            body = re.sub(r"\nThe same pages are published in the\n.*?their source\.\n", "\n",
                          body, flags=re.S)
        (a.wiki_dir / f"{page}.md").write_text(banner + body, encoding="utf-8")
        print(f"{src:20} -> {page}.md")

    side = ["**CloudStack Template Factory**", ""]
    side += [f"- [{p.replace('-', ' ')}]({p})" for p in PAGES.values()]
    side += ["", f"[Repository]({REPO_URL}) · [Releases]({REPO_URL}/releases) · "
             f"[Changelog]({REPO_URL}/blob/{a.ref}/CHANGELOG.md)"]
    (a.wiki_dir / "_Sidebar.md").write_text("\n".join(side) + "\n", encoding="utf-8")
    print("sidebar             -> _Sidebar.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
