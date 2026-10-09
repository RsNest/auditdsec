#!/usr/bin/env python3
"""Fold the panel's assets into one self-contained file for design review.

The agent serves the separate files; this is only for looking at the result
without running anything. Demo data is inlined, so the page never calls an API.
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
ASSETS = ROOT / "internal" / "web" / "assets"
OUT = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "preview.html"


def read(name: str) -> str:
    return (ASSETS / name).read_text(encoding="utf-8")


def main() -> None:
    html = read("index.html")
    html = html.replace(
        '<link rel="stylesheet" href="app.css">',
        "<style>\n" + read("app.css") + "\n</style>",
    )
    scripts = "".join(
        "<script>\n" + read(name) + "\n</script>\n"
        for name in ("i18n.js", "dev/mock.js", "core.js", "views.js")
    )
    for tag in ('<script src="i18n.js"></script>',
                '<script src="core.js"></script>',
                '<script src="views.js"></script>'):
        html = html.replace(tag, "")
    html = html.replace("</body>", scripts + "</body>")
    OUT.write_text(html, encoding="utf-8")
    print(f"{OUT} ({len(html.encode('utf-8')) // 1024} KiB)")


if __name__ == "__main__":
    main()
