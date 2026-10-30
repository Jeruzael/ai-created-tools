"""Maintainer-only Lucide sprite generation; never run by the application or CI."""

import json
from pathlib import Path
import urllib.request
import xml.etree.ElementTree as ET


ICONS = ("layout-dashboard", "scan-line", "folder", "activity", "package", "shield-check",
         "history", "book-open", "info", "panel-left", "menu", "x", "copy", "chevron-left",
         "chevron-right", "arrow-up-down", "bell", "hard-drive", "arrow-right", "play", "log-out")


def main():
    headers = {"User-Agent": "SidebarStudio-icon-vendor", "Accept": "application/vnd.github+json"}
    request = urllib.request.Request("https://api.github.com/repos/lucide-icons/lucide/commits/main", headers=headers)
    with urllib.request.urlopen(request, timeout=30) as response:
        revision = json.load(response)["sha"]
    base = "https://raw.githubusercontent.com/lucide-icons/lucide/" + revision + "/"
    root = Path(__file__).resolve().parents[1] / "ui"
    root.mkdir(exist_ok=True)
    symbols = []
    for name in ICONS:
        print("Reading " + name, flush=True)
        source_name = "clock" if name == "history" else name
        with urllib.request.urlopen(base + "icons/" + source_name + ".svg", timeout=30) as response:
            svg = ET.fromstring(response.read())
        for element in svg.iter():
            element.tag = element.tag.rsplit("}", 1)[-1]
            if element.tag not in ("svg", "path", "rect", "circle", "line", "polyline", "polygon", "ellipse"):
                raise ValueError("Unexpected icon element")
            if any(key not in ("xmlns", "width", "height", "viewBox", "fill", "stroke", "stroke-width",
                               "stroke-linecap", "stroke-linejoin", "class", "d", "x", "y", "rx", "ry",
                               "cx", "cy", "r", "x1", "x2", "y1", "y2", "points") for key in element.attrib):
                raise ValueError("Unexpected icon attribute")
        body = "".join(ET.tostring(child, encoding="unicode") for child in svg)
        symbols.append(f'<symbol id="icon-{name}" viewBox="0 0 24 24">{body}</symbol>')
    sprite = '<svg xmlns="http://www.w3.org/2000/svg" class="icon-sprite" aria-hidden="true">' + "".join(symbols) + '</svg>'
    (root / "lucide-sprite.svg").write_text(sprite, encoding="utf-8")
    with urllib.request.urlopen(base + "LICENSE", timeout=30) as response:
        (root / "LUCIDE-LICENSE.txt").write_bytes(response.read())
    (root / "lucide-source.json").write_text(json.dumps({"repository": "https://github.com/lucide-icons/lucide",
        "revision": revision, "icons": ICONS, "aliases": {"history": "clock"}}, indent=2) + "\n", encoding="utf-8")
    print(f"Vendored {len(ICONS)} icons at {revision}; runtime remains offline.")


if __name__ == "__main__":
    main()
