"""Build the supplied attack entry point without importing or running it."""
from __future__ import annotations

import argparse
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def assignment(tree: ast.Module, name: str) -> ast.Assign:
    matches = [node for node in tree.body if isinstance(node, ast.Assign)
               and any(isinstance(target, ast.Name) and target.id == name
                       for target in node.targets)]
    if len(matches) != 1:
        raise ValueError(f"Expected exactly one assignment to {name}")
    return matches[0]


def build_source(root: Path = ROOT) -> str:
    template = (root / "submission/attack_template.py").read_text(encoding="utf-8")
    tree = ast.parse(template)
    order = ast.literal_eval(assignment(tree, "SOURCE_MODULE_ORDER").value)
    # Preserve the historical dictionary insertion order for byte-for-byte builds.
    import json
    manifest = json.loads((root / "reference/provenance.json").read_text(encoding="utf-8"))
    names = list(manifest["modules"])
    if len(set(order)) != len(order) or set(names) != set(order):
        raise ValueError("Module manifest and import order do not agree")
    modules = {}
    for name in names:
        if not name.startswith("src.attacks.") or not all(part.isidentifier() for part in name.split(".")):
            raise ValueError(f"Unexpected module name: {name}")
        source = (root / (name.replace(".", "/") + ".py")).read_text(encoding="utf-8")
        ast.parse(source, filename=name)
        modules[name] = source
    node = assignment(tree, "MODULE_SOURCES")
    lines = template.splitlines(keepends=True)
    lines[node.lineno - 1:node.end_lineno] = [f"MODULE_SOURCES = {modules!r}\n"]
    source = "".join(lines)
    ast.parse(source, filename="attack.py")
    return source


def build(output: Path, root: Path = ROOT) -> Path:
    source = build_source(root)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(source, encoding="utf-8", newline="\n")
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "dist/attack.py")
    args = parser.parse_args()
    output = build(args.output)
    print(f"Built {output.name!a} ({output.stat().st_size:,} bytes); no model execution")


if __name__ == "__main__":
    main()
