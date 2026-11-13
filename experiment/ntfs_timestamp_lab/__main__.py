from __future__ import annotations

import argparse
from pathlib import Path

from .build_dataset import build
from .report import write_reports


def main() -> None:
    parser = argparse.ArgumentParser(description="Synthetic NTFS timestamp lab")
    parser.add_argument("--output", default=None,
                        help="Output directory (default: .../lab/output)")
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    out = Path(args.output) if args.output else here / "output"
    build(out)
    write_reports(out)
    print(f"Artifacts and reports written to {out}")


if __name__ == "__main__":
    main()
