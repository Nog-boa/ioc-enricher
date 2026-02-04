"""Command-line interface for ioc_enricher."""

from __future__ import annotations

import argparse
from pathlib import Path

from .enrichers.pipeline import enrich_records
from .output.csv_writer import write_records
from .parsing.pipeline import parse_input


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ioc_enricher",
        description="IOC enrichment tool (VirusTotal)",
    )
    parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Path to input CSV or TXT containing IOCs",
    )
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Path to output CSV",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    records = parse_input(args.input)
    records = enrich_records(records)
    write_records(args.output, records)
    print(f"Wrote {len(records)} rows to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
