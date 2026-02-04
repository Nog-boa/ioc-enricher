from __future__ import annotations

import csv
from pathlib import Path


def _looks_like_header(row: list[str]) -> bool:
    lowered = [cell.strip().lower() for cell in row]
    return any(cell in {"ioc", "indicator", "value"} for cell in lowered)


def _select_column(row: list[str]) -> int:
    lowered = [cell.strip().lower() for cell in row]
    for idx, cell in enumerate(lowered):
        if cell in {"ioc", "indicator", "value"}:
            return idx
    return 0


def iter_ioc_strings(path: Path) -> list[str]:
    suffix = path.suffix.lower()
    if suffix == ".txt":
        return _read_txt(path)
    return _read_csv(path)


def _read_txt(path: Path) -> list[str]:
    items: list[str] = []
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            items.append(line.strip())
    return items


def _read_csv(path: Path) -> list[str]:
    items: list[str] = []
    with path.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
        reader = csv.reader(handle)
        column_index: int | None = None
        for row_index, row in enumerate(reader):
            if not row:
                items.append("")
                continue
            if row_index == 0 and _looks_like_header(row):
                column_index = _select_column(row)
                continue
            if column_index is None:
                column_index = 0
            if column_index >= len(row):
                items.append("")
            else:
                items.append(row[column_index])
    return items
