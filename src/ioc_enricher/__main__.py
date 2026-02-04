"""Module entrypoint to support `python -m ioc_enricher`."""

from .cli import main


if __name__ == "__main__":
    raise SystemExit(main())