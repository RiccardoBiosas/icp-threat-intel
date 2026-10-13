"""Entry point for ``make run``. The APScheduler jobs arrive in a later task (T16)."""

import sys


def main() -> int:
    print("scheduler: not implemented", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
