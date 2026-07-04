import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_PATH = PROJECT_ROOT / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

from insider_threat_detection.simulator import append_sample_events_csv, generate_sample_events_csv


def main() -> None:
    output_path = Path("data") / "network_events.csv"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.exists():
        append_sample_events_csv(output_path, user_count=6, events_per_user=80)
        print(f"Sample data appended to {output_path}")
    else:
        generate_sample_events_csv(output_path, user_count=6, events_per_user=80)
        print(f"Sample data written to {output_path}")


if __name__ == "__main__":
    main()
