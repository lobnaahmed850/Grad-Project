import json
import re
import sys
from datetime import datetime, timezone
from statistics import mean


LOADTEST_PATTERN = re.compile(
    r"LOADTEST\s+seq=(\d+)\s+sent_ns=(\d+)\s+source=linux"
)


def percentile(values, p):
    if not values:
        return None

    values = sorted(values)

    index = (len(values) - 1) * p / 100

    lower = int(index)
    upper = min(lower + 1, len(values) - 1)

    if lower == upper:
        return values[lower]

    fraction = index - lower

    return (
        values[lower]
        + (values[upper] - values[lower]) * fraction
    )


def iso_to_ns(value):
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return int(dt.timestamp() * 1_000_000_000)


def analyze(raw_file, expected):

    received = 0
    sequences = set()
    latencies = []
    receive_times = []

    with open(raw_file, "r", encoding="utf-8") as f:

        for line in f:

            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            payload = record.get("raw_payload", "")
            match = LOADTEST_PATTERN.search(payload)

            if not match:
                continue

            seq = int(match.group(1))
            sent_ns = int(match.group(2))

            received += 1
            sequences.add(seq)

            received_at = record.get("received_at")

            if received_at:

                try:
                    received_ns = iso_to_ns(received_at)

                    latency_ms = (
                        received_ns - sent_ns
                    ) / 1_000_000

                    latencies.append(latency_ms)

                    receive_times.append(received_ns)

                except Exception:
                    pass

    lost = expected - received

    loss_percentage = (
        (lost / expected) * 100
        if expected > 0
        else 0
    )

    print()
    print("=" * 70)
    print("AI NET - LINUX LOAD TEST RESULTS")
    print("=" * 70)

    print(f"Expected events       : {expected}")
    print(f"Received events       : {received}")
    print(f"Lost events           : {lost}")
    print(f"Loss percentage       : {loss_percentage:.6f}%")

    if receive_times:

        duration = (
            max(receive_times) - min(receive_times)
        ) / 1_000_000_000

        if duration > 0:

            actual_eps = received / duration

            print(f"Measured receive EPS  : {actual_eps:.2f}")

    if latencies:

        print()
        print("Latency")
        print("-" * 70)

        print(f"Samples               : {len(latencies)}")
        print(f"Minimum               : {min(latencies):.3f} ms")
        print(f"Average               : {mean(latencies):.3f} ms")
        print(f"P50                   : {percentile(latencies, 50):.3f} ms")
        print(f"P95                   : {percentile(latencies, 95):.3f} ms")
        print(f"P99                   : {percentile(latencies, 99):.3f} ms")
        print(f"Maximum               : {max(latencies):.3f} ms")

        negative = sum(
            1 for x in latencies if x < 0
        )

        print(f"Negative latency      : {negative}")

    missing = []

    if expected <= 2_000_000:

        for seq in range(1, expected + 1):

            if seq not in sequences:
                missing.append(seq)

    print()

    if missing:

        print(f"Missing sequence IDs  : {len(missing)}")

        if len(missing) <= 50:
            print(missing)

    else:

        print("Missing sequence IDs  : 0")

    print("=" * 70)


if __name__ == "__main__":

    if len(sys.argv) != 3:

        print(
            "Usage: python analyze_linux_loadtest.py "
            "<raw_logs.json> <expected_events>"
        )

        sys.exit(1)

    raw_file = sys.argv[1]
    expected = int(sys.argv[2])

    analyze(raw_file, expected)