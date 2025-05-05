import os
import json
from collections import defaultdict

def aggregate_json_stats(base_folder):
    result = {}

    for app_name in os.listdir(base_folder):
        app_path = os.path.join(base_folder, app_name)
        if not os.path.isdir(app_path):
            continue

        totals = defaultdict(int)

        for root, _, files in os.walk(app_path):
            for file in files:
                if not file.endswith(".json") or "streams" in file:
                    continue

                json_path = os.path.join(root, file)
                try:
                    with open(json_path, "r") as f:
                        data = json.load(f)

                    for key in [
                        "Stage 1 Filtered Streams Count",
                        "Stage 2 Filtered Streams Count",
                        "Stage 1 Filtered Packets Count",
                        "Stage 2 Filtered Packets Count",
                    ]:
                        if key in data:
                            for proto, count in data[key].items():
                                totals[f"{key} - {proto}"] += count
                except Exception as e:
                    print(f"Error reading {json_path}: {e}")

        result[app_name] = totals

    # Print result
    for app, counts in result.items():
        print(f"=== {app} ===")
        print(f"Stage 1 Filtered Streams Count: TCP={counts['Stage 1 Filtered Streams Count - TCP']}, UDP={counts['Stage 1 Filtered Streams Count - UDP']}")
        print(f"Stage 2 Filtered Streams Count: TCP={counts['Stage 2 Filtered Streams Count - TCP']}, UDP={counts['Stage 2 Filtered Streams Count - UDP']}")
        print(f"Stage 1 Filtered Packets Count: TCP={counts['Stage 1 Filtered Packets Count - TCP']}, UDP={counts['Stage 1 Filtered Packets Count - UDP']}")
        print(f"Stage 2 Filtered Packets Count: TCP={counts['Stage 2 Filtered Packets Count - TCP']}, UDP={counts['Stage 2 Filtered Packets Count - UDP']}")
        print()

if __name__ == "__main__":
    aggregate_json_stats("/data_sdb/metrics")
