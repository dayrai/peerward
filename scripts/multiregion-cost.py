#!/usr/bin/env python3
"""Calculate a transparent monthly cost interval without vendor price claims."""

import argparse
import json
import pathlib


def nonnegative(name: str, value: object) -> float:
    number = float(value)
    if number < 0:
        raise ValueError(f"{name} must be non-negative")
    return number


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("model", type=pathlib.Path)
    arguments = parser.parse_args()
    model = json.loads(arguments.model.read_text(encoding="utf-8"))
    peers = int(nonnegative("peer_count", model["peer_count"]))
    concurrent = nonnegative("concurrent_rate", model["concurrent_rate"])
    relay_low, relay_high = map(float, model["relay_traffic_ratio"])
    traffic_low, traffic_high = map(float, model["gib_per_active_peer_month"])
    price_low, price_high = map(float, model["egress_price_per_gib"])
    cross_rate = nonnegative("cross_region_rate", model["cross_region_rate"])
    cross_price = nonnegative("cross_region_price_per_gib", model["cross_region_price_per_gib"])
    fixed = sum(nonnegative("fixed_monthly_cost", value) for value in model["fixed_monthly_costs"].values())
    if concurrent > 1 or cross_rate > 1 or not (0 <= relay_low <= relay_high <= 1):
        raise ValueError("rates must be within [0,1] and intervals ordered")
    active = peers * concurrent
    relay_gib = [active * traffic_low * relay_low, active * traffic_high * relay_high]
    bandwidth_cost = [relay_gib[0] * price_low, relay_gib[1] * price_high]
    cross_cost = [relay_gib[0] * cross_rate * cross_price, relay_gib[1] * cross_rate * cross_price]
    output = {
        "model_version": 1,
        "currency": model["currency"],
        "inputs_are_operator_supplied": True,
        "active_peers": active,
        "relay_gib_month": relay_gib,
        "relay_bandwidth_cost_month": bandwidth_cost,
        "cross_region_cost_month": cross_cost,
        "fixed_cost_month": fixed,
        "total_cost_month": [fixed + bandwidth_cost[0] + cross_cost[0], fixed + bandwidth_cost[1] + cross_cost[1]],
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
