"""DNS result-driven follow-up query rules."""


def followup_queries(records: list[dict[str, str]]) -> list[tuple[str, str]]:
    queries: set[tuple[str, str]] = set()
    for record in records:
        kind, value = record["type"], record["value"]
        if kind == "SOA":
            queries.update((record["name"], item) for item in ("NS", "A", "AAAA", "MX", "TXT", "SRV"))
        elif kind == "NS":
            queries.add((value, "A"))
            queries.add((value, "AAAA"))
        elif kind in {"A", "AAAA", "CNAME"}:
            queries.add((value, "PTR"))
    return sorted(queries)
