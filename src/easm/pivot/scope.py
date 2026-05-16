from easm.models import ScopeResult


class ScopeEvaluator:
    def evaluate(self, target, entity_type: str, entity_value: str) -> ScopeResult:
        if entity_type == "domain":
            for suffix in target.match_rules.domains:
                if entity_value.endswith("." + suffix) or entity_value == suffix:
                    return ScopeResult.IN_SCOPE
            return ScopeResult.OUT_OF_SCOPE
        if entity_type == "asn":
            from easm.entity_store import normalize_entity_value
            normalized = normalize_entity_value("asn", entity_value)
            configured = [normalize_entity_value("asn", a) for a in target.match_rules.asns]
            return ScopeResult.IN_SCOPE if normalized in configured else ScopeResult.OUT_OF_SCOPE
        if entity_type in ("ip", "ip_range"):
            import ipaddress
            try:
                parsed = ipaddress.ip_network(entity_value, strict=False)
                for cidr_str in (target.match_rules.ip_ranges or []):
                    if parsed.subnet_of(ipaddress.ip_network(cidr_str, strict=False)):
                        return ScopeResult.IN_SCOPE
                return ScopeResult.OUT_OF_SCOPE
            except ValueError:
                return ScopeResult.UNKNOWN
        if entity_type == "hostname":
            for suffix in target.match_rules.domains:
                if entity_value.endswith("." + suffix) or entity_value == suffix:
                    return ScopeResult.IN_SCOPE
            return ScopeResult.OUT_OF_SCOPE
        return ScopeResult.UNKNOWN
