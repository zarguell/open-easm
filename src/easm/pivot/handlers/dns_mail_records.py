import dns.resolver
from easm.pivot.handlers.base import PivotHandler


class DnsMailRecordsHandler(PivotHandler):
    pivot_type = "dns_mail_records"
    source_name = "dns_mail_records"

    async def execute(self, job: dict, pool) -> list[dict]:
        domain = job["entity_value"]
        result: dict = {"domain": domain}

        # MX records
        mx_records = []
        try:
            answers = dns.resolver.resolve(domain, "MX")
            for rdata in answers:
                mx_records.append({
                    "preference": rdata.preference,
                    "exchange": str(rdata.exchange).rstrip("."),
                })
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
            pass
        result["mx_records"] = mx_records

        # SPF record (from TXT)
        try:
            answers = dns.resolver.resolve(domain, "TXT")
            for rdata in answers:
                txt = b" ".join(rdata.strings).decode(errors="replace")
                if txt.startswith("v=spf1"):
                    result["spf_record"] = txt
                    break
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
            pass

        # DMARC record
        try:
            answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
            for rdata in answers:
                txt = b" ".join(rdata.strings).decode(errors="replace")
                if txt.startswith("v=DMARC1"):
                    result["dmarc_record"] = txt
                    break
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
            pass

        return [result]
