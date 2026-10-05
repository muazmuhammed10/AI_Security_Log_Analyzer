import re


def extract_iocs(content: str):

    ips = set()
    domains = set()
    urls = set()
    hashes = set()

    # --------------------------------------------------
    # IPv4 Addresses
    # --------------------------------------------------

    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    for ip in re.findall(ip_pattern, content):
        ips.add(ip)

    # --------------------------------------------------
    # URLs
    # --------------------------------------------------

    url_pattern = r"https?://[^\s\"'<>]+"

    for url in re.findall(url_pattern, content):
        # Remove common punctuation at the end
        url = url.rstrip(".,;:!?)]}")

        urls.add(url)

    # --------------------------------------------------
    # Domains
    # --------------------------------------------------

    domain_pattern = (
        r"\b(?:[a-zA-Z0-9-]+\.)+"
        r"(?:com|net|org|edu|gov|io|co|info|biz|xyz|online|site|app|dev)\b"
    )

    for domain in re.findall(domain_pattern, content):

        domains.add(
            domain.lower()
        )

    # --------------------------------------------------
    # MD5
    # 32 hexadecimal characters
    # --------------------------------------------------

    md5_pattern = r"\b[a-fA-F0-9]{32}\b"

    for hash_value in re.findall(
        md5_pattern,
        content
    ):

        hashes.add(hash_value.lower())

    # --------------------------------------------------
    # SHA-1
    # 40 hexadecimal characters
    # --------------------------------------------------

    sha1_pattern = r"\b[a-fA-F0-9]{40}\b"

    for hash_value in re.findall(
        sha1_pattern,
        content
    ):

        hashes.add(hash_value.lower())

    # --------------------------------------------------
    # SHA-256
    # 64 hexadecimal characters
    # --------------------------------------------------

    sha256_pattern = r"\b[a-fA-F0-9]{64}\b"

    for hash_value in re.findall(
        sha256_pattern,
        content
    ):

        hashes.add(hash_value.lower())

    # --------------------------------------------------
    # Remove IP addresses from domains
    # --------------------------------------------------

    domains = {
        domain
        for domain in domains
        if not re.fullmatch(
            ip_pattern,
            domain
        )
    }

    # --------------------------------------------------
    # Return IOC results
    # --------------------------------------------------

    return {
        "ip_addresses": sorted(ips),
        "domains": sorted(domains),
        "urls": sorted(urls),
        "hashes": sorted(hashes)
    }