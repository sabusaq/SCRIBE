# Drop IOC lists here (one indicator per line). Lines starting with # are ignored.
# Types: MD5/SHA1/SHA256 hashes, IP addresses, domains, filenames, or any string.
#
# Indicators are typed at load: hashes/IPs/domains match on word boundaries and are
# reported as high confidence; everything else is a substring match reported as low
# confidence. The sweep runs across every parsed CSV (Amcache SHA1 column, MFT/UsnJrnl
# filenames/paths, event-log details, etc.) and records the time of each hit.
#
# Indicators shorter than 5 characters are dropped (and reported) - too generic.
# An EMPTY IOC set is fine - Sigma detection still runs.
#
# Example (delete these):
# 44d88612fea8a8f36de82e1278abb02f
# evil.exe
# 203.0.113.10
# malicious-domain.example
