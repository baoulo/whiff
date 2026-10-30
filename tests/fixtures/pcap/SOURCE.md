# Fixtures for `pcap` (pcap packet capture)

Files made for whiff's tests, CC0-1.0, for a fictitious harbour (Saltmere Harbour, documentation IP ranges). Regenerate with `scripts/fixtures/forensic.sh`.

| File | Origin | Licence |
|---|---|---|
| `saltmere-harbour.pcap` | text2pcap -F pcap: DNS, HTTP, TLS, ARP and IPv6 mDNS frames | CC0-1.0 |
| `saltmere-harbour-ns.pcap` | editcap -F nsecpcap: the same with nanosecond times | CC0-1.0 |
