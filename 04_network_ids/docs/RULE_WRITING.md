# Rule Writing Guide for NIDS
# ============================================================

## Introduction

This guide covers best practices for writing effective Suricata and Snort rules for the NIDS platform.

## Rule Structure

### Basic Rule Format
```
action protocol src_ip src_port -> dst_ip dst_port (options)
```

### Actions
| Action | Description |
|--------|-------------|
| `alert` | Generate alert, continue inspection |
| `drop` | Drop packet, generate alert (IPS mode) |
| `reject` | Drop packet, send TCP RST/ICMP unreachable |
| `rejectsrc` | Drop, send TCP RST to source |
| `rejectdst` | Drop, send ICMP unreachable to destination |
| `pass` | Allow packet, stop inspection |
| `sdrop` | Silently drop, no alert |

### Protocols
- `tcp`, `udp`, `icmp`, `ip`
- Application layer: `http`, `dns`, `tls`, `ssh`, `ftp`, `smb`, `dcerpc`, etc.

## Rule Options

### Metadata Options
```
msg:"Description of the alert";          # Human-readable description
reference:url,https://example.com;       # Reference URL
reference:cve,2021-44228;                # CVE reference
classtype:web-application-attack;        # Classification type
priority:1;                              # Priority (1=high, 2=medium, 3=low)
metadata:created_at 2024-01-15;          # Creation date
metadata:updated_at 2024-06-15;          # Last update
sid:1000001;                             # Signature ID (unique)
rev:2;                                   # Revision number
```

### Payload Matching
```
content:"malicious string";              # Case-sensitive content match
content:"malicious string"; nocase;      # Case-insensitive
content:"|00 01 02 03|";                 # Binary content (hex)
content:"GET"; http_method;              # HTTP method
content:"POST"; http_method;             # HTTP POST
content:"example.com"; http_host;        # HTTP Host header
content:"/admin"; http_uri;              # HTTP URI
content:"Mozilla"; http_user_agent;      # User-Agent
content:"sessionid"; http_cookie;        # Cookie
content:"malicious"; http_header;        # Any HTTP header
content:"malicious"; http_raw_header;    # Raw HTTP header
content:"malicious"; http_raw_uri;       # Raw URI
content:"malicious"; http_stat_code;     # HTTP status code
content:"malicious"; http_stat_msg;      # HTTP status message
content:"malicious"; http_raw_request;   # Raw request
content:"malicious"; http_raw_response;  # Raw response
```

### Content Modifiers
```
nocase;                    # Case-insensitive
depth:10;                  # Max bytes from start
offset:20;                 # Bytes to skip from start
distance:10;               # Bytes from previous match
within:50;                 # Max bytes from previous match
fast_pattern;              # Use as fast pattern matcher
fast_pattern:only;         # Only use as fast pattern
relative;                  # Relative to previous match
```

### PCRE (Perl Compatible Regular Expressions)
```
pcre:"/pattern/flags";
pcre:"/pattern/i";         # Case-insensitive
pcre:"/pattern/s";         # Dot matches newline
pcre:"/pattern/m";         # Multi-line
pcre:"/pattern/x";         # Extended (ignore whitespace)
pcre:"/pattern/A";         # Anchored at start
pcre:"/pattern/E";         # Anchored at end
pcre:"/pattern/U";         # Ungreedy
pcre:"/pattern/X";         # Extra (PCRE_EXTRA)
```

### HTTP-Specific Keywords
```
http_method;               # Match HTTP method
http_uri;                  # Match URI
http_header;               # Match any header
http_header_name;          # Match header name
http_header_value;         # Match header value
http_cookie;               # Match cookie
http_client_body;          # Request body
http_server_body;          # Response body
http_raw_header;           # Raw headers
http_raw_uri;              # Raw URI
http_raw_request;          # Raw request
http_raw_response;         # Raw response
http_stat_code;            # Status code
http_stat_msg;             # Status message
http_method;               # Method (GET, POST, etc.)
http_version;              # HTTP version
```

### DNS Keywords
```
dns.query;                 # Query name
dns.query.type;            # Query type (A, AAAA, MX, TXT, etc.)
dns.query.class;           # Query class
dns.answer;                # Answer section
dns.authority;             # Authority section
dns.additional;            # Additional section
dns.rrtype;                # Resource record type
dns.rclass;                # Resource record class
dns.ttl;                   # Time to live
dns.opcode;                # Opcode (QUERY, IQUERY, STATUS)
dns.rcode;                 # Response code (NOERROR, NXDOMAIN, etc.)
dns.aa;                    # Authoritative answer
dns.tc;                    # Truncated
dns.rd;                    # Recursion desired
dns.ra;                    # Recursion available
dns.ad;                    # Authenticated data
dns.cd;                    | Checking disabled
dns.query_length;          # Query name length
```

### TLS/SSL Keywords
```
tls.version;               # TLS version
tls.cipher;                # Cipher suite
tls.sni;                   # Server Name Indication
tls.fingerprint;           # Certificate fingerprint
tls.subject;               # Certificate subject
tls.issuer;                # Certificate issuer
tls.serial;                # Serial number
tls.notbefore;             # Not before date
tls.notafter;              # Not after date
tls.key_usage;             # Key usage
tls.extended_key_usage;    # Extended key usage
tls.ja3;                   # JA3 fingerprint
tls.ja3s;                  # JA3S fingerprint
```

### Flow Keywords
```
flow:to_server;            # Client to server
flow:to_client;            # Server to client
flow:from_server;          # Server to client (alias)
flow:from_client;          # Client to server (alias)
flow:established;          # Established connection
flow:not_established;      # Not established
flow:stateless;            # Stateless
flow:only_stream;          # Only reassembled stream
flow:no_stream;            # Don't reassemble
flow:to_server,established; # Client->Server, established
flow:to_client,established; # Server->Client, established
```

### Thresholding
```
threshold:type threshold, track by_src|by_dst|by_rule|by_both, count N, seconds T
threshold:type threshold, track by_src, count 10, seconds 60;
threshold:type both, track by_src, count 5, seconds 60;
threshold:type limit, track by_src, count 100, seconds 60;
```

Threshold types:
- `threshold`: Alert every N occurrences
- `limit`: Alert at most N times per period
- `both`: Alert every N, but limit to 1 alert per period
- `suppression`: Suppress alerts entirely

Tracking:
- `by_src`: Track by source IP
- `by_dst`: Track by destination IP
- `by_rule`: Track by rule (SID)
- `by_both`: Track by source and destination IP pair

### Byte Test / Byte Jump
```
byte_test:4,>,1000,0,relative;  # 4 bytes, > 1000, offset 0, relative
byte_test:2,=,0x1234,4;         # 2 bytes, equals 0x1234, offset 4
byte_jump:4,4,relative;         # Jump 4 bytes at offset 4, relative
```

### IP Reputation
```
reputation:bad;                  # Bad reputation
reputation:malware;              # Malware
reputation:botnet;               # Botnet
reputation:tor;                  # Tor
reputation:proxy;                # Proxy
reputation:vpn;                  # VPN
```

## Rule Writing Best Practices

### 1. Use Specific Content Matches First
```
# Good: Specific content first
alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (
    msg:"WEB-APP SQL Injection";
    flow:to_server,established;
    content:"union"; nocase;
    content:"select"; nocase; distance:0; within:50;
    pcre:"/union\s+.*select/i";
    sid:1000001; rev:1;
)

# Bad: PCRE first (slow)
alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (
    msg:"WEB-APP SQL Injection";
    flow:to_server,established;
    pcre:"/union\s+.*select/i";
    sid:1000001; rev:1;
)
```

### 2. Use Fast Pattern
```
# Good: Fast pattern on rare content
alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (
    msg:"WEB-APP Specific Attack";
    flow:to_server,established;
    content:"very_rare_string"; fast_pattern; nocase;
    content:"common_string"; nocase;
    sid:1000001; rev:1;
)
```

### 3. Optimize PCRE
```
# Good: Anchor and be specific
pcre:"/^GET\s+\/admin\/delete\s+HTTP/i";

# Bad: Unanchored, greedy
pcre:"/admin.*delete/i";
```

### 4. Use Flow Correctly
```
# Server-side attack
flow:to_server,established;

# Client-side attack
flow:to_client,established;

# Both directions
flow:established;
```

### 5. Use Flowbits for State Tracking
```
# Set flowbit on first packet
alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (
    msg:"WEB-APP Login Page Accessed";
    flow:to_server,established;
    content:"/login"; http_uri;
    flowbits:set,login_page_accessed;
    sid:1000001; rev:1;
)

# Check flowbit on subsequent packet
alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (
    msg:"WEB-APP Brute Force Login Attempt";
    flow:to_server,established;
    content:"/login"; http_uri;
    flowbits:isset,login_page_accessed;
    threshold: type both, track by_src, count 10, seconds 300;
    sid:1000002; rev:1;
)
```

### 6. Use Dataset for Large Lists
```
# datasets/rules/ssl_ports: 443,8443,9443,993,995
# datasets/rules/malware_domains: evil.com,badsite.com

# In rule:
alert tls any any -> $HOME_NET any (
    tls.sni; dataset:malware_domains;
    sid:1000001; rev:1;
)
```

## Rule Testing

### 1. Syntax Check
```bash
suricata -T -c /etc/suricata/suricata.yaml -v
snort -T -c /etc/snort/snort.conf
```

### 2. Test with PCAP
```bash
suricata -c /etc/suricata/suricata.yaml -r test.pcap -l /tmp/test_output
snort -c /etc/snort/snort.conf -r test.pcap -l /tmp/test_output -A fast
```

### 3. Performance Profiling
```bash
suricata -c /etc/suricata/suricata.yaml -r test.pcap \
  --set profiling.rules.enabled=yes \
  --set profiling.keywords.enabled=yes
```

## Rule Testing Checklist

- [ ] Syntax validation passes (`suricata -T`)
- [ ] Rule triggers on positive test case
- [ ] Rule does NOT trigger on negative test case
- [ ] Rule has appropriate threshold
- [ ] Rule has appropriate severity/classtype
- [ ] Rule has unique SID
- [ ] Rule has meaningful msg and reference
- [ ] Rule tested with PCAP
- [ ] Performance impact acceptable
- [ ] Rule documented

## Rule Categories & SID Ranges

| Category | SID Range | Description |
|----------|-----------|-------------|
| Reserved | 1-999999 | System/Standard rules |
| Local/Custom | 1000000-1999999 | Organization-specific |
| Vendor | 2000000-2999999 | Vendor-specific |
| Community | 3000000-3999999 | Community contributed |

## Classification Types (classtype)

| Class Type | Description | Priority |
|------------|-------------|----------|
| attempted-admin | Attempted admin privilege gain | High |
| attempted-user | Attempted user privilege gain | High |
| inappropriate-content | Inappropriate content | Medium |
| policy-violation | Policy violation | Medium |
| shellcode-detect | Shellcode detected | High |
| successful-admin | Successful admin access | Critical |
| successful-user | Successful user access | High |
| trojan-activity | Trojan activity | Critical |
| unsuccessful-user | Failed user access | Medium |
| web-application-attack | Web application attack | High |
| web-application-activity | Web application activity | Low |

## Rule Lifecycle

1. **Development**: Write rule, test locally
2. **Testing**: Validate with PCAPs, check false positives
3. **Staging**: Deploy to staging sensor
- Monitor for 24-48 hours
- Check false positive rate
- [ ] Performance impact < 1%
- [ ] No crashes or memory leaks
- [ ] Alerts actionable

3. **Production**: Deploy to production sensors
4. **Monitoring**: Track alert volume, false positives
4. **Maintenance**: Regular review, update, retire

## SID Management

### SID Allocation
| Range | Purpose |
|-------|---------|
| 1000000-1009999 | Web Application Attacks |
| 1001000-1001999 | Authentication Attacks |
| 1002000-1001999 | Malware/C2 |
| 1003000-1003999 | Reconnaissance |
| 1004000-1004999 | Exploits |
| 1005000-1005999 | Data Exfiltration |
| 1006000-1006999 | Policy Violations |
| 1007000-1007999 | ICS/OT Specific |

### SID Tracking
- Maintain SID registry (spreadsheet/database)
- Include: SID, description, author, date, status
- Track revisions
- Deprecate unused rules

## Performance Considerations

### Rule Ordering
1. Most specific rules first
2. Most frequent matches first
3. Expensive keywords (PCRE, byte_test) last

### Keyword Cost (Approximate)
| Keyword | Relative Cost |
|---------|---------------|
| content | 1x |
| pcre | 10-100x |
| byte_test | 5x |
| byte_jump | 5x |
| pcre (complex) | 100x+ |
| lua | Variable |

## Rule Documentation Template

```markdown
# Rule SID: 1000001
# Title: WEB-APP SQL Injection Union Select
# Author: Security Team
# Date: 2024-01-15
# Revision: 2
# Status: Active

## Description
Detects SQL injection attempts using UNION SELECT technique in HTTP parameters.

## Detection Logic
- Matches "union" followed by "select" within 50 bytes
- Case-insensitive
- HTTP POST/GET parameters

## Test Cases
- Positive: `GET /?id=1 union select 1,2,3`
- Negative: `GET /?id=1 union all select 1` (no "select" after union)

## False Positives
- Legitimate SQL documentation pages
- SQL tutorial content

## Mitigation
- Input validation
- Parameterized queries
- WAF rules

## References
- CWE-89: SQL Injection
- OWASP Top 10: A03:2021
- https://owasp.org/www-community/attacks/SQL_Injection

## MITRE ATT&CK
- T1190: Exploit Public-Facing Application
```

## Rule Review Checklist

- [ ] Unique SID
- [ ] Descriptive msg
- [ ] Appropriate classtype
- [ ] Appropriate priority
- [ ] At least one reference
- [ ] Fast pattern used
- [ ] Content matches optimized
- [ ] PCRE anchored and specific
- [ ] Threshold appropriate
- [ ] Flow direction correct
- [ ] Tested with positive case
- [ ] Tested with negative case
- [ ] False positive rate < 0.1%
- [ ] Performance impact < 1%
- [ ] Documentation complete
- [ ] SID registered in registry
- [ ] Code reviewed by peer

---

*Guide Version: 1.0 | Last Updated: 2024*