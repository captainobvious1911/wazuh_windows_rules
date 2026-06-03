# wazuh_windows_rules
Extended ruleset for detections and correlations on Windows events.

## Files

| File | What it Covers |

| `100-logon_events_windows.xml` | 4624/4625 by logon type, brute-force correlations |
| `101-ps_events_windows.xml` | PowerShell 4104: recon, credential access, evasion, persistence, lateral movement |
| `102-registry_integrity_windows.xml` | FIM registry persistence (Run keys, LSA, WDigest, IFEO, Winlogon, AppInit_DLLs) |
| `103-local_rules.xml` | Default rule deduplication, DCSync machine-account suppression, Kerberoasting, Golden Ticket |
| `104-ad_correlation_rules.xml` | Account/group management, DCSync, privilege escalation, GPO changes, offensive tooling |
| `105-additional_ad_detections.xml` | Kerberos pre-auth failures (4768/4771), OverPass-the-Hash |

## Attack coverage (or at least tried to) :)

Kerberoasting · DCSync · Golden Ticket · Pass-the-Hash · LSASS/SAM/NTDS dumping · AMSI bypass · Credential file search · Explicit credential logons · PSRemoting/WMI lateral movement · RDP brute force · Registry/WMI/scheduled task persistence · Defender tampering · Event log clearing · AD enumeration (PowerView patterns) · SPN enumeration · Recon burst correlation


## Important — read before deploying

**Load order:** Files are manually numbered 100–105 because I had problem with rules silently failing and have lost a lot of time on that section. Wazuh loads alphabetically and cross-file `<if_sid>` dependencies must resolve in order.

**scriptBlockText matching:** All PS rules use `type="pcre2"` with `(?i)`. Without this, Wazuh's default OS_Regex requires a full-field match and patterns never fire.

**Default rule deduplication:** `103-local_rules.xml` silences several default Wazuh rules (60106, 60122, 60141 etc.) to level 0 — they still route events to child rules but stop emitting duplicate alerts. Removing 103 causes double alerts.

## Looking for feedback on

- Are the brute-force thresholds (`frequency="5" timeframe="120"`) reasonable or too noisy in your environment?
- Any common PS attack patterns missing from the 4104 rules?
- False positive suppressions you've needed beyond NT SERVICE / IIS AppPool / Azure AD Connect service accounts?
- Do you see any rules that are overkill and could be handled by default rules without hassle of spanning to another custom child rule?
- Ideas for dashboards and visualisations in AD environment with Windows Servers (RDS, NPS, SQL, and other "Classic" services)
