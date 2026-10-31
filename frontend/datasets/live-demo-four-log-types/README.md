# Four-file live demo dataset

This compact, fully synthetic incident story is intended for a live walkthrough. It follows a suspected account compromise across five dates, **2026-10-17 to 2026-10-21 (UTC)**. The same test IP appears across host, web, application, and firewall records so the unified timeline can connect activity across sources.

| File | Type | Records |
|---|---|---:|
| `host-auth.log` | Linux authentication | 10 |
| `web-access.log` | Apache/Nginx access | 10 |
| `application-events.jsonl` | Application JSON Lines | 10 |
| `firewall-network.log` | Firewall/network syslog | 10 |
| **Total** | 4 separate formats | **40** |

## Load into Tracepoint

1. Open **Add log files** and select all four files in this folder.
2. Set format to **Detect format** and timezone to **UTC**.
3. Check **Start a new case (replace the selected synthetic scenario)**.
4. Click **Analyze logs**.
5. Show the unified 40-event timeline. Search for `203.0.113.77`, then point out repeated auth failures, successful access, privileged activity, web export, application warnings, and firewall decisions.

All IP addresses are from documentation-only ranges. This is synthetic data, not a real incident or a labeled benchmark.
