# Synthetic five-day incident dataset — 12,500 events

Generated for the IT2PL hackathon prototype. All addresses use documentation-only TEST-NET ranges. Usernames, hosts, request IDs, and activity are synthetic.

## Date range and counts

Events cover five completed dates: **2026-10-17 through 2026-10-21 UTC**. The current project date is 2026-10-22.

| Dataset type | File | Records | Per day |
|---|---|---:|---:|
| Linux host authentication | `host-auth.log` | 2,500 | 500 |
| Apache/Nginx web access | `web-access.log` | 3,500 | 700 |
| Application JSON Lines | `application-events.jsonl` | 4,000 | 800 |
| Firewall/network syslog | `firewall-network.log` | 2,500 | 500 |
| **Total** | 4 files | **12,500** | **2,500** |

## Use in the prototype

Open Tracepoint, choose **Add log files**, select all four files in this folder, set format to **Detect format**, use **UTC** as the source timezone for host-auth timestamps, and check **Start a new case (replace the selected synthetic scenario)** so the bundled demo events are excluded. Click **Analyze logs**. The normalized timeline should contain exactly 12,500 events spanning the five dates. The event table shows 100 records per page; use Previous / Next to browse.

All events are generated, not collected from real systems. This dataset supports parser/performance demonstrations; it is not representative of real attack frequency or a labeled ground-truth benchmark.
