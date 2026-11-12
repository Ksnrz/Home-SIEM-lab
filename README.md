# Home SIEM Lab

Testing what a default Wazuh install detects on Windows.

<p>
  <img src="docs/sysmon-1.png" width="49%" alt="Sysmon Event 1 showing a base64-encoded PowerShell command">
  <img src="docs/4104.png" width="49%" alt="PowerShell Event 4104 showing the decoded script">
</p>

The same command seen in two logs. Sysmon Event 1 (left) records only the encoded command line.
PowerShell Event 4104 (right) records the script after decoding.

This lab runs MITRE ATT&CK techniques against a Windows 11 VM and records which ones the default
Wazuh ruleset detects, which ones it logs without alerting, and which ones it misses.

Work in progress. v1 (3 techniques) is scheduled for Nov 22, 2026.

## Skills demonstrated

| Skill | Evidence |
|---|---|
| SIEM deployment and configuration | Wazuh server, Windows agent, log channel config: [config](config/) |
| Windows event logging | Sysmon 1, PowerShell 4104, Security 4625 and 4698 |
| MITRE ATT&CK mapping | [Detection results](#detection-results) |
| Adversary emulation | Atomic Red Team and Hydra: [write-ups](docs/techniques/) |
| Alert triage | Interpreting rule IDs and severity levels |
| Log pipeline troubleshooting | [Things I learned](#things-i-learned-along-the-way) |
| Technical documentation | This README and one write-up per technique |

## Detection results

A technique counts as **detected** when the default ruleset raises an alert at level 7 or higher.
Lower levels are stored but would not normally reach an analyst.

| Technique | ATT&CK | Event ID | Detected by default | Rule ID / level |
|---|---|---|---|---|
| PowerShell encoded command | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Sysmon 1, 4104 | Yes | 92057 / 12 |
| Scheduled task | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | `<...>` | `<...>` | `<...>` |
| Brute force (RDP) | [T1110](https://attack.mitre.org/techniques/T1110/) | 4625 | `<...>` | `<...>` |

Full write-ups with screenshots:
[T1059.001](docs/techniques/t1059-001-powershell-encoded.md),
[T1053.005](docs/techniques/t1053-005-scheduled-task.md),
[T1110](docs/techniques/t1110-brute-force.md)

## Things I learned along the way

**Encoded PowerShell is detected from the process tree, not the payload.**
Sysmon sees only base64, but rule 92057 (level 12) fires because PowerShell launched a child
PowerShell process with `-e`. Wazuh also mapped the alert to T1059.001 automatically.
A related rule for cmd execution (92032) fired at level 3.

**Script Block Logging needs a change on both sides.**
Enabling the policy makes Windows write Event 4104, but the Wazuh agent does not read the
`Microsoft-Windows-PowerShell/Operational` channel until it is added to `ossec.conf`.

**Threat Hunting shows alerts, not raw logs.**
Events that match no rule, or match one below level 3, are not stored in the alerts index.
An empty search result does not mean the agent failed to collect the event.

**Most 4104 events during a test come from the test framework.**
Atomic Red Team is itself a PowerShell module, so 4104 records its internal functions
(for example `Invoke-ExecuteCommand.ps1`) alongside the actual attack. Interactive console use
adds more noise, such as `prompt` and `$Host` blocks. Filtering by the `path` field separates
framework code from the payload.

**Tool installation is visible.**
Installing Atomic Red Team triggered rules 91816 and 91820 at level 4: recorded, but below
the alert threshold.

## Lab setup

![Lab architecture](docs/architecture.png)

| Machine | Role | IP |
|---|---|---|
| Ubuntu `<version>` | Wazuh `<version>` all-in-one | 192.168.95.130 |
| Windows 11 (`win-lab`) | Target with Sysmon and the Wazuh agent | 192.168.95.131 |
| Kali Linux | Attacker for brute force | `<IP>` |

All machines run in VMware Workstation on an isolated network.

Changes from the default configuration:

- Sysmon installed with `<config name + link>`
- Sysmon and PowerShell/Operational channels added to the agent: [`config/agent-localfile.xml`](config/agent-localfile.xml)
- Script Block Logging enabled through the registry: [`config/enable-logging.ps1`](config/enable-logging.ps1)
- `Other Object Access Events` audit policy enabled to log scheduled task creation (4698)

## Roadmap

- [x] T1059.001 PowerShell encoded command
- [ ] T1053.005 Scheduled task
- [ ] T1110 Brute force from Kali
- [ ] T1136.001 Local account creation and T1070.001 Event log clearing
- [ ] Custom Wazuh rule for a detection gap, with before/after testing
- [ ] 2 to 3 Sigma rules tested against lab logs
- [ ] Incident report

## Tools

[Wazuh](https://wazuh.com), [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon),
[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team), Kali Linux, Hydra, VMware Workstation

## License

MIT. See [LICENSE](LICENSE).
