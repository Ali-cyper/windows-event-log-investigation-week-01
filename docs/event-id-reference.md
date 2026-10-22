# Windows Event ID Reference — Week 01

This reference includes the core events in the Week 01 training plan plus logoff events present in the supplied data.

| Event ID | Meaning | Useful fields / questions | Common analytical mistake |
|---|---|---|---|
| `4624` | Successful logon | Which account? Which computer received the logon? Source IP / workstation? Logon Type? Authentication package? Time? | Assuming every successful logon is benign or malicious without context. |
| `4625` | Failed logon | Account, target computer, source IP, workstation, Logon Type, Status, SubStatus, repeated pattern, subsequent success. | Treating one failure as proof of brute force; ignoring the surrounding baseline. |
| `4672` | Special privileges assigned to a new logon | Account, Logon ID (in native event data), privilege list, whether the account is expected to have these privileges. | Treating the event alone as proof of compromise. SYSTEM and expected administrators can legitimately generate it. |
| `4688` | New process created | Subject user, process path, parent path, command line, time, target logon context / IDs when available. | Judging by executable name alone; a legitimate binary can be used suspiciously, and command-line telemetry may be disabled. |
| `4634` | Account logoff / session terminated | Account, Logon ID, computer, time; correlate on the same computer. | Assuming every session has a clean logoff event or correlating IDs across different machines. |
| `4647` | User initiated logoff | User, computer, Logon ID where present, and related `4634`. | Treating `4647` and `4634` as identical; one records initiation, the other session termination. |

## Logon Type quick reference

| Logon Type | Label | Practical meaning |
|---:|---|---|
| `2` | Interactive | A user logged on interactively to the computer. |
| `3` | Network | A user or computer accessed the computer over the network. This alone does not identify the exact application or protocol. |
| `10` | RemoteInteractive | A user logged on remotely using Terminal Services / Remote Desktop. Validate the actual access path with supporting telemetry. |

## Status and SubStatus in the primary dataset

- `0xC000006D` — generic logon failure status.
- `0xC000006A` — incorrect password substatus.
- `0x0` — success status in the simplified dataset.

Read Status and SubStatus together. Do not use the `Keywords` text in the primary CSV as the main success/failure decision field because that column is inconsistent for some `4625` rows.

## Correlation reminders

1. A native Windows event can include a `Logon ID` / `SubjectLogonId`. When present, it is often valuable for linking a successful logon, privilege assignment, process creation, and logoff on the same computer.
2. The main CSV intentionally uses a simplified cross-event schema and has no Logon ID column. Its case timeline is therefore based on time, source, account, target host, and sequence — not proven session identity.
3. Event `4672` means sensitive privileges were assigned, not that the account is automatically compromised.
4. Event `4688` may not contain a command line unless the relevant process-creation command-line auditing policy is enabled.

## Official documentation

- [Microsoft Learn — Event 4624](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)
- [Microsoft Learn — Event 4625](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625)
- [Microsoft Learn — Event 4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)
- [Microsoft Learn — Event 4688](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688)
- [Microsoft Learn — Audit Logoff (4634, 4647)](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-logoff)
