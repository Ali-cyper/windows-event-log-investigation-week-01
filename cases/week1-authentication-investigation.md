# Case Report — Repeated Logon Failures Followed by Privileged Access

## 1. Case metadata

| Field | Value |
|---|---|
| Case ID | WEL-W01-001 |
| Role | SOC L1 training case |
| Dataset | `data/week1_authentication_events_300.csv` |
| Dataset date | 26 August 2026 |
| Primary source | `10.10.50.23` |
| Source workstation | `FIN-01` |
| Primary host | `SRV-FILE-01` |
| Additional hosts | `SRV-APP-01`, `DC-01` |
| Classification | **Malicious activity indicated** (synthetic dataset) |
| Confidence | **High within the training scenario**; reduced for any real-world interpretation by dataset limitations |

## 2. Executive summary

The dataset shows a sustained sequence of failed remote-interactive logons from `10.10.50.23` / `FIN-01` to `SRV-FILE-01`, targeting four accounts. The failures are followed by a successful `Administrator` logon with Logon Type `10`, a special-privilege event, and process creation showing identity discovery, account discovery, local administrator-group inspection, network configuration discovery, and domain privileged-group discovery. The same source later has successful `Administrator` logons to `SRV-APP-01` and `DC-01`, with further special-privilege and PowerShell process events.

The sequence is consistent with multi-account credential guessing followed by privileged remote access and subsequent host/domain discovery. The data does not prove which passwords were tried, whether the exact method was password spraying or per-account password guessing, or the complete session linkage because the CSV lacks Logon ID.

## 3. Key evidence

### Authentication pattern

- From `13:35:14` to `13:46:39`, there are **40 failed logons (`4625`)** on `SRV-FILE-01` from `10.10.50.23`, workstation `FIN-01`, Logon Type `10`.
- The attempts target `Administrator`, `backup.admin`, `svc_backup`, and `helpdesk` — **10 failures per account** before the first observed successful logon.
- Failure status is `0xC000006D`, with substatus `0xC000006A` in these records, indicating an authentication failure consistent with an incorrect password.

### Successful and privileged access

- `13:47:34` — `4624`: `Administrator` successfully logs on to `SRV-FILE-01` with Logon Type `10`.
- `13:47:44` — `4672`: special privileges assigned to `Administrator` on `SRV-FILE-01`.
- `13:52:08` — `4624`: successful network logon as `Administrator` on `SRV-APP-01` from the same source.
- `13:52:16` — `4672`: special privileges on `SRV-APP-01`.
- `13:54:50` — `4624`: successful network logon as `Administrator` on `DC-01` from the same source.
- `13:54:58` — `4672`: special privileges on `DC-01`.

### Post-logon process activity

The `4688` records on `SRV-FILE-01` include:

| Time | Process / command | Interpretation |
|---|---|---|
| `13:48:01` | `cmd.exe /c whoami` | Identity discovery. |
| `13:48:19` | `cmd.exe /c net user` | Account discovery. |
| `13:48:50` | `powershell.exe -NoProfile -Command "Get-LocalGroupMember Administrators"` | Local administrator-group discovery. |
| `13:49:06` | `ipconfig /all` | Network configuration discovery. |
| `13:49:26` | `net group "Domain Admins" /domain` | Domain privileged-group discovery. |
| `13:55:41` | `powershell.exe -NoProfile -Command Get-Process` | Process enumeration on `SRV-FILE-01`. |
| `13:56:11` | Same `Get-Process` command | Similar process enumeration on `SRV-APP-01`. |
| `13:56:46` | Same `Get-Process` command | Similar process enumeration on `DC-01`. |

These commands can be legitimate in an approved administrative session. The suspicious authentication sequence, privileged account, timing, and multi-host pattern make them concerning as a group; command names alone are not a verdict.

## 4. Timeline

| Time | Event | Observation |
|---|---|---|
| `13:35:14` | `4625` | First observed failure from `10.10.50.23` to `SRV-FILE-01` for `Administrator`. |
| `13:35:14–13:46:39` | 40 × `4625` | Repeated failures across four accounts, Logon Type `10`. |
| `13:47:34` | `4624` | Successful RemoteInteractive logon as `Administrator` on `SRV-FILE-01`. |
| `13:47:44` | `4672` | Special privileges assigned. |
| `13:48:01–13:49:26` | 5 × `4688` | Identity, account, local group, network, and domain group discovery. |
| `13:49:47–13:51:33` | 4 × `4625` | Further failures as `Administrator` on `SRV-APP-01`. |
| `13:52:08` | `4624` | Successful network logon as `Administrator` on `SRV-APP-01`. |
| `13:52:16` | `4672` | Special privileges recorded on `SRV-APP-01`. |
| `13:52:53–13:54:15` | 4 × `4625` | Further failures as `Administrator` on `DC-01`. |
| `13:54:50` | `4624` | Successful network logon as `Administrator` on `DC-01`. |
| `13:54:58` | `4672` | Special privileges recorded on `DC-01`. |
| `13:55:41–13:56:46` | 3 × `4688` | PowerShell `Get-Process` activity recorded across the three hosts. |

## 5. ATT&CK mapping — provisional

- **T1110 — Brute Force:** supported by the repeated authentication failures and subsequent successful access. The exact sub-technique is not proven by this dataset. `T1110.001 Password Guessing` may be a working hypothesis, but should remain provisional.
- **T1021.001 — Remote Desktop Protocol:** the first successful logon has Logon Type `10` (`RemoteInteractive`), which is commonly associated with Remote Desktop / Terminal Services. Validate with RDP connection logs and network evidence before asserting the actual protocol in a real case.
- The post-access commands are consistent with account, group, network, and process discovery. Add more specific ATT&CK mappings only after validating the exact behaviors against current technique definitions and available evidence.

## 6. Verdict

**Verdict: Malicious activity indicated**  
**Confidence: High within this synthetic scenario**

**Rationale:** The combination of 40 failed remote-interactive logons across four accounts, a successful privileged `Administrator` logon from the same source, event `4672`, subsequent discovery commands, and further successful logons on additional servers is inconsistent with an isolated typo or single accidental login failure.

## 7. Recommended actions if this were a real environment

1. Preserve the relevant Security logs and EDR telemetry from `FIN-01`, `SRV-FILE-01`, `SRV-APP-01`, and `DC-01`.
2. Verify whether `FIN-01` and the `Administrator` account were authorized for Remote Desktop / remote network access at those times.
3. If activity is not authorized, follow the organization's incident response process to contain the source host and terminate suspicious sessions without destroying evidence.
4. Rotate or reset the potentially affected credentials according to response procedures; review privileged account exposure and membership of `Domain Admins`.
5. Review native RDP logs, domain controller authentication records, PowerShell operational/script-block logs, EDR process trees, and network flow evidence.
6. Determine whether the source address belongs to a legitimate internal host, VPN, jump server, or other expected infrastructure before making blocking decisions.

## 8. Limitations

- The records are synthetic and use a simplified CSV schema.
- The CSV contains no Logon ID / SubjectLogonId, so exact event-to-session correlation is unavailable.
- There is an inconsistent `Keywords` field: 29 `4625` rows in the full dataset are labelled `Audit Success`. The suspicious source's failed records are labelled `Audit Failure`, but the dataset-wide inconsistency is documented to avoid overstating its quality.
- The process-parent fields and command lines need validation against native process telemetry in a real investigation.
- No evidence of data exfiltration, persistence, malware execution, or a specific password value is provided; none should be claimed.

## 9. Dataset-wide context

The primary CSV contains 300 rows spanning `08:16:51–13:58:46` on `26 August 2026`:

| Event ID | Count |
|---:|---:|
| `4624` | 92 |
| `4625` | 77 |
| `4634` | 29 |
| `4647` | 21 |
| `4672` | 16 |
| `4688` | 65 |

The suspicious source `10.10.50.23` appears in 62 records: 48 failed logons, 3 successful logons, 3 special-privilege events, and 8 process-creation events.
