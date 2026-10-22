# Data Quality and Scope Notes

## Source materials recovered for this project

The primary analysed file is `data/week1_authentication_events_300.csv`. Three other recovered files are included as supplementary practice artifacts. The case report is based on the primary CSV only; do not combine rows from the supplementary files into the same timeline because they are distinct synthetic data artifacts.

## Known limitations in the primary CSV

1. **No native Windows event envelope:** the CSV is a simplified table, not an original `.evtx` file or raw exported event XML. Treat its field mapping as a training representation.
2. **No Logon ID:** the columns do not include `Logon ID` or `SubjectLogonId`, so session correlation cannot be established at the native event level.
3. **Inconsistent `Keywords`:** 29 rows with `EventID=4625` are marked `Audit Success`. This conflicts with the meaning of Event ID 4625. For those rows, do not trust `Keywords` to indicate outcome. Use Event ID and available status fields, and verify against native logs when possible.
4. **Common columns across event types:** fields such as `SourceIP`, `LogonType`, and account names are populated in a uniform table even when native event schemas differ. In real investigations, interpret each field according to that event's actual schema.
5. **Synthetic process lineage:** the `ParentProcess` and `CommandLine` entries are intentionally simplified. In particular, PowerShell `Get-Process` records with `svchost.exe` as the parent warrant validation in a real case with process telemetry and service context.
6. **No corroborating telemetry:** there are no original endpoint telemetry, process IDs for full tree correlation, PowerShell script-block logs, RDP connection logs, network flows, or change tickets included here.

## How to handle these limits professionally

- Do not silently correct the original CSV.
- Record the caveat in the incident report.
- Make the strongest conclusion supported by the sequence, while avoiding unsupported claims about exact tooling, motive, or credential technique.
- Request the underlying `.evtx`, EDR process tree, RDP logs, domain controller logs, and approved-administration baseline before treating this as a real incident.

## Historical source / reconstruction note

The recovered training continuation notes identify Week 01 as Windows Authentication / Brute Force and mention a file-based synthetic exercise after a LetsDefend practical challenge was found to require a subscription. A high-level saved progress summary also referenced HTB Sherlock Logjammer. The exact Logjammer challenge files, original answers, and analyst notes were not available among the retrievable sources for this repository; consequently, the case report is based on the included synthetic CSV and is not presented as a Logjammer solution. See [`week01-overview.md`](week01-overview.md).

## Scope exclusion

The broader training plan contains later-week subjects. This repository deliberately extracts only Week 01 Windows Event Log / authentication material and excludes the later-week notes.
