# Week 01 — Learner Review Notes and Follow-Up Checklist

This document records the Week 01 learning context that could be recovered from the saved training notes. It is a practical review aid, not a claim that every item below was a mistake made during one specific investigation. The original conversation history and the full HTB Sherlock Logjammer artifacts were not available for complete verbatim reconstruction.

## Confirmed initial blocker reported by the learner

The learner clarified that the main difficulty at the very beginning was **how to open and inspect the XML event-log files**: there was no suitable application available on the device to view them. The learner searched for a solution and found Elastic as the tool they could use to inspect/analyze the events. Once this setup/viewing problem was solved, they reported being able to continue with the rest of the work.

This should be recorded as an environment/tooling blocker, not mislabeled as a failure to understand Windows logs. For future labs, include a short setup step before the investigation:

1. Identify the file format (`.evtx`, XML export, JSON, or CSV).
2. Choose a compatible viewer or ingestion workflow. Elastic can be used for searching and correlating ingested events, but it is not simply a universal double-click XML viewer; the exact import path depends on the file/export format and Elastic setup.
3. Confirm that timestamps, Event IDs, account names, host names, and event details were parsed correctly before drawing conclusions.
4. Keep the original source file unchanged and record any parsing/import issues.

## Starting point recorded in the training notes

- Windows Event Logs and Windows/AD concepts had been encountered in TryHackMe SOC Level 1, but the hands-on use was described as relatively shallow.
- At times, the learner still needed to look up the meaning of an Event ID or a Windows service rather than confidently interpret it in context.
- MITRE ATT&CK technique selection was a development goal: connect a technique to observed evidence during investigation rather than trying to memorize every technique in advance.
- The main objective was to become able to move from an alert or artifact to a defensible conclusion, including what evidence supports or weakens the hypothesis.

These are recovered baseline notes, not a complete transcript of all answers, hints, or corrections from the original chats.

## Week 01 focus areas to reinforce

### 1. Event ID recognition must lead to investigation, not stop at a label

Know the basic purpose of the primary events:

- `4624` — successful logon.
- `4625` — failed logon.
- `4672` — special privileges assigned to a logon.
- `4688` — process creation.

For each event, ask: which account, which host, what time, what source, what session context, and what happened before and after it?

### 2. Keep the attack label proportional to the evidence

Repeated failures across several accounts can support a multi-account credential-guessing hypothesis. They do not, by themselves, prove the exact technique. Distinguish among:

- **Repeated password guessing against one account** — many attempts are aimed at a single identity.
- **Password spraying** — a small set of password guesses is tried across many accounts, often to avoid account lockout.
- **Multi-account guessing with limited telemetry** — a broader description to use when the logs do not reveal the password sequence clearly.

For this dataset, ten failures per account across four accounts are visible before the first successful logon. Because the CSV contains no password-attempt values and is a simplified table, the report intentionally avoids claiming the exact credential-attack subtype as proven.

### 3. Treat `4672` as context, not a verdict

Special privileges can occur during legitimate administrative activity. Check the account, host, time, privilege list, and expected baseline. Correlate with a matching logon session when the native `Logon ID` is available. Do not invent a Logon ID when it is absent from the simplified CSV.

### 4. Read process creation in context

For `4688`, check the executable path, parent process, command line, account, host, timestamp, and surrounding logons. Commands such as `whoami`, `net user`, `ipconfig /all`, or PowerShell queries can be legitimate; their order and context are what make them concerning in the training case.

### 5. Be disciplined about evidence quality

This exercise specifically exposes two limitations:

- The primary CSV does not include `Logon ID` / `SubjectLogonId`, so exact session linkage cannot be demonstrated from that file alone.
- 29 rows with Event ID `4625` are inconsistently marked `Audit Success` in `Keywords`. Preserve and document the inconsistency instead of silently editing the source; validate against native logs if this were a real incident.

### 6. Make MITRE ATT&CK mapping provisional

First describe the observable behavior in plain language. Then map it to a technique only if the evidence supports it. If the logs support repeated credential attempts but do not expose the exact credential strategy, record the broader technique and note the uncertainty rather than overstating a sub-technique.

## Week 01 investigation self-check

Before calling a case complete, confirm that you can answer all of these without relying on the conclusion in the report:

- [ ] What made the alert worth investigating?
- [ ] Which exact events establish failed authentication?
- [ ] What pattern exists across source IP, account, host, and time?
- [ ] Is there a later successful logon from a matching source?
- [ ] What does the Logon Type mean, and what does it not prove?
- [ ] Is the privilege event expected, and can it be correlated to the session?
- [ ] What command lines followed the logon, and why are they concerning in context?
- [ ] Which facts are directly observed, and which are interpretations?
- [ ] What fields or corroborating logs are missing?
- [ ] Is the verdict and MITRE mapping no stronger than the evidence allows?

## Historical exercise note

The saved training continuation states that the LetsDefend practical exercise required a subscription, so a file-based synthetic investigation was used as an accessible alternative. A high-level progress summary also referenced HTB Sherlock Logjammer, including Windows Security, System, Defender, Firewall, and PowerShell logs. However, its original challenge files, exact answers, and detailed personal corrections were not recovered. This repository therefore does not claim to reproduce those missing details or to be a verified Logjammer walkthrough.
