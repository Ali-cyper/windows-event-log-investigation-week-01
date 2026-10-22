# Week 01 — Windows Authentication Investigation Method

## Objective

Move from reading isolated Event IDs to answering an incident question with a defensible timeline. The goal is not to memorize numbers in isolation; it is to determine what happened, what evidence supports the conclusion, and what remains unknown.

## Step 1 — Triage the alert

Record the alert name, time range, affected host, account, reported source, and severity. Confirm what data is available before making assumptions.

## Step 2 — Build the authentication picture

Start with `4625` and `4624`.

- Group failures by source IP and target host.
- Count distinct accounts and attempts per account.
- Check whether attempts are tightly clustered in time or spread over a longer period.
- Compare against normal service-account, administrative, and user activity.
- Check if any success follows the failed attempts from the same source and for a related account/host.

### Brute force vs. password spraying

- **Password guessing / brute force against one account:** many guesses are directed at one account.
- **Password spraying:** a small set of commonly used passwords is attempted across multiple accounts, usually to avoid account lockout thresholds.
- A basic event log normally does not reveal which password was attempted. A pattern may support a hypothesis, but do not claim to know the exact strategy unless the evidence can distinguish it.

The primary dataset shows repeated failures across four account names and later a success. This supports **multi-account password-guessing activity**; the exact credential-attack subtype cannot be proven from the CSV alone.

## Step 3 — Interpret Logon Type

Interpret Logon Type in context. Type `10` identifies a RemoteInteractive logon associated with Terminal Services / Remote Desktop. Type `3` indicates network logon but does not by itself identify the exact protocol.

## Step 4 — Inspect privilege events

Review `4672` only after identifying the account, host, time, and relevant successful logon. Check whether the listed privileges are expected for this identity and system. In native event data, use Logon ID when present; the primary CSV does not provide one.

## Step 5 — Inspect process creation

For each relevant `4688`, document:

- timestamp and affected computer;
- subject account;
- process path;
- parent process path;
- command line and arguments;
- whether the command makes sense for the account, parent process, host, and phase of activity;
- corroborating EDR, PowerShell, network, or other event records.

Commands such as `whoami`, `net user`, `ipconfig /all`, `Get-LocalGroupMember Administrators`, and querying the `Domain Admins` group can be legitimate admin activity. In this case, their sequence immediately following suspicious authentication makes the combined pattern concerning. Context, not command name alone, supports the verdict.

## Step 6 — Build a timeline

Use one row per notable event. Preserve exact timestamps from the dataset. Separate:

- **Observed fact:** directly present in the log.
- **Interpretation:** what the observed fact might indicate.
- **Unknown:** evidence not available in the dataset.

## Step 7 — Write the verdict

A usable SOC L1 verdict answers:

1. What is the classification — Benign, Suspicious, or Malicious?
2. How confident are you, and why?
3. What are the strongest three to five pieces of evidence?
4. What could be a benign explanation?
5. What additional data would confirm or refute the hypothesis?
6. What immediate actions are proportionate to the evidence?

## Required report pattern

```text
Verdict: Malicious / Suspicious / Benign
Confidence: Low / Medium / High
Summary: One or two sentences.
Evidence:
- [Timestamp] [Event ID] — [observable fact]
- [Timestamp] [Event ID] — [observable fact]
Interpretation: Explain how the sequence fits together.
Limitations: Name missing fields or inconsistent data.
Recommended actions: Prioritized containment, validation, and evidence preservation.
```

## First-attempt rule used in training

Try the investigation without AI or external answer searches for the first 45 minutes. A meaningful attempt includes filtering, comparing events, writing a provisional hypothesis, building a timeline, and trying to prove or disprove it. Hints should guide the next check rather than reveal the final answer. After reviewing the solution, repeat the difficult section independently.
