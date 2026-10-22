# Windows Event Log Investigation — Week 01

**Week 1 of a self-designed, 12-week SOC analyst learning path.**
Focus: Windows authentication events (Event IDs 4624, 4625, 4672, 4688), investigation workflow, and incident report writing.

> **Disclosure:** The dataset and parts of the documentation were generated with AI assistance. All data is **synthetic** and does not describe any real organization, user, or incident. The investigation work and conclusions are my own; I used AI afterwards to review my reasoning and identify gaps.

---

## Objectives

- Understand the core Windows authentication Event IDs and what each one tells an analyst.
- Move from "this looks suspicious" to **evidence-based** conclusions.
- Follow a single user's activity across events to build a complete picture.
- Write a structured investigation report.

## Approach

1. **Sourcing practice data.** Many public labs and datasets require payment, so I generated a synthetic Windows event dataset with AI assistance and investigated it as if it were real.
2. **Tooling.** I first tried Splunk, but it requires a business email account, so I moved on. I found **Elastic**, loaded the dataset, and explored it. My use of Elastic this week was basic (loading data and exploring events); deeper search and dashboarding is planned for later weeks.
3. **Investigation.** I analyzed the events myself, traced the activity of the accounts involved, and documented findings in a report.
4. **Review.** I asked AI to review my analysis and mistakes, then recorded what I learned.

## What I Learned

- **Event IDs.** I learned the key authentication and process events (4624, 4625, 4672, 4688) and how to read them in context: who, from where, when, and what happened before and after.
- **Verify before concluding.** Early on, I tended to label anything unusual as an attack. I learned to treat an anomaly as a lead: check whether it is actually abnormal, then follow the user's full activity trail through the collected artifacts before drawing a conclusion.
- **Report writing.** I learned to structure an investigation report: scope, evidence, timeline, assessment, and confidence.
- **Analyst mindset.** I shifted from recognizing terms to asking investigative questions and separating observed facts from interpretation.
- **Elastic (introductory).** I ran it, loaded the data, and explored events. I plan to go deeper in later weeks.

## Investigation Summary (synthetic scenario)

| Stage | Observation |
|---|---|
| Failed logons | 40 failed logons (4625) against `SRV-FILE-01` from `10.10.50.23`, spread across four accounts (10 each) |
| Successful access | Successful RemoteInteractive logon (Type 10) as `Administrator`, followed by a privilege event (4672) |
| Discovery | `whoami`, `net user`, `ipconfig /all`, `net group "Domain Admins" /domain` |
| Lateral movement | Logons to `SRV-APP-01` and `DC-01` |

**Assessment (lab scenario only):** the sequence strongly indicates malicious activity. Full reasoning: [`cases/week1-authentication-investigation.md`](cases/week1-authentication-investigation.md).

## Data Limitations

- The CSV is a simplified table, not a native `.evtx` export.
- It has no Logon ID, so sessions cannot be linked exactly.
- 29 rows with Event ID 4625 are labeled `Audit Success`, which contradicts the event's meaning. See [`docs/data-quality-notes.md`](docs/data-quality-notes.md).

## Screenshots

| | |
|---|---|
| ![Dataset loaded in Elastic](screenshots/01-elastic-data-loaded.png) | ![Failed logons filtered](screenshots/02-failed-logons-4625.png) |
| ![Account activity trail](screenshots/03-account-activity.png) | ![Script output](screenshots/04-script-output.png) |

## Repository Structure

```
data/      synthetic dataset
cases/     investigation report
docs/      data-quality notes and references
scripts/   Python analysis helper
tests/     unit tests
```

## Run

```bash
python scripts/analyze_events.py
python -m unittest discover -s tests -v
```

## Tools

Python (standard library), Elastic, Windows Event Logs.

## Next

Week 2 of the 12-week plan builds on this foundation.

Arabic version: [README_AR.md](README_AR.md)
