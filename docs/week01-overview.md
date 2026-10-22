# Week 01 Overview — Windows Authentication and Event Logs

## Training objective

Week 01 was the first focused investigation block in the SOC L1 practical plan. Its aim was to build confidence reading Windows Security events and to move from memorising Event IDs toward explaining an incident from evidence.

The scope for this repository is deliberately limited to:

- Successful and failed authentication.
- Repeated logon-failure patterns and multi-account targeting.
- Logon Type and authentication context.
- Special-privilege events.
- Process creation, command lines, and parent-process context.
- Timeline construction, data-quality checks, and an evidence-based SOC verdict.

## Topics and event IDs

| Event ID | Week 01 focus | Investigation question |
|---|---|---|
| `4624` | Successful logon | Did a success occur after a suspicious failure pattern? Which account, host, source, and Logon Type were involved? |
| `4625` | Failed logon | Are failures repeated, clustered, or spread over multiple accounts and hosts? |
| `4672` | Special privileges assigned to a logon | Are privileged rights expected for this account and system, and can this event be correlated with the session? |
| `4688` | Process creation | Which process was started, by whom, with what command line, and under which parent process? |
| `4634` | Logoff / logon session ended | Does the event help place a session's end in the timeline? |
| `4647` | User-initiated logoff | Is there evidence of a user-initiated sign-out? |

The main four focus IDs were `4624`, `4625`, `4672`, and `4688`. The logoff IDs appear as supporting reference material only.

## Training approach recovered from the notes

The training notes describe this workflow:

1. Identify the alert, time window, affected computer, account, and source address.
2. Spend the initial 45 minutes investigating independently, without AI or answer searches.
3. Filter and compare events; group failed logons by source, account, target host, and time.
4. Write a provisional hypothesis and try to disprove it using the available evidence.
5. Ask for a limited hint only after a genuine attempt; if help is used, repeat the difficult part independently.
6. Build a timeline and write a short English SOC verdict that states what happened, evidence, confidence, limitations, and recommended actions.

The goal is not to label every `4625` as an attack. A single failure can occur for benign reasons; repeated failures and the context around subsequent successful logons need to be assessed together.

## Practice path and scope boundary

The saved training continuation notes record that Day 1 was intended to focus on Windows Authentication / Brute Force. The LetsDefend path and quiz were reviewed, but its practical challenge required a subscription, so a file-based synthetic log exercise was used as an accessible alternative. The original investigation prompt is preserved in [`../labs/original-week1-investigation-prompts.txt`](../labs/original-week1-investigation-prompts.txt), and the case analysis uses the primary CSV in [`../data/week1_authentication_events_300.csv`](../data/week1_authentication_events_300.csv).

A saved high-level progress summary also references HTB Sherlock **Logjammer** and Windows Security, System, Defender, Firewall, and PowerShell logs. However, the exact Logjammer challenge files, question answers, and original investigation notes were not present among the retrievable saved materials used for this repository. Therefore, this project does **not** claim to be a verified Logjammer walkthrough and does not attribute the synthetic CSV findings to that challenge.

## Included deliverables

- A primary 300-event synthetic authentication dataset.
- Separate supplementary text and XML-style training artifacts. These represent different datasets and must not be merged into the primary case timeline.
- Original Week 01 investigation prompts and a structured lab version.
- An incident case report with timeline, evidence, limitations, provisional ATT&CK mapping, and response suggestions.
- Event ID and investigation-method references.
- A Python standard-library script and unit tests for repeatable dataset checks.

## Professional reporting rules

- Clearly label synthetic training data.
- Keep observations separate from interpretations.
- Do not invent missing `Logon ID` values or exact attack sub-techniques.
- Treat `4672` and dual-use administration commands in context, not as standalone proof of compromise.
- Record inconsistent fields instead of silently altering the source data.
- Never publish real credentials, private customer logs, or sensitive identifying details. The included lab data is synthetic.
