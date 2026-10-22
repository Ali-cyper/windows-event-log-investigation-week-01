# Data directory

All files here are synthetic Windows-event training material.

## Primary case dataset

- `week1_authentication_events_300.csv` — 300 simplified event records analyzed in the report. The source IP `10.10.50.23` is the main suspicious indicator in this lab scenario.

## Supplementary practice artifacts

- `supplementary_authentication_sample.txt` — short, hand-readable authentication exercise containing failed logons, successful logons, privilege events, and post-logon process commands.
- `supplementary_windows_events_readable.log` — a larger human-readable set of Windows Security event records.
- `supplementary_windows_security_xml_events.txt` — synthetic Windows Security event records shown in an XML-like Windows event format.

The supplementary files are intentionally kept separate. They are not additional rows from the main CSV and should not be mixed into the case timeline. Data is not guaranteed to be identical across these separate files.
