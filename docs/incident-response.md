# Incident response and forensic exercise

Scenario: repeated synthetic failed logins followed by suspected evidence modification.
Prepare: define owner, escalation contact and authorized scope; synchronize clocks; retain baseline hashes.
Identify: AUTH-05 triggers when a source reaches five failed events. This simple rule has no time-window
model and can produce false positives; review context before attributing malicious behavior.
Contain: revoke affected sessions, rotate exposed keys and isolate the compromised lab workload.
Preserve: copy evidence read-only, record collector, UTC time, SHA-256 and handling events.
Eradicate: fix the cause and patch the workload. Recover: restore a verified backup and retest controls.
Learn: record cause, response timeline and corrective tasks.

The executable manifest test changes one synthetic evidence file and detects a changed digest.
It demonstrates integrity comparison; a hash alone does not prove authenticity or legal chain of custody.
Capture template: evidence ID, original location, collector, acquisition UTC, SHA-256, transfer/handling,
read-only working copy and findings. Raw evidence remains outside the public repository.
