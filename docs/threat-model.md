# Threat model, controls and risk register

Assets: classroom identities, questions, teacher credentials, configuration and audit evidence.
Actors: student, teacher, administrator, outsider and compromised client. Trust boundaries:
browser/application, application/database, teacher-only data projection, network segments and keys.
CIA: confidentiality of authorship, integrity of votes/answers, availability during teaching.

| Threat | Likelihood x impact (assumed) | Control | Verification |
|---|---|---|---|
| Password database exposure | 3 x 5 | Unique salt, PBKDF2-SHA256 600000 iterations | Correct/wrong password and salt tests |
| Record tampering | 3 x 5 | AES-256-GCM with authenticated context | Tamper and wrong-context rejection |
| Direct database access from student segment | 4 x 5 | Default-deny segmentation | Policy matrix and Linux ACL lab |
| Identity leakage in analytics | 3 x 4 | Remove direct identifiers; keyed pseudonyms | Redaction and key separation tests |
| Audit evidence modification | 2 x 4 | SHA-256 manifest and retained original | Forensic edit detection test |
| Repeated failed authentication | 4 x 3 | Threshold detection and escalation | Four/five/seven-event fixtures |
| Loss of service | 3 x 3 | Backups, restart checks, incident procedure | SA persistence and migration checks |

Risk numbers are an analytical prioritization exercise, not measured incident frequencies.
PBKDF2 protects passwords; AES-GCM protects records; hashing is not encryption. Fresh nonces and
key separation are demonstrated. Key management remains a distinct operational responsibility.

## Data classification and access

Public: product documentation and synthetic fixtures. Restricted: teacher-visible names and moderation.
Sensitive: credentials and encryption keys. Never commit restricted classroom records or private keys.
Redaction reduces disclosure but cannot promise anonymity for arbitrary small datasets. Keyed
pseudonyms remain linkable and should be handled as pseudonymous data. This is not a legal compliance certification.

Reference concepts: STRIDE-style threat categories, CIA, least privilege and defense in depth.
Library implementation: https://cryptography.io/en/latest/hazmat/primitives/aead/ .
