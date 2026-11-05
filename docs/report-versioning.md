# Report snapshots and versioning

Each generated report is an immutable snapshot of persisted assessment data. The report record stores its content in the database and receives the next version number for that assessment. The snapshot includes its generation time and a SHA-256 data revision fingerprint so readers can identify the source state used to create it.

Generation records the source fingerprint before building the snapshot and checks it again before saving. If the assessment data changed during generation, the request is rejected and can be retried. Generating a later report creates a new version; it does not modify older snapshots. Finding, remediation, execution, or retest changes therefore appear only in a subsequently generated report.

Report list, detail, and export routes apply the assessment's client membership checks. Detail access and exports are recorded as audit events. See the report generation documentation for supported output formats and their handling rules.
