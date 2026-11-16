-- Monitoring outputs (docs/05-monitoring-konzept.md): any number of push targets per kind, and the alarm
-- instances already reported as open, so a restart neither repeats "open" nor loses "clear".
-- Secrets (community, passwords, headers) are stored as JSON in plain text on purpose (decision E4: they belong
-- into the backup); the UI never shows them and they never go into audit, logs or exports.

CREATE TABLE monitor_target (
    id         INTEGER PRIMARY KEY,
    kind       TEXT NOT NULL CHECK (kind IN ('syslog', 'otlp', 'snmptrap')),
    name       TEXT NOT NULL UNIQUE,
    enabled    INTEGER NOT NULL DEFAULT 1,
    endpoint   TEXT NOT NULL,
    events     TEXT NOT NULL DEFAULT 'alarm,audit',
    config     TEXT NOT NULL DEFAULT '{}',
    secret     TEXT NOT NULL DEFAULT '{}',
    created_ts TEXT NOT NULL,
    updated_ts TEXT NOT NULL
);

CREATE TABLE monitor_alarm_state (
    kind      TEXT NOT NULL,
    key       TEXT NOT NULL,
    opened_ts TEXT NOT NULL,
    PRIMARY KEY (kind, key)
);

-- the single syslog target of the first version becomes the first target
INSERT INTO monitor_target(kind, name, enabled, endpoint, events, config, created_ts, updated_ts)
    SELECT 'syslog', 'Syslog', 1, value, 'alarm,audit', '{"transport":"udp","format":"rfc5424","facility":"local0"}',
           strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    FROM setting WHERE key = 'syslog_target' AND value != '';
DELETE FROM setting WHERE key = 'syslog_target';
