-- Known service hosts (e.g. a Discord game server notifier that queries every game): they send discovery
-- packets like players, the players page lists them separately and does not count them.

CREATE TABLE service_host (
    ip    TEXT PRIMARY KEY,
    name  TEXT NOT NULL,
    note  TEXT NOT NULL DEFAULT '',
    user  TEXT NOT NULL,
    ts    TEXT NOT NULL
);
