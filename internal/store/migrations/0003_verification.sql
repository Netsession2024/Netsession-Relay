-- "Tested at event X" records per game (docs/02-plan.md 3.x table verification, phase 10). The newest row decides
-- the badge on the game. pcap files are not stored here (download from the port finder, commit to testdata/).

CREATE TABLE verification (
    id      INTEGER PRIMARY KEY,
    game_id TEXT NOT NULL REFERENCES game(id) ON DELETE CASCADE,
    event   TEXT NOT NULL,
    result  TEXT NOT NULL CHECK (result IN ('works', 'fails', 'partial')),
    variant TEXT NOT NULL DEFAULT '',
    note    TEXT NOT NULL DEFAULT '',
    user    TEXT NOT NULL,
    ts      TEXT NOT NULL
);

CREATE INDEX verification_game ON verification(game_id, id);
