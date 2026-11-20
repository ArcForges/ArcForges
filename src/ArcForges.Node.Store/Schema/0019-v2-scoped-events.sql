-- SPDX-License-Identifier: AGPL-3.0-only
-- Only committed Sandbox and Run identities and revisions enter the V2 event feed.
ALTER TABLE event ADD COLUMN owner_id TEXT;
ALTER TABLE event ADD COLUMN sandbox_id TEXT;
CREATE INDEX event_owner_cursor ON event(owner_id,epoch,sequence);
CREATE INDEX event_sandbox_cursor ON event(owner_id,sandbox_id,epoch,sequence);

-- A filtered stream must distinguish a missing scoped prefix from unrelated sequence numbers.
CREATE TABLE event_eviction (
 owner_id TEXT NOT NULL, sandbox_id TEXT NOT NULL, epoch TEXT NOT NULL, through_sequence INTEGER NOT NULL,
 PRIMARY KEY(owner_id,sandbox_id), FOREIGN KEY(sandbox_id) REFERENCES sandbox(sandbox_id) ON DELETE CASCADE
) STRICT;
CREATE INDEX event_eviction_owner_epoch ON event_eviction(owner_id,epoch,through_sequence);

CREATE TRIGGER event_keep_bounded_prefix AFTER INSERT ON event
WHEN NEW.owner_id IS NOT NULL AND NEW.sandbox_id IS NOT NULL
BEGIN
 INSERT INTO event_eviction(owner_id,sandbox_id,epoch,through_sequence)
 SELECT owner_id,sandbox_id,epoch,max(sequence) FROM event
 WHERE epoch=NEW.epoch AND sequence<=NEW.sequence-100000 AND owner_id IS NOT NULL AND sandbox_id IS NOT NULL
 GROUP BY owner_id,sandbox_id,epoch
 ON CONFLICT(owner_id,sandbox_id) DO UPDATE SET epoch=excluded.epoch,through_sequence=excluded.through_sequence;
 DELETE FROM event WHERE sequence<=NEW.sequence-100000 AND owner_id IS NOT NULL;
END;

CREATE TRIGGER sandbox_event_inserted AFTER INSERT ON sandbox
BEGIN
 INSERT INTO event(epoch,kind,aggregate_id,revision,created_utc,body_json,owner_id,sandbox_id)
 VALUES((SELECT CAST(journal_generation AS TEXT) FROM store_meta WHERE singleton=1),
        'sandbox',NEW.sandbox_id,NEW.revision,NEW.created_utc,'{}',NEW.owner_id,NEW.sandbox_id);
END;

CREATE TRIGGER sandbox_event_revised AFTER UPDATE OF state,revision ON sandbox
WHEN NEW.state<>OLD.state OR NEW.revision<>OLD.revision
BEGIN
 INSERT INTO event(epoch,kind,aggregate_id,revision,created_utc,body_json,owner_id,sandbox_id)
 VALUES((SELECT CAST(journal_generation AS TEXT) FROM store_meta WHERE singleton=1),
        'sandbox',NEW.sandbox_id,NEW.revision,NEW.updated_utc,'{}',NEW.owner_id,NEW.sandbox_id);
END;

CREATE TRIGGER run_event_inserted AFTER INSERT ON run
BEGIN
 INSERT INTO event(epoch,kind,aggregate_id,revision,created_utc,body_json,owner_id,sandbox_id)
 SELECT CAST(m.journal_generation AS TEXT),'run',NEW.run_id,NEW.revision,NEW.created_utc,'{}',s.owner_id,s.sandbox_id
 FROM sandbox s CROSS JOIN store_meta m WHERE s.sandbox_id=NEW.sandbox_id AND m.singleton=1;
END;

CREATE TRIGGER run_event_revised AFTER UPDATE OF revision ON run
WHEN NEW.revision<>OLD.revision
BEGIN
 INSERT INTO event(epoch,kind,aggregate_id,revision,created_utc,body_json,owner_id,sandbox_id)
 SELECT CAST(m.journal_generation AS TEXT),'run',NEW.run_id,NEW.revision,
        strftime('%Y-%m-%dT%H:%M:%fZ','now'),'{}',s.owner_id,s.sandbox_id
 FROM sandbox s CROSS JOIN store_meta m WHERE s.sandbox_id=NEW.sandbox_id AND m.singleton=1;
END;
