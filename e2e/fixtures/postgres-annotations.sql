CREATE SCHEMA __SCHEMA__;
CREATE TABLE __SCHEMA__.records (
 id integer, amount integer, email text, content text, secret text,
 legacy text DEFAULT 'SENSITIVE_DEFAULT', invalid text, tags text[]
);
COMMENT ON COLUMN __SCHEMA__.records.id IS 'Record identifier.
@access: safe';
COMMENT ON COLUMN __SCHEMA__.records.amount IS '@access: safe';
COMMENT ON COLUMN __SCHEMA__.records.email IS '@access: pii';
COMMENT ON COLUMN __SCHEMA__.records.content IS '@access: content';
COMMENT ON COLUMN __SCHEMA__.records.secret IS 'SENSITIVE_SCHEMA_COMMENT
@access: secret';
COMMENT ON COLUMN __SCHEMA__.records.invalid IS '@access: safe
@access: banana';
COMMENT ON COLUMN __SCHEMA__.records.tags IS '@access: safe';
INSERT INTO __SCHEMA__.records VALUES
 (1,10,'first@example.test','SENSITIVE_MESSAGE','SENSITIVE_KEY','SENSITIVE_PHI','SENSITIVE_DUPLICATE',ARRAY['a','b']),
 (2,20,'second@example.test','SENSITIVE_MESSAGE','SENSITIVE_KEY','SENSITIVE_PHI','SENSITIVE_DUPLICATE',ARRAY['b']);
CREATE TABLE __SCHEMA__.owners (id integer PRIMARY KEY, label text, content text);
COMMENT ON COLUMN __SCHEMA__.owners.id IS '@access: safe';
COMMENT ON COLUMN __SCHEMA__.owners.label IS '@access: safe';
COMMENT ON COLUMN __SCHEMA__.owners.content IS '@access: content';
INSERT INTO __SCHEMA__.owners VALUES (1,'first','SENSITIVE_MESSAGE'),(3,'third','SENSITIVE_MESSAGE');
CREATE TABLE __SCHEMA__.closed (secret text);
COMMENT ON COLUMN __SCHEMA__.closed.secret IS '@access: secret';
INSERT INTO __SCHEMA__.closed VALUES ('SENSITIVE_KEY');
CREATE TABLE __SCHEMA__.all_safe (id integer);
COMMENT ON COLUMN __SCHEMA__.all_safe.id IS '@access: safe';
INSERT INTO __SCHEMA__.all_safe VALUES (1);
CREATE VIEW __SCHEMA__.unsafe_view AS SELECT secret AS id FROM __SCHEMA__.records;
COMMENT ON COLUMN __SCHEMA__.unsafe_view.id IS '@access: safe';
CREATE TABLE __SCHEMA__.generated (id integer, echo text GENERATED ALWAYS AS ('SENSITIVE_GENERATED'::text) STORED);
COMMENT ON COLUMN __SCHEMA__.generated.id IS '@access: safe';
COMMENT ON COLUMN __SCHEMA__.generated.echo IS '@access: safe';
INSERT INTO __SCHEMA__.generated(id) VALUES (1);

ALTER TABLE __SCHEMA__.records ADD COLUMN owner_id integer REFERENCES __SCHEMA__.owners(id);
COMMENT ON COLUMN __SCHEMA__.records.owner_id IS '@access: safe';
UPDATE __SCHEMA__.records SET owner_id=1;
