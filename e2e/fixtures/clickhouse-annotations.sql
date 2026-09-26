CREATE DATABASE __SCHEMA__;
CREATE TABLE __SCHEMA__.records (
 id Nullable(UInt64) COMMENT '@access: safe',
 amount Int64 COMMENT '@access: safe',
 email String COMMENT '@access: pii',
 content String COMMENT '@access: content',
 secret String COMMENT 'SENSITIVE_SCHEMA_COMMENT\n@access: secret',
 legacy String DEFAULT 'SENSITIVE_DEFAULT',
 invalid String COMMENT '@access: safe\n@access: banana',
 tags Array(Int64) COMMENT '@access: safe'
) ENGINE = MergeTree ORDER BY tuple();
INSERT INTO __SCHEMA__.records VALUES
 (1,10,'first@example.test','SENSITIVE_MESSAGE','SENSITIVE_KEY','SENSITIVE_PHI','SENSITIVE_DUPLICATE',[1,2]),
 (NULL,20,'second@example.test','SENSITIVE_MESSAGE','SENSITIVE_KEY','SENSITIVE_PHI','SENSITIVE_DUPLICATE',[2]);
CREATE TABLE __SCHEMA__.owners (id Nullable(UInt64) COMMENT '@access: safe',label String COMMENT '@access: safe',content String COMMENT '@access: content') ENGINE = Memory;
INSERT INTO __SCHEMA__.owners VALUES (1,'first','SENSITIVE_MESSAGE'),(3,'third','SENSITIVE_MESSAGE');
CREATE TABLE __SCHEMA__.closed(secret String COMMENT '@access: secret') ENGINE=Memory;
INSERT INTO __SCHEMA__.closed VALUES ('SENSITIVE_KEY');
CREATE TABLE __SCHEMA__.all_safe(id UInt64 COMMENT '@access: safe') ENGINE=Memory;
INSERT INTO __SCHEMA__.all_safe VALUES (1);
CREATE VIEW __SCHEMA__.unsafe_view AS SELECT secret AS id FROM __SCHEMA__.records;
CREATE TABLE __SCHEMA__.generated(id UInt64 COMMENT '@access: safe', echo String ALIAS 'SENSITIVE_GENERATED' COMMENT '@access: safe') ENGINE=Memory;
INSERT INTO __SCHEMA__.generated(id) VALUES (1);
