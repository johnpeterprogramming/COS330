-- SQLite
ALTER TABLE users ADD COLUMN hash text;
ALTER TABLE users ADD COLUMN nonce text;
ALTER TABLE users ADD COLUMN salt text;