-- SQLite
ALTER TABLE users ADD COLUMN md5 text;
ALTER TABLE users ADD COLUMN sha256 text;
ALTER TABLE users ADD COLUMN bcrypt text;