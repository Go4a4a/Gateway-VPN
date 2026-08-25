CREATE UNIQUE INDEX users_username_nocase
ON users(username COLLATE NOCASE);
