CREATE TABLE users (
    auth_user_id serial PRIMARY KEY,
    name_first VARCHAR(255) NOT NULL,
    name_last VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    CREATEAT VARCHAR(255),
    img BYTEA,
    username VARCHAR(255),
    permission_id INT DEFAULT 1
);

CREATE TABLE channels (
    channel_id serial PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    is_public BOOLEAN NOT NULL,
)

CREATE TABLE channel_users (
    auth_user_id INTEGER PRIMARY KEY,
    channel_id INTEGER PRIMARY KEY,
    is_owner BOOLEAN
    FOREIGN KEY (auth_user_id) REFERENCES users(auth_user_id) ON DELETE CASCADE,
    FOREIGN KEY (channel_id) REFERENCES channels(channel_id) ON DELETE CASCADE,
)

/*
channelsId num
owners list
all memebers list
is_public boolean
*/

/*
messages

(
    messageId num
    channelId num
    message string
    react
)
*/

/*
reacts

(
    react_id num
    channelId
    messageId
)
*/