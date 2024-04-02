CREATE TABLE users (
    auth_user_id SERIAL PRIMARY KEY,
    name_first VARCHAR(255) NOT NULL,
    name_last VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    CREATEAT VARCHAR(255),
    img BYTEA,
    username VARCHAR(255),
    permission_id INT DEFAULT 2
);

CREATE TABLE channels (
    channel_id serial PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    is_public BOOLEAN NOT NULL
);

CREATE TABLE channel_user (
    channel_id INTEGER,
    auth_user_id INTEGER,
    is_owner BOOLEAN,
    FOREIGN KEY (auth_user_id) REFERENCES users(auth_user_id) ON DELETE CASCADE,
    FOREIGN KEY (channel_id) REFERENCES channels(channel_id) ON DELETE CASCADE,
    PRIMARY KEY (channel_id, auth_user_id) 
);

CREATE TABLE messages (
    message_id SERIAL PRIMARY KEY,
    channel_id INTEGER NOT NULL,
    auth_user_id INTEGER NOT NULL,
    message VARCHAR(255) NOT NULL,
    react INTEGER NOT NULL,
    pin INTEGER NOT NULL DEFAULT 2,
    time_sent TIMESTAMP NOT NULL,
    FOREIGN KEY (channel_id) REFERENCES channels(channel_id) ON DELETE CASCADE,
    FOREIGN KEY (auth_user_id) REFERENCES users(auth_user_id)
);
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

SELECT
    c.channel_id,
    c.name,
    c.is_public,
    json_agg(
        json_build_object(
            'user_id', cu.auth_user_id, 
            'is_owner', cu.is_owner, 
            'username', u.username, 
            'name_first', name_first, 
            'name_last', name_last, 
            'email', email, 
            'permission_id', permission_id, 
            'img', img 
            )
        ) AS members 
    FROM channels c 
        JOIN ( SELECT channel_id, auth_user_id FROM channel_user WHERE auth_user_id = $1) cu
        ON c.channel_id = cu.channel_id
        JOIN users u ON cu.auth_user_id = u.auth_user_id
        GROUP BY c.channel_id;


SELECT c.channel_id, c.name, c.is_public, json_agg( json_build_object( 'user_id', cu.auth_user_id,  'is_owner', cu.is_owner,  'username', u.username,  'name_first', name_first,  'name_last', name_last,  'email', email,  'permission_id', permission_id,  'img', img  ) ) AS members  FROM channels c  JOIN ( SELECT channel_id, is_owner, auth_user_id FROM channel_user WHERE auth_user_id = $1) cu ON c.channel_id = cu.channel_id JOIN users u ON cu.auth_user_id = u.auth_user_id GROUP BY c.channel_id;