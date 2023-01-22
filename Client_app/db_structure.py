QUERY = """
CREATE TABLE IF NOT EXISTS crypto_user (
    id integer PRIMARY KEY AUTOINCREMENT NOT NULL,
    private_key text NOT NULL
);

CREATE TABLE IF NOT EXISTS crypto_chat (
    id integer PRIMARY KEY AUTOINCREMENT NOT NULL,
    chat_name text integer NOT NULL,
    chat_pass text NOT NULL
);

"""
