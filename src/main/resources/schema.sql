CREATE TABLE IF NOT EXISTS users
(
    id         BIGSERIAL PRIMARY KEY,
    email      TEXT    NOT NULL UNIQUE,
    password   TEXT    NOT NULL,
    first_name TEXT    NOT NULL,
    last_name  TEXT    NOT NULL,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS roles
(
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT    NOT NULL UNIQUE,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE

);

CREATE TABLE IF NOt EXISTS users_roles
(
    user_id BIGINT REFERENCES users (id),
    role_id BIGINT REFERENCES roles (id),
    PRIMARY KEY (user_id, role_id)
);


INSERT INTO users (email, password, first_name, last_name)
VALUES ('bob@test.com', '$2a$12$UdMD/WnTmdyBQX4FY4BS6O8GNLRR5CGzwtC6exVuKpULQ6vmhVZZW', 'Bob', 'Odinson'),
       ('alice@test.com', '$2a$12$n1oNmtcIgwSUQQ4FrItHLuA1jaX1cSg9qBnIxIQ32Ds397J7ByT9.', 'Alice', 'Poppins'),
       ('john@test.com', '$2a$12$gagao3NtNtsgRPBlAPra5e/aJmzjov9h0v3Yh/ZOe9i5wP.j0c5H2', 'John', 'Wick')
ON CONFLICT (email) DO NOTHING;

INSERT INTO roles (name)
VALUES ('ADMIN'),
       ('USER')
ON CONFLICT (name) DO NOTHING;

INSERT INTO users_roles (user_id, role_id)
VALUES ((SELECT id FROM users WHERE email = 'bob@test.com'), (SELECT id FROM roles WHERE name = 'ADMIN')),
       ((SELECT id FROM users WHERE email = 'alice@test.com'), (SELECT id FROM roles WHERE name = 'USER')),
       ((SELECT id FROM users WHERE email = 'john@test.com'), (SELECT id FROM roles WHERE name = 'ADMIN')),
       ((SELECT id FROM users WHERE email = 'john@test.com'), (SELECT id FROM roles WHERE name = 'USER'))
ON CONFLICT (user_id, role_id) DO NOTHING;

CREATE TABLE IF NOT EXISTS rsa_key_pairs
(
    id          VARCHAR(1000) NOT NULL PRIMARY KEY,
    private_key TEXT          NOT NULL,
    public_key  TEXT          NOT NULL,
    created     TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (id, created)
);