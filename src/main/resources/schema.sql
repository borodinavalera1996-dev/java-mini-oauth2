CREATE TABLE IF NOT EXISTS users (
    userid             VARCHAR(100) PRIMARY KEY,
    username           VARCHAR(150) NOT NULL UNIQUE,
    passwordhash       VARCHAR(255) NOT NULL,
    info               JSONB,
    created_at         TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at         TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS clients (
    clientid           VARCHAR(100) PRIMARY KEY,
    clientsecrethash   VARCHAR(255) NOT NULL,
    info               JSONB,
    created_at         TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS refresh_index (
    refreshid          UUID PRIMARY KEY,
    userid             VARCHAR(100) NOT NULL REFERENCES users(userid) ON DELETE CASCADE,
    client_id          VARCHAR(100) NOT NULL REFERENCES clients(clientid) ON DELETE CASCADE,
    exp                TIMESTAMP WITH TIME ZONE NOT NULL,
    rotated            BOOLEAN DEFAULT FALSE NOT NULL,
    created_at         TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at         TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_refresh_userid ON refresh_index(userid);
CREATE INDEX IF NOT EXISTS idx_refresh_exp ON refresh_index(exp);

CREATE TABLE IF NOT EXISTS  revocation (
    revocation_id      BIGSERIAL PRIMARY KEY,
    token_type         VARCHAR(20) NOT NULL CHECK (token_type IN ('access', 'refresh')),
    target_id          VARCHAR(255) NOT NULL, -- jti для access-токенов или refresh_id для refresh-токенов
    exp                TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at         TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    reason             VARCHAR(255)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_revocation_lookup ON revocation(token_type, target_id);
CREATE INDEX IF NOT EXISTS idx_revocation_exp ON revocation(exp);

CREATE TABLE IF NOT EXISTS metrics (
    event_id           BIGSERIAL PRIMARY KEY,
    event_type         VARCHAR(30) NOT NULL CHECK (event_type IN ('token_issued', 'token_refreshed', 'token_revoked', 'auth_error')),
    client_id          VARCHAR(100) REFERENCES clients(clientid) ON DELETE SET NULL,
    userid             VARCHAR(100) REFERENCES users(userid) ON DELETE SET NULL,
    ip_address         VARCHAR(45),
    error_code         VARCHAR(100),
    details            JSONB,
    timestamp          TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics(timestamp);
CREATE INDEX IF NOT EXISTS idx_metrics_type ON metrics(event_type);

INSERT INTO users (userid, username, passwordhash, info) VALUES
(
  'user-001',
  'alice',
  '$2a$10$sO7dWGUxdHb47KqraONVBeXK0vBPowlYFzlSVtOZd7ciZVZC/LMiy',
  '{"first_name": "Alice", "last_name": "Smith", "roles": ["payments:read"]}'
),
(
  'user-002',
  'bob',
  '$2a$10$sO7dWGUxdHb47KqraONVBeXK0vBPowlYFzlSVtOZd7ciZVZC/LMiy',
  '{"first_name": "Bob", "last_name": "Johnson", "roles": ["payments:read", "payments:write"]}'
),
(
  'user-003',
  'charlie',
  '$2a$10$sO7dWGUxdHb47KqraONVBeXK0vBPowlYFzlSVtOZd7ciZVZC/LMiy',
  '{"first_name": "Charlie", "last_name": "Brown", "roles": []}'
)
ON CONFLICT DO NOTHING;

INSERT INTO clients (clientid, clientsecrethash, info)
VALUES
(
    'cli-001',
    '$2a$10$J6uODlvcYcBvzVTZr.6b/unLqyp1QzEBNPWDxtWimii58gSPpVOka',
    '{"app_name": "Web Dashboard Portal", "allowed_scopes": ["payments:read"], "aud": "payments-api"}'
),
(
    'cli-002',
    '$2a$10$J6uODlvcYcBvzVTZr.6b/unLqyp1QzEBNPWDxtWimii58gSPpVOka',
    '{"app_name": "Mobile Payment App", "allowed_scopes": ["payments:read", "payments:write"], "aud": "payments-api"}'
)
ON CONFLICT DO NOTHING;
