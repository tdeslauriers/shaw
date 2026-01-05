-- Account table
CREATE TABLE account (
    uuid CHAR(36) PRIMARY KEY,
    username VARCHAR(128) NOT NULL,
    user_index VARCHAR(128) NOT NULL,
    password VARCHAR(255) NOT NULL,
    legacy BOOLEAN NOT NULL DEFAULT TRUE,
    firstname VARCHAR(128) NOT NULL,
    lastname VARCHAR(128) NOT NULL,
    birth_date VARCHAR(128),
    slug VARCHAR(128) NOT NULL,
    slug_index VARCHAR(128) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT UTC_TIMESTAMP,
    enabled BOOLEAN NOT NULL,
    account_expired BOOLEAN NOT NULL,
    account_locked BOOLEAN NOT NULL
);
CREATE UNIQUE INDEX idx_user_blind_index ON account (user_index);
CREATE UNIQUE iNDEX idx_slug_index ON account (slug_index);

-- scopes table is in Ran Database, call s2s service for data
-- account scope xref table
CREATE TABLE account_scope (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    account_uuid CHAR(36) NOT NULL,
    scope_uuid CHAR(36) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT UTC_TIMESTAMP,
    CONSTRAINT fk_account_scope_xref_id FOREIGN KEY (account_uuid) REFERENCES account (uuid)
);
CREATE INDEX idx_account_scope_xref ON account_scope(account_uuid);
CREATE INDEX idx_scope_account_xref ON account_scope(scope_uuid);

-- refresh token table
CREATE TABLE refresh (
    uuid CHAR(36) PRIMARY KEY,
    refresh_index VARCHAR(128) NOT NULL,
    client_id VARCHAR(128) NOT NULL,
    refresh_token VARCHAR(128) NOT NULL,
    username VARCHAR(128) NOT NULL,
    username_index VARCHAR(128) NOT NULL,
    scopes VARCHAR(1024) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT UTC_TIMESTAMP,
    revoked BOOLEAN NOT NULL
);
CREATE UNIQUE INDEX idx_refresh_index ON refresh(refresh_index);
CREATE INDEX idx_refresh_username ON refresh(username_index);

-- password history table
CREATE TABLE password_history (
    uuid CHAR(36) NOT NULL PRIMARY KEY,
    password VARCHAR(255) NOT NULL,
    legacy BOOLEAN NOT NULL DEFAULT TRUE,
    updated TIMESTAMP NOT NULL DEFAULT UTC_TIMESTAMP,
    account_uuid CHAR(36) NOT NULL,
    CONSTRAINT fk_pw_history_account_uuid FOREIGN KEY (account_uuid) REFERENCES account (uuid)
);
CREATE INDEX idx_pw_history_account_uuid ON password_history (account_uuid);

-- auth code table
CREATE TABLE authcode (
    uuid CHAR(36) PRIMARY KEY,
    authcode_index VARCHAR(128) NOT NULL,
    authcode VARCHAR(128) NOT NULL,
    nonce VARCHAR(128) NOT NULL,
    client_uuid VARCHAR(128) NOT NULL,
    redirect_url VARCHAR(2048) NOT NULL,
    scopes VARCHAR(1024) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT UTC_TIMESTAMP,
    claimed BOOLEAN NOT NULL,
    revoked BOOLEAN NOT NULL
);
CREATE UNIQUE INDEX idx_authcode ON authcode(auth_code);

-- auth code account xref table
CREATE TABLE authcode_account (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    authcode_uuid CHAR(36) NOT NULL,
    account_uuid CHAR(36) NOT NULL,
    created_at TIMESTAMP NOT NULL,
    CONSTRAINT fk_authcode_account_xref_id FOREIGN KEY (account_uuid) REFERENCES account (uuid),
    CONSTRAINT fk_account_authcode_xref_id FOREIGN KEY (authcode_uuid) REFERENCES authcode (uuid)
);
CREATE INDEX idx_authcode_account_xref ON authcode_account(authcode_uuid);

-- client table
CREATE TABLE client (
    uuid CHAR(36) NOT NULL PRIMARY KEY,
    client_id CHAR(36) NOT NULL,
    client_name VARCHAR(64) NOT NULL,
    description VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT UTC_TIMESTAMP,
    enabled BOOLEAN NOT NULL,
    client_expired BOOLEAN NOT NULL,
    client_locked BOOLEAN NOT NULL
);
CREATE UNIQUE INDEX idx_client_clientname ON client(client_name);
CREATE UNIQUE INDEX idx_client_clientid ON client(client_id);

-- redirect table
CREATE TABLE redirect (
    uuid CHAR(36) NOT NULL PRIMARY KEY,
    redirect_url VARCHAR(2048) NOT NULL,
    enabled BOOLEAN NOT NULL,
    client_uuid CHAR(36),
    CONSTRAINT fk_redirect_client_uuid FOREIGN KEY (client_uuid) REFERENCES client (uuid)
);
CREATE UNIQUE INDEX idx_redirect ON redirect (redirect_url);

-- client scope xref table
CREATE TABLE account_client (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    account_uuid CHAR(36) NOT NULL,
    client_uuid CHAR(36) NOT NULL,
    created_at TIMESTAMP NOT NULL,
    CONSTRAINT fk_account_client_xref_id FOREIGN KEY (account_uuid) REFERENCES account (uuid),
    CONSTRAINT fk_client_account_xref_id FOREIGN KEY (client_uuid) REFERENCES client (uuid)
);
CREATE INDEX idx_account_client_xref ON account_client(account_uuid);
CREATE INDEX idx_client_account_xref ON account_client(client_uuid);

-- service token table
CREATE TABLE servicetoken (
    uuid CHAR(36) PRIMARY KEY,
    service_name VARCHAR(32) NOT NULL,
    service_token VARCHAR(2048) NOT NULL DEFAULT UTC_TIMESTAMP,
    service_expires TIMESTAMP NOT NULL,
    refresh_token VARCHAR(128) NOT NULL,
    refresh_expires TIMESTAMP NOT NULL DEFAULT UTC_TIMESTAMP
);
CREATE INDEX idx_servicetoken_servicename ON servicetoken(service_name);
CREATE INDEX idx_servicetoken_refreshexpires ON servicetoken(refresh_expires);