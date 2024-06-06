CREATE TABLE account (
    uuid CHAR(36) PRIMARY KEY,
    username VARCHAR(128) NOT NULL,
    user_index VARCHAR(128) NOT NULL,
    password VARCHAR(255) NOT NULL,
    firstname VARCHAR(128) NOT NULL,
    lastname VARCHAR(128) NOT NULL,
    birth_date VARCHAR(128),
    created_at TIMESTAMP NOT NULL,
    enabled BOOLEAN NOT NULL,
    account_expired BOOLEAN NOT NULL,
    account_locked BOOLEAN NOT NULL
);
CREATE UNIQUE INDEX idx_user_blind_index ON account (user_index);
-- scopes table is in Ran Database, call s2s service for data
CREATE TABLE account_scope (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    account_uuid CHAR(36) NOT NULL,
    scope_uuid CHAR(36) NOT NULL,
    created_at TIMESTAMP NOT NULL,
    CONSTRAINT fk_account_scope_xref_id FOREIGN KEY (account_uuid) REFERENCES account (uuid)
);
CREATE INDEX idx_account_scope_xref ON account_scope(account_uuid);
CREATE INDEX idx_scope_account_xref ON account_scope(scope_uuid);
CREATE TABLE refresh (
    uuid CHAR(36) PRIMARY KEY,
    refresh_index VARCHAR(128) NOT NULL,
    service_name VARCHAR(32) NOT NULL,
    refresh_token VARCHAR(128) NOT NULL,
    account_uuid CHAR(36) NOT NULL,
    created_at TIMESTAMP NOT NULL,
    revoked BOOLEAN NOT NULL
);
CREATE UNIQUE INDEX idx_refreshindex ON refresh(refresh_index);
CREATE INDEX idx_refresh_sevice_name ON refresh(service_name);
CREATE TABLE password_history (
    uuid CHAR(36) NOT NULL PRIMARY KEY,
    password VARCHAR(255) NOT NULL,
    updated DATE NOT NULL,
    account_uuid CHAR(36) NOT NULL,
    CONSTRAINT fk_pw_history_account_uuid FOREIGN KEY (account_uuid) REFERENCES account (uuid)
);
CREATE UNIQUE INDEX idx_pw_history_account_uuid ON password_history (account_uuid);
CREATE TABLE authcode (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    auth_code CHAR(36) NOT NULL,
    created_at TIMESTAMP NOT NULL,
    revoked BOOLEAN NOT NULL,
    account_uuid CHAR(36) NOT NULL,
    CONSTRAINT fk_account_authcode_id FOREIGN KEY (account_uuid) REFERENCES account (uuid)
);
CREATE UNIQUE INDEX idx_account_auth_code ON authcode (auth_code);
CREATE TABLE client (
    uuid CHAR(36) NOT NULL PRIMARY KEY,
    client_id CHAR(36) NOT NULL,
    client_name VARCHAR(64) NOT NULL,
    description VARCHAR(255),
    created_at TIMESTAMP NOT NULL,
    enabled BOOLEAN NOT NULL,
    client_expired BOOLEAN NOT NULL,
    client_locked BOOLEAN NOT NULL
);
CREATE UNIQUE INDEX idx_client_clientname ON client(client_name);
CREATE UNIQUE INDEX idx_client_clientid ON client(client_id);
CREATE TABLE redirect (
    uuid CHAR(36) NOT NULL PRIMARY KEY,
    redirect_url CHAR(36) NOT NULL,
    enabled BOOLEAN NOT NULL,
    client_uuid CHAR(36),
    CONSTRAINT fk_redirect_client_uuid FOREIGN KEY (client_uuid) REFERENCES client (uuid)
);
CREATE UNIQUE INDEX idx_redirect ON redirect (redirect_url);
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
CREATE TABLE servicetoken (
    uuid CHAR(36) PRIMARY KEY,
    service_name VARCHAR(32) NOT NULL,
    service_token VARCHAR(2048) NOT NULL,
    service_expires TIMESTAMP NOT NULL,
    refresh_token VARCHAR(128) NOT NULL,
    refresh_expires TIMESTAMP NOT NULL
);
CREATE INDEX idx_servicetoken_servicename ON servicetoken(service_name);
CREATE INDEX idx_servicetoken_refreshexpires ON servicetoken(refresh_expires);