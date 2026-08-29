-- Complete the optional user/data-plane WireGuard server without placing any
-- private key material in SQLite.  Versioned secret files remain the only
-- source for server and managed-peer private keys.
ALTER TABLE wireguard_ingress_servers ADD COLUMN public_key TEXT NOT NULL DEFAULT '';
ALTER TABLE wireguard_ingress_servers ADD COLUMN config_generation INTEGER NOT NULL DEFAULT 1
    CHECK(config_generation > 0);

ALTER TABLE wireguard_ingress_peers ADD COLUMN client_dns_enabled INTEGER NOT NULL DEFAULT 1
    CHECK(client_dns_enabled IN (0, 1));
ALTER TABLE wireguard_ingress_peers ADD COLUMN allow_whitelist_only INTEGER NOT NULL DEFAULT 1
    CHECK(allow_whitelist_only IN (0, 1));
ALTER TABLE wireguard_ingress_peers ADD COLUMN block_when_unqualified INTEGER NOT NULL DEFAULT 1
    CHECK(block_when_unqualified IN (0, 1));

CREATE TABLE wireguard_ingress_server_dns (
    server_id TEXT NOT NULL,
    address TEXT NOT NULL,
    priority INTEGER NOT NULL CHECK(priority > 0),
    PRIMARY KEY(server_id, address),
    UNIQUE(server_id, priority),
    FOREIGN KEY(server_id) REFERENCES wireguard_ingress_servers(id) ON DELETE CASCADE
);

CREATE TABLE wireguard_ingress_listen_interfaces (
    server_id TEXT NOT NULL,
    network_interface_id TEXT NOT NULL,
    exposure_mode TEXT NOT NULL DEFAULT 'LOCAL'
        CHECK(exposure_mode IN ('LOCAL', 'PUBLIC')),
    priority INTEGER NOT NULL CHECK(priority > 0),
    PRIMARY KEY(server_id, network_interface_id),
    UNIQUE(server_id, priority),
    FOREIGN KEY(server_id) REFERENCES wireguard_ingress_servers(id) ON DELETE CASCADE,
    FOREIGN KEY(network_interface_id) REFERENCES network_interfaces(id) ON DELETE RESTRICT
);

CREATE TABLE wireguard_ingress_peer_client_allowed_ips (
    peer_id TEXT NOT NULL,
    cidr TEXT NOT NULL,
    priority INTEGER NOT NULL CHECK(priority > 0),
    PRIMARY KEY(peer_id, cidr),
    UNIQUE(peer_id, priority),
    FOREIGN KEY(peer_id) REFERENCES wireguard_ingress_peers(id) ON DELETE CASCADE
);

CREATE TABLE wireguard_ingress_peer_access_methods (
    peer_id TEXT NOT NULL,
    access_method_id TEXT NOT NULL,
    priority INTEGER NOT NULL CHECK(priority > 0),
    PRIMARY KEY(peer_id, access_method_id),
    UNIQUE(peer_id, priority),
    FOREIGN KEY(peer_id) REFERENCES wireguard_ingress_peers(id) ON DELETE CASCADE,
    FOREIGN KEY(access_method_id) REFERENCES access_methods(id) ON DELETE RESTRICT
);

CREATE TABLE wireguard_ingress_counters (
    singleton_id INTEGER PRIMARY KEY CHECK(singleton_id=1),
    next_peer_number INTEGER NOT NULL CHECK(next_peer_number > 0)
);

INSERT INTO wireguard_ingress_counters(singleton_id, next_peer_number)
VALUES (
    1,
    COALESCE((SELECT MAX(display_number)+1 FROM wireguard_ingress_peers), 1)
);

CREATE INDEX idx_wireguard_ingress_peers_server_state
    ON wireguard_ingress_peers(server_id, enabled, revoked_at, display_number);
CREATE INDEX idx_wireguard_ingress_runtime_state
    ON wireguard_ingress_runtime(state, desired_generation, applied_generation);
