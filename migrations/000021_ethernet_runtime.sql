ALTER TABLE uplinks
ADD COLUMN readiness_reason TEXT NOT NULL DEFAULT 'NOT_OBSERVED';

-- Runtime DHCP observations must not overwrite the configuration which the
-- user expects networkd to recreate after a NIC replacement or reboot.
ALTER TABLE uplinks
ADD COLUMN configured_ipv4_cidr TEXT;

ALTER TABLE uplinks
ADD COLUMN configured_gateway TEXT;

ALTER TABLE uplinks
ADD COLUMN configured_dns_json TEXT NOT NULL DEFAULT '[]';

UPDATE uplinks
SET configured_ipv4_cidr=CASE WHEN address_mode='STATIC' THEN ipv4_cidr END,
    configured_gateway=CASE WHEN address_mode='STATIC' THEN gateway END,
    configured_dns_json=dns_json;

UPDATE uplinks
SET readiness_reason=CASE
    WHEN enabled=0 THEN 'DISABLED_BY_USER'
    WHEN state='UPLINK_READY' THEN 'READY'
    WHEN state='UPLINK_SUBNET_CONFLICT' THEN 'SUBNET_CONFLICT'
    ELSE 'NOT_OBSERVED'
END;

CREATE INDEX uplinks_runtime_state
ON uplinks(type, enabled, state, priority, readiness_reason);

-- The bounded legacy modem bridge continues to write HiLink state through
-- uplinks. Keep the generic reason projection coherent for both future inserts
-- and state transitions without letting this trigger touch Ethernet reasons.
CREATE TRIGGER uplinks_hilink_readiness_insert
AFTER INSERT ON uplinks
WHEN NEW.type='HILINK'
BEGIN
    UPDATE uplinks
    SET readiness_reason=CASE
        WHEN NEW.enabled=0 THEN 'DISABLED_BY_USER'
        WHEN NEW.state='UPLINK_READY' THEN 'READY'
        ELSE 'NOT_OBSERVED'
    END
    WHERE id=NEW.id;
END;

CREATE TRIGGER uplinks_hilink_readiness_update
AFTER UPDATE OF enabled, state ON uplinks
WHEN NEW.type='HILINK'
BEGIN
    UPDATE uplinks
    SET readiness_reason=CASE
        WHEN NEW.enabled=0 THEN 'DISABLED_BY_USER'
        WHEN NEW.state='UPLINK_READY' THEN 'READY'
        ELSE 'NOT_OBSERVED'
    END
    WHERE id=NEW.id;
END;
