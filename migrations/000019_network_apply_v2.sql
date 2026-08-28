ALTER TABLE network_apply_transactions
ADD COLUMN manifest_schema INTEGER NOT NULL DEFAULT 1
    CHECK(manifest_schema IN (1, 2));

ALTER TABLE network_apply_transactions
ADD COLUMN operation_kind TEXT NOT NULL DEFAULT 'LAN_ADDRESS'
    CHECK(operation_kind IN ('LAN_ADDRESS', 'ETHERNET_UPLINK'));

ALTER TABLE network_apply_transactions
ADD COLUMN candidate_json TEXT NOT NULL DEFAULT '{}';

CREATE INDEX network_apply_operation_history
ON network_apply_transactions(operation_kind, created_at DESC);
