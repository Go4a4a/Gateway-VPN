ALTER TABLE management_resources
ADD COLUMN health_reason_code TEXT NOT NULL DEFAULT ''
    CHECK(length(health_reason_code) <= 64);

ALTER TABLE management_resources
ADD COLUMN last_probe_at TEXT;

ALTER TABLE management_resources
ADD COLUMN last_probe_route_generation INTEGER NOT NULL DEFAULT 0
    CHECK(last_probe_route_generation >= 0);

ALTER TABLE management_resources
ADD COLUMN probe_interface TEXT NOT NULL DEFAULT ''
    CHECK(length(probe_interface) <= 15);

ALTER TABLE management_resources
ADD COLUMN probe_gateway TEXT NOT NULL DEFAULT ''
    CHECK(length(probe_gateway) <= 64);

ALTER TABLE management_resources
ADD COLUMN health_probe_address TEXT NOT NULL DEFAULT ''
    CHECK(length(health_probe_address) <= 64);
