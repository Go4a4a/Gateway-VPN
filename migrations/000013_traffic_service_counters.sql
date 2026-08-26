ALTER TABLE traffic_daily_totals
ADD COLUMN service_download_bytes INTEGER NOT NULL DEFAULT 0;

ALTER TABLE traffic_daily_totals
ADD COLUMN service_upload_bytes INTEGER NOT NULL DEFAULT 0;
