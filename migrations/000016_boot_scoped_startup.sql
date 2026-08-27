ALTER TABLE access_selection_runtime ADD COLUMN observed_boot_id TEXT
    CHECK(observed_boot_id IS NULL OR length(observed_boot_id) BETWEEN 1 AND 64);
