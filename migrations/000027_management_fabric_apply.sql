-- Host application is a separate root transaction.  Keep its last committed
-- generation distinct from the desired generation so WebUI and recovery never
-- infer kernel state merely from an unprivileged database mutation.

ALTER TABLE management_fabric_generations
ADD COLUMN applied_generation INTEGER NOT NULL DEFAULT 0
    CHECK(applied_generation >= 0);

ALTER TABLE management_fabric_generations
ADD COLUMN last_error_code TEXT NOT NULL DEFAULT '';
