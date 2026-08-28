CREATE UNIQUE INDEX operations_one_active_system_power
ON operations(kind)
WHERE kind='SYSTEM_POWER' AND status IN ('QUEUED', 'RUNNING');
