CREATE UNIQUE INDEX operations_one_active_system_uninstall
ON operations(kind)
WHERE kind='SYSTEM_UNINSTALL' AND status IN ('QUEUED', 'RUNNING');
