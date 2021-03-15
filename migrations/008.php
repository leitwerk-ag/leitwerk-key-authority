<?php
$migration_name = 'Add an execution_time for sync_request';

$this->database->query("
ALTER TABLE `server`
DROP `rsa_key_fingerprint`,
ADD `host_key` varchar(2000) NULL,
ADD `jumphosts` varchar(1000) NOT NULL AFTER `port`;
");
