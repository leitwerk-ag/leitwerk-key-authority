<?php
$migration_name = 'Add key_scan setting for servers';

$this->database->query("
ALTER TABLE `server`
ADD `key_scan` enum('full','rootonly','off') NOT NULL DEFAULT 'full' AFTER `authorization`;
");
