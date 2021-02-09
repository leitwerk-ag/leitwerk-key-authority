<?php
$migration_name = 'Add an execution_time for sync_request';

$this->database->query("
ALTER TABLE sync_request
ADD execution_time datetime NULL;
");
