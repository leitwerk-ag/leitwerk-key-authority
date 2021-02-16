<?php
$migration_name = 'Add a column for the creation date of ssh keys';

$this->database->query("
ALTER TABLE `public_key`
ADD `creation_date` date NULL DEFAULT CURDATE() AFTER `entity_id`,
ADD `deletion_date` date NULL
");
