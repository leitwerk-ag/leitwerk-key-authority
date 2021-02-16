<?php
$migration_name = 'Add tables for external key superivsion';

$this->database->query("
CREATE TABLE `external_key` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `status` enum('new','allowed','denied') NOT NULL DEFAULT 'new',
  `type` varchar(30) NOT NULL,
  `keydata` mediumtext NOT NULL
);
");

$this->database->query("
CREATE TABLE `external_key_occurrence` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `key` int(10) unsigned NOT NULL,
  `server` int(10) unsigned NOT NULL,
  `account_name` varchar(50) NOT NULL,
  `comment` mediumtext NOT NULL,
  `appeared` datetime NOT NULL DEFAULT NOW(),
  FOREIGN KEY (`key`) REFERENCES `external_key` (`id`) ON DELETE CASCADE,
  FOREIGN KEY (`server`) REFERENCES `server` (`id`) ON DELETE CASCADE
);
");

$this->database->query("
ALTER TABLE `server`
ADD `key_supervision_error` mediumtext NULL;
");
