<?php
##
## Copyright 2021 Leitwerk AG
##
## Licensed under the Apache License, Version 2.0 (the "License");
## you may not use this file except in compliance with the License.
## You may obtain a copy of the License at
##
## http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS,
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.
##

/**
 * External keys are the keys stored in ~/.ssh/authorized_keys on target machines.
 * They are not managed but supervised by this tool. (Detect new keys, check if allowed)
 */
class ExternalKey extends Record {
	/**
	 * Defines the database table that this object is stored in
	 */
	protected $table = 'external_key';

	/**
	 * Defines the field that is the primary key of the table
	 */
	protected $idfield = 'id';

	/**
	 * Array of occurrences (where this key was found)
	 * @var ExternalKeyOccurrence[]
	 */
	public $occurrence;

	/**
	 * Get a list of all keys that are stored in the database.
	 *
	 * @param bool $with_hostnames If true, occurrences are fetched with hostnames
	 * @return array An array of ExternalKey objects
	 */
	public static function list_external_keys($with_hostnames = false) {
		global $database;

		// load the keys
		$result = $database->query("SELECT * FROM external_key");
		$keys = [];
		$keys_assoc = [];
		while ($row = $result->fetch_assoc()) {
			$key = new ExternalKey($row['id'], $row);
			$key->occurrence = [];
			$keys[] = $key;
			$keys_assoc[$row['id']] = $key;
		}

		// load key occurrences
		$join = "";
		if ($with_hostnames) {
			$join = " LEFT JOIN server ON external_key_occurrence.server = server.id";
		}
		$result = $database->query(" SELECT * FROM external_key_occurrence{$join}");
		while ($row = $result->fetch_assoc()) {
			$external_key = $keys_assoc[$row['key']];
			$attributes = [
				'key' => $row['key'],
				'server' => $row['server'],
				'account_name' => $row['account_name'],
				'comment' => $row['comment'],
				'appeared' => $row['appeared'],
			];
			if ($with_hostnames) {
				$attributes['hostname'] = $row['hostname'];
			}
			$external_key->occurrence[] = new ExternalKeyOccurrence($row['id'], $attributes);
		}

		return $keys;
	}

	/**
	 * Load a specific external key, but without the corresponding occurrences.
	 *
	 * @param int $id Database id of the key to load
	 * @return ExternalKey|null The loaded key, or null if there was no key with this id
	 */
	public static function get_by_id(int $id) {
		global $database;
		$stmt = $database->prepare("SELECT * FROM external_key WHERE id = ?");
		$stmt->bind_param("i", $id);
		$stmt->execute();
		$result = $stmt->get_result();
		if ($row = $result->fetch_assoc()) {
			return new ExternalKey($row['id'], $row);
		}
	}

	/**
	 * Update the occurencess of this key in the database (insert new entries, delete missing entries)
	 *
	 * @param ExternalKeyOccurrence[] $new_occurrences The current occurrences used for update 
	 */
	public function update_occurrences(array $new_occurrences) {
		// Remove entries from the database
		$this->occurrence = array_filter($this->occurrence, function($occurrence) use($new_occurrences) {
			$existing = false;
			foreach ($new_occurrences as $new_occurrence) {
				if ($occurrence->equals($new_occurrence)) {
					$existing = true;
					break;
				}
			}
			if (!$existing) {
				$occurrence->delete();
			}
			return $existing;
		});

		// Insert new entries that are not in the database yet
		foreach ($new_occurrences as $new_occurrence) {
			$in_db = false;
			foreach ($this->occurrence as $db_occurrence) {
				if ($new_occurrence->equals($db_occurrence)) {
					$in_db = true;
					break;
				}
			}
			if (!$in_db) {
				$new_occurrence->key = $this->id;
				$new_occurrence->insert();
				$this->occurrence[] = $new_occurrence;
			}
		}
	}

	/**
	 * Insert this new key into the database
	 */
	public function insert() {
		$stmt = $this->database->prepare("
			INSERT INTO external_key
			(type, keydata) VALUES (?, ?)
		");
		$stmt->bind_param("ss", $this->type, $this->keydata);
		$stmt->execute();
		$this->id = $stmt->insert_id;

		foreach ($this->occurrence as $occurrence) {
			$occurrence->key = $this->id;
			$occurrence->insert();
		}
	}

	/**
	 * Remove this external key from the database
	 */
	public function delete() {
		// Key occurrences are automatically deleted, because of 'ON DELETE CASCADE'
		$stmt = $this->database->prepare("DELETE FROM external_key WHERE id = ?");
		$stmt->bind_param("i", $this->id);
		$stmt->execute();
	}
}
