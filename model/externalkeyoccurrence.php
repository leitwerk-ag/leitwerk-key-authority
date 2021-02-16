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
 * They are not managed but supervised by this tool. (New keys are detected and checked if they are allowed)
 */
class ExternalKeyOccurrence extends Record {
	/**
	 * Defines the database table that this object is stored in
	 */
	protected $table = 'external_key_occurrence';

	/**
	 * Defines the field that is the primary key of the table
	 */
	protected $idfield = 'id';

	/**
	 * Insert this new occurrence into the database
	 */
	public function insert() {
		$stmt = $this->database->prepare("
			INSERT INTO external_key_occurrence
			(`key`, server, account_name, comment) VALUES (?, ?, ?, ?)
		");
		$stmt->bind_param("iiss", $this->key, $this->server, $this->account_name, $this->comment);
		$stmt->execute();
		$this->id = $this->database->insert_id;
	}

	/**
	 * Check if this instance represents the same occurrence as the instance $other
	 *
	 * @param ExternalKeyOccurrence $other Instance to compare with
	 * @return bool true if both are equal, false if they are unequal
	 */
	public function equals(ExternalKeyOccurrence $other) {
		return $this->server == $other->server
			&& $this->account_name == $other->account_name
			&& $this->comment == $other->comment;
	}

	/**
	 * Remove this external key occurrence from the database
	 */
	public function delete() {
		$stmt = $this->database->prepare("DELETE FROM external_key_occurrence WHERE id = ?");
		$stmt->bind_param("i", $this->id);
		$stmt->execute();
	}
}
