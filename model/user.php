<?php
##
## Copyright 2013-2017 Opera Software AS
## Modifications Copyright 2021 Leitwerk AG
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
* Class that represents a user of this system
*/
class User extends Entity {
	/**
	* Defines the database table that this object is stored in
	*/
	protected $table = 'user';
	/**
	* Defines the field that is the primary key of the table
	*/
	protected $idfield = 'entity_id';
	/**
	* LDAP connection object
	*/
	private $ldap;
	/**
	 * Group guid's, this user is member of (will be set by get_details_from_ldap())
	 */
	private $ldap_group_guids;

	public function __construct($id = null, $preload_data = array()) {
		parent::__construct($id, $preload_data);
		global $ldap;
		$this->ldap = $ldap;
	}

	/**
	* Write property changes to database and log the changes.
	* Triggers a resync if the user was activated/deactivated.
	*/
	public function update() {
		$changes = parent::update();
		$resync = false;
		foreach($changes as $change) {
			$loglevel = LOG_INFO;
			switch($change->field) {
			case 'active':
				$resync = true;
				if($change->new_value == 1) $loglevel = LOG_WARNING;
				break;
			case 'admin':
				if($change->new_value == 1) $loglevel = LOG_WARNING;
				break;
			case 'csrf_token':
			case 'superior_entity_id':
				return;
			}
			$this->log(array('action' => 'Setting update', 'value' => $change->new_value, 'oldvalue' => $change->old_value, 'field' => ucfirst(str_replace('_', ' ', $change->field))), $loglevel);
		}
		if($resync) {
			$this->sync_remote_access();
		}
	}

	/**
	* Magic getter method - if superior field requested, return User object of user's superior
	* @param string $field to retrieve
	* @return mixed data stored in field
	*/
	public function &__get($field) {
		global $user_dir;
		switch($field) {
		case 'superior':
			if(is_null($this->superior_entity_id)) $superior = null;
			else $superior = new User($this->superior_entity_id);
			return $superior;
		default:
			return parent::__get($field);
		}
	}

	/**
	* List all events on entities and servers that this user has management access to
	* @param array $include list of extra data to include in response
	* @return array of *Event objects
	*/
	public function list_events($include = array()) {
		global $event_dir;
		if(is_null($this->entity_id)) throw new BadMethodCallException('User must be in directory before events can be listed');
		return $event_dir->list_events($include, array('admin' => $this->entity_id));
	}

	/**
	* List all servers that are managed by this user
	* @param array $include list of extra data to include in response
	* @return array of Server objects
	*/
	public function list_admined_servers($include = array()) {
		global $server_dir;
		if(is_null($this->entity_id)) throw new BadMethodCallException('User must be in directory before admined servers can be listed');
		return $server_dir->list_servers($include, array('admin' => $this->entity_id, 'key_management' => array('none', 'keys', 'other')));
	}

	/**
	* List all groups that are administrated by this user
	* @param array $include list of extra data to include in response
	* @return array of Group objects
	*/
	public function list_admined_groups($include = array()) {
		global $group_dir;
		if(is_null($this->entity_id)) throw new BadMethodCallException('User must be in directory before admined group can be listed');
		$groups = $group_dir->list_groups($include, array('admin' => $this->entity_id));
		return $groups;
	}

	/**
	* List all groups that this user is a member of
	* @param array $include list of extra data to include in response
	* @return array of Group objects
	*/
	public function list_group_memberships($include = array()) {
		global $group_dir;
		if(is_null($this->entity_id)) throw new BadMethodCallException('User must be in directory before group memberships can be listed');
		$groups = $group_dir->list_groups($include, array('member' => $this->entity_id));
		return $groups;
	}

	/**
	* Determine if this user is a leader of the specified entity or server.
	* @param Record $record object to check for management privileges
	* @return bool true if user is a leader of the object
	* @throws InvalidArgumentException if a non-managable Record is provided
	*/
	public function admin_of(Record $record) {
		switch(get_class($record)) {
		case 'Server':
			$stmt = $this->database->prepare("
				SELECT entity_id
				FROM group_member
				WHERE  (`group` IN (
						SELECT entity_id
						FROM server_admin
						WHERE server_id = ?)
					AND entity_id = ?)
				UNION  (SELECT entity_id
					FROM server_admin
					WHERE server_id = ?
					AND entity_id = ?)");
			$stmt->bind_param('dddd', $record->id, $this->entity_id, $record->id, $this->entity_id);
			$stmt->execute();
			$result = $stmt->get_result();
			return $result->num_rows >= 1;
			break;
		case 'Group':
		case 'ServerAccount':
			$stmt = $this->database->prepare("SELECT * FROM entity_admin WHERE admin = ? AND entity_id = ?");
			$stmt->bind_param('dd', $this->entity_id, $record->entity_id);
			$stmt->execute();
			$result = $stmt->get_result();
			return $result->num_rows >= 1;
			break;
		default:
			throw new InvalidArgumentException('Records of type '.get_class($record).' cannot be administered');
		}
	}

	/**
	* Determine if this user is a member of the specified group
	* @param Group $group to check membership of
	* @return bool true if user is an member of the group
	*/
	public function member_of(Group $group) {
		$stmt = $this->database->prepare("SELECT * FROM group_member WHERE entity_id = ? AND `group` = ?");
		$stmt->bind_param('dd', $this->entity_id, $group->entity_id);
		$stmt->execute();
		$result = $stmt->get_result();
		return $result->num_rows >= 1;
	}

	/**
	* Add a public key to this user for use with any outbound access rules that apply to them.
	* An email is sent to the user and sec-ops to inform them of the change.
	* This action is logged with a warning level as it is potentially granting SSH access with the key.
	* @param PublicKey $key to be added
	*/
	public function add_public_key(PublicKey $key) {
		global $active_user, $config;
		parent::add_public_key($key);
		$url = $config['web']['baseurl'].'/pubkeys/'.urlencode($key->id);
		$email = new Email;
		$email->add_reply_to($config['email']['admin_address'], $config['email']['admin_name']);
		$email->add_recipient($this->email, $this->name);
		$email->add_cc($config['email']['report_address'], $config['email']['report_name']);
		$email->subject = "A new SSH public key has been added to your account ({$this->uid})";
		$email->body = "A new SSH public key has been added to your account on Leitwerk Key Authority.\n\nIf you added this key then all is well. If you do not recall adding this key, please contact {$config['email']['admin_address']} immediately.\n\n".$key->summarize_key_information();
		$email->send();
		$this->log(array('action' => 'Pubkey add', 'value' => $key->fingerprint_md5), LOG_WARNING);
	}

	/**
	* Delete the specified public key from this user.
	* @param PublicKey $key to be removed
	*/
	public function delete_public_key(PublicKey $key) {
		global $active_user;
		parent::delete_public_key($key);
		$this->log(array('action' => 'Pubkey remove', 'value' => $key->fingerprint_md5));
	}

	/**
	* Add an alert to be displayed to this user on their next normal page load.
	* @param UserAlert $alert to be displayed
	*/
	public function add_alert(UserAlert $alert) {
		if(is_null($this->entity_id)) throw new BadMethodCallException('User must be in directory before alerts can be added');
		$stmt = $this->database->prepare("INSERT INTO user_alert SET entity_id = ?, class = ?, content = ?, escaping = ?");
		$stmt->bind_param('dssd', $this->entity_id, $alert->class, $alert->content, $alert->escaping);
		$stmt->execute();
		$alert->id = $stmt->insert_id;
		$stmt->close();
	}

	/**
	* List all alerts for this user *and* delete them.
	* @return array of UserAlert objects
	*/
	public function pop_alerts() {
		if(is_null($this->entity_id)) throw new BadMethodCallException('User must be in directory before alerts can be listed');
		$stmt = $this->database->prepare("SELECT * FROM user_alert WHERE entity_id = ?");
		$stmt->bind_param('d', $this->entity_id);
		$stmt->execute();
		$result = $stmt->get_result();
		$alerts = array();
		$alert_ids = array();
		while($row = $result->fetch_assoc()) {
			$alerts[] = new UserAlert($row['id'], $row);
			$alert_ids[] = $row['id'];
		}
		$stmt->close();
		if(count($alert_ids) > 0) {
			$this->database->query("DELETE FROM user_alert WHERE id IN (".implode(", ", $alert_ids).")");
		}
		return $alerts;
	}

	/**
	* Determine if this user has been granted access to the specified account.
	* @param ServerAccount $account to check for access
	* @return bool true if user has access to the account
	*/
	public function has_access(ServerAccount $account) {
		if(is_null($this->entity_id)) throw new BadMethodCallException('User must be in directory before access can be checked');
		$stmt = $this->database->prepare("SELECT * FROM access WHERE source_entity_id = ? AND dest_entity_id = ?");
		$stmt->bind_param('dd', $this->entity_id, $account->entity_id);
		$stmt->execute();
		$result = $stmt->get_result();
		return (bool)$result->fetch_assoc();
	}

	/**
	* Return HTML containing the user's CSRF token for inclusion in a POST form.
	* Also includes a random string of the same length to help guard against http://breachattack.com/
	* @return string HTML
	*/
	public function get_csrf_field() {
		return '<input type="hidden" name="csrf_token" value="'.hesc($this->get_csrf_token()).'"><!-- '.hash("sha512", mt_rand(0, mt_getrandmax())).' -->'."\n";
	}

	/**
	* Return the user's CSRF token. Generate one if they do not yet have one.
	* @return string CSRF token
	*/
	public function get_csrf_token() {
		if(is_null($this->entity_id)) throw new BadMethodCallException('User must be in directory before CSRF token can be generated');
		if(!isset($this->data['csrf_token'])) {
			$this->data['csrf_token'] = hash("sha512", mt_rand(0, mt_getrandmax()));
			$this->update();
		}
		return $this->data['csrf_token'];
	}

	/**
	* Check the given string against the user's CSRF token.
	* @return bool true on string match
	*/
	public function check_csrf_token($token) {
		return $token === $this->get_csrf_token();
	}

	/**
	* Retrieve the user's details from LDAP.
	* @throws UserNotFoundException if the user is not found in LDAP
	*/
	public function get_details_from_ldap() {
		global $config;
		$attributes = array();
		$attributes[] = 'dn';
		$attributes[] = $config['ldap']['user_id'];
		$attributes[] = $config['ldap']['user_name'];
		$attributes[] = $config['ldap']['user_email'];
		$attributes[] = $config['ldap']['group_member_value'];
		if(isset($config['ldap']['user_active'])) {
			$attributes[] = $config['ldap']['user_active'];
		}
		$ldapusers = $this->ldap->search($config['ldap']['dn_user'], LDAP::escape($config['ldap']['user_id']).'='.LDAP::escape($this->uid), array_keys(array_flip($attributes)));
		if($ldapuser = reset($ldapusers)) {
			$this->auth_realm = 'LDAP';
			$this->uid = $ldapuser[strtolower($config['ldap']['user_id'])];
			$this->name = $ldapuser[strtolower($config['ldap']['user_name'])];
			$this->email = $ldapuser[strtolower($config['ldap']['user_email'])];
			if(isset($config['ldap']['user_active'])) {
				$this->active = 0;
				if(isset($config['ldap']['user_active_true'])) {
					$this->active = intval($ldapuser[strtolower($config['ldap']['user_active'])] == $config['ldap']['user_active_true']);
				} elseif(isset($config['ldap']['user_active_false'])) {
					$this->active = intval($ldapuser[strtolower($config['ldap']['user_active'])] != $config['ldap']['user_active_false']);
				} elseif (isset($config['ldap']['user_active_bitmask'])) {
					// Microsoft Active Directory uses bitflags to store if a user is active
					// https://docs.microsoft.com/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties
					if (preg_match('/^(!?)([0-9]+)$/', $config['ldap']['user_active_bitmask'], $groups)) {
						$negated = $groups[1] == "!";
						$mask = (int)$groups[2];
						$bit_set = ((int)$ldapuser[strtolower($config['ldap']['user_active'])] & $mask) != 0;
						$this->active = (int)($bit_set ^ $negated);
					}
				}
			} else {
				$this->active = 1;
			}
			$this->admin = 0;
			$group_member = $ldapuser[strtolower($config['ldap']['group_member_value'])];
			$indirect_option = "";
			if ($config['ldap']['indirect_group_memberships']) {
				$indirect_option = ":1.2.840.113556.1.4.1941:";
			}
			$ldapgroups = $this->ldap->search($config['ldap']['dn_group'], LDAP::escape($config['ldap']['group_member'])."$indirect_option=".LDAP::escape($group_member), array('cn', strtolower($config['ldap']['group_num'])));
			$ldap_group_guids = [];
			foreach($ldapgroups as $ldapgroup) {
				$ldap_group_guids[] = $ldapgroup[strtolower($config['ldap']['group_num'])];
				if($ldapgroup['cn'] == $config['ldap']['admin_group_cn']) $this->admin = 1;
			}
			$this->ldap_group_guids = $ldap_group_guids;
		} else {
			throw new UserNotFoundException('User does not exist.');
		}
	}

	/**
	 * Get the group ObjectGUIDs, this user is member of. Fetch them via ldap, if not already done.
	 *
	 * @return string[] guids of the groups this user is member of
	 */
	public function get_ldap_group_guids() {
		global $config;
		if ($this->ldap_group_guids === null) {
			$this->get_details_from_ldap();
		}
		return $this->ldap_group_guids;
	}

	/**
	 * Adds the user to ldap groups or removes him from ldap groups, based on the current status on the directory server.
	 */
	public function update_group_memberships() {
		global $group_dir;
		foreach ($group_dir->get_sys_groups() as $sys_group) {
			$should_be_member = $this->active && in_array($sys_group->ldap_guid, $this->get_ldap_group_guids());
			if ($should_be_member && !$this->member_of($sys_group)) {
				// Use the keys-sync user as actor, because this is an automatic process
				$sys_group->add_member($this, User::get_keys_sync_user());
			}
			if (!$should_be_member && $this->member_of($sys_group)) {
				$sys_group->delete_member($this);
			}
		}
	}

	/**
	* Retrieve the user's superior from LDAP.
	* @throws UserNotFoundException if the user is not found in LDAP
	*/
	public function get_superior_from_ldap() {
		global $user_dir, $config;
		if(is_null($this->entity_id)) throw new BadMethodCallException('User must be in directory before superior employee can be looked up');
		if(!isset($config['ldap']['user_superior'])) {
			throw new BadMethodCallException("Cannot retrieve user's superior if user_superior is not configured");
		}
		$ldapusers = $this->ldap->search($config['ldap']['dn_user'], LDAP::escape($config['ldap']['user_id']).'='.LDAP::escape($this->uid), array($config['ldap']['user_superior']));
		if($ldapuser = reset($ldapusers)) {
			$superior = null;
			if(isset($ldapuser[strtolower($config['ldap']['user_superior'])]) && $ldapuser[strtolower($config['ldap']['user_superior'])] != $this->uid) {
				$superior_uid = $ldapuser[strtolower($config['ldap']['user_superior'])];
				try {
					$superior = $user_dir->get_user_by_uid($superior_uid);
				} catch(UserNotFoundException $e) {
				}
			}
			if(is_null($superior)) {
				$this->superior_entity_id = null;
			} else {
				$this->superior_entity_id = $superior->entity_id;
			}
			$this->update();
		} else {
			throw new UserNotFoundException('User does not exist.');
		}
	}

	/**
	 * The keys-sync user is used internally to do regular tasks (ldap update, rollout of keys)
	 * This function returns an instance of this keys-sync user.
	 * If the user does not exist yet, it will be created.
	 *
	 * @return User An instance of the keys-sync user
	 */
	public static function get_keys_sync_user() {
		global $user_dir;
		try {
			$keys_sync = $user_dir->get_user_by_uid('keys-sync');
		} catch(UserNotFoundException $e) {
			$keys_sync = new User;
			$keys_sync->uid = 'keys-sync';
			$keys_sync->name = 'Synchronization script';
			$keys_sync->email = '';
			$keys_sync->active = 1;
			$keys_sync->admin = 1;
			$keys_sync->developer = 0;
			$user_dir->add_user($keys_sync);
		}
		return $keys_sync;
	}

	/**
	* Implements the Entity::sync_access as a no-op as it makes no sense to grant access TO a user.
	*/
	public function sync_access() {
	}

	/**
	 * Find all server accounts that this user has directly or indirectly been allowed to access.
	 *
	 * @return array List of ServerAccount objects
	 */
	public function find_accessible_server_accounts(): array {
		// Put this user and groups where he is a member into one array
		$sources = array_merge([$this], $this->list_group_memberships());

		// Find all granted accesses of this user or its groups
		$accesses = [];
		foreach ($sources as $source) {
			$accesses = array_merge($accesses, $source->list_remote_access());
		}

		// Collect access target (that can be server accounts and other groups)
		$targets = array_map(function($access) {
			return $access->dest_entity;
		}, $accesses);

		// Expand targets to the final account list (get members of the groups)
		$target_accounts = [];
		foreach ($targets as $target) {
			switch (get_class($target)) {
				case 'ServerAccount':
					$target_accounts[] = $target;
					break;
				case 'Group':
					$members = $target->list_members();
					$member_accounts = array_filter($members, function($member) {
						return $member instanceof ServerAccount;
					});
					$target_accounts = array_merge($target_accounts, $member_accounts);
					break;
				default:
					throw new Exception("One accessible entity is neither a ServerAccount nor aGroup.");
			}
		}

		// Filter out inactive accounts
		$target_accounts = array_filter($target_accounts, function($account) {
			return $account->server->key_management != 'decommissioned';
		});

		return $target_accounts;
	}
}
