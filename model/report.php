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
 * Data class describing the result of a permissions report, ready for rendering into html
 */
class Report {
	private $leaders_report;
	private $access_report;

	private function __construct($leaders_report, $access_report) {
		$this->leaders_report = $leaders_report;
		$this->access_report = $access_report;
	}

	/**
	 * Load all needed information for a permissions report from database and create
	 * a result, ready to be displayed.
	 *
	 * @return Report Contains the resulting report data
	 */
	public static function create(): Report {
		global $server_dir;

		$servers = $server_dir->list_servers([], ['key_management' => ['keys']]);
		$leaders_serverlist = [];
		foreach ($servers as $server) {
			$leaders = new Leaders();
			$leaders->server_leaders = $server->list_effective_admins();

			$accounts = $server->list_accounts();
			foreach ($accounts as $account) {
				$account_leaders = $account->list_admins();
				// Accounts that exist without leaders are not relevant for the leader overview
				if (!empty($account_leaders)) {
					usort($account_leaders, function($l1, $l2) {
						return $l1->name <=> $l2->name;
					});
					$leaders->account_leaders[$account->name] = $account_leaders;
				}
			}
			ksort($leaders->account_leaders);
			$leaders_serverlist[] = [$leaders, $server];
		}
		$leaders_report = group_entries($leaders_serverlist);

		$access_serverlist = [];
		foreach ($servers as $server) {
			$access = new AccessRights();

			$accounts = $server->list_accounts();
			foreach ($accounts as $account) {
				$permitted = get_permitted_users($account);
				if (!empty($permitted)) {
					usort($permitted, function($u1, $u2) {
						return $u1->name <=> $u2->name;
					});
					$access->access_rights[$account->name] = $permitted;
				}
			}
			ksort($access->access_rights);
			$access_serverlist[] = [$access, $server];
		}
		$access_report = group_entries($access_serverlist);

		return new Report($leaders_report, $access_report);
	}

	public function get_leaders_report(): array {
		return $this->leaders_report;
	}

	public function get_access_report(): array {
		return $this->access_report;
	}
}

/**
 * Contains a list of server leaders and server account leaders for
 * one specific server.
 */
class Leaders {
	public $server_leaders;
	public $account_leaders = [];

	/**
	 * Create an index string that will be equal for identical leader configurations
	 * but unequal for different leader configurations. (The leaders of the server
	 * itself and all its accounts affect the resulting string)
	 *
	 * @return string The generated index string
	 */
	public function identityString(): string {
		$leader_ids = array_map(function($leader) {
			return $leader->entity_id;
		}, $this->server_leaders);
		$account_leader_ids = array_map(function($account) {
			return array_map(function($leader) {
				return $leader->entity_id;
			}, $account);
		}, $this->account_leaders);
		return json_encode([
			"leaders" => $leader_ids,
			"account_leaders" => $account_leader_ids,
		]);
	}
}

/**
 * Find all users that are allowed to access the given server account by any rule.
 * Each access is counted, even if restricted by options.
 *
 * @param ServerAccount $account The server account to find access rules for.
 * @return array List of user objects that are allowed to access.
 */
function get_permitted_users(ServerAccount $account): array {
	if (!$account->active || $account->sync_status == 'proposed') {
		return [];
	}
	$accesses = $account->list_access();
	$accessors = get_all_accessors($accesses);

	$groups = $account->list_group_membership();
	foreach ($groups as $group) {
		if (!$group->active) {
			continue;
		}
		$accesses = $group->list_access();
		$accessors = array_merge($accessors, get_all_accessors($accesses));
	}
	$users = array_filter($accessors, function($accessor) {
		return get_class($accessor) == "User";
	});
	remove_duplicates($users, function($user) {
		return $user->entity_id;
	});
	usort($users, function($u1, $u2) {
		return $u1->name <=> $u2->name;
	});
	return $users;
}

/**
 * Get all users and server accounts that are allowed to use one of the given accesses.
 * There may be duplicates in the result.
 *
 * @param array $accesses List of Access objects
 * @return array List of User and ServerAccount objects
 */
function get_all_accessors(array $accesses): array {
	$accessors = [];
	foreach ($accesses as $access) {
		$accessor = $access->source_entity;
		switch (get_class($accessor)) {
			case 'User':
			case 'ServerAccount':
				$accessors[] = $accessor;
				break;
			case 'Group':
				$accessors = array_merge($accessors, $accessor->list_members());
				break;
			default:
				throw new Exception("Found an accessor that is not a user, server account or group.");
		}
	}
	return $accessors;
}

/**
 * Remove duplicate entries from the given array. Duplicates are detected, if the identity
 * callback returns the same value.
 *
 * @param array $a The array to remove duplicates from
 * @param callable $identity Function that produces an int or string for each array element.
 */
function remove_duplicates(array &$a, callable $identity) {
	$result_map = [];
	foreach ($a as $elem) {
		$id = $identity($elem);
		if (!isset($result_map[$id])) {
			$result_map[$id] = $elem;
		}
	}
	$a = array_values($result_map);
}

/**
 * Contains a list of users that are allowed to access, for each individual
 * account name of one specific server.
 */
class AccessRights {
	public $access_rights = [];

	/**
	 * Create an index string that will be equal for identical access configurations
	 * but unequal for different access configurations.
	 *
	 * @return string The generated index string
	 */
	public function identityString(): string {
		$user_ids = array_map(function($account) {
			return array_map(function($user) {
				return $user->entity_id;
			}, $account);
		}, $this->access_rights);
		return json_encode($user_ids);
	}
}

/**
 * Group entries with identical configuration together.
 *
 * The input $entries must be an array of tuples. A tuple is an array
 * with two elements. The first element of each tuple must be an object
 * that has an identityString() method. Objects that produce the same
 * identityString() are considered equal and grouped together.
 *
 * The result is an array of groups. Each group is a tuple. The first
 * element is chosen from one of the grouped elements. The second element
 * is an array containing all second elements of the grouped tuples.
 *
 * At the end, the groups are sorted by their element count, in decreasing
 * order.
 */
function group_entries(array $entries): array {
	$groups = [];
	foreach ($entries as $entry) {
		$id = $entry[0]->identityString();
		if (!isset($groups[$id])) {
			$groups[$id] = [$entry[0], []];
		}
		$groups[$id][1][] = $entry[1];
	}
	usort($groups, function($a, $b) {
		return count($b[1]) <=> count($a[1]);
	});
	return $groups;
}
