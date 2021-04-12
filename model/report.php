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

	private function __construct($leaders_report) {
		$this->leaders_report = $leaders_report;
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
		return new Report($leaders_report);
	}

	public function get_leaders_report(): array {
		return $this->leaders_report;
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
