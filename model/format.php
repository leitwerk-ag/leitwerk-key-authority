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

class Format {
	/**
	 * Build an html link pointing to the page of the given server.
	 * The result is already properly escaped.
	 *
	 * @param Server $server Server instance to create a link for
	 * @return string Html string for output
	 */
	public static function server_link(Server $server): string {
		$url = hesc(rrurl('/servers/'.urlencode($server->hostname)));
		$hostname = hesc($server->hostname);
		return "<a href=\"$url\" class=\"server\">$hostname</a>";
	}

	/**
	 * Build an html link pointing to the account page of a given user.
	 * The result is already properly escaped.
	 *
	 * @param User $user User instance to create a link for
	 * @return string Html string for output
	 */
	public static function user_link(User $user): string {
		$url = hesc(rrurl('/users/'.urlencode($user->uid)));
		$class = 'user' . ($user->active ? '' : ' text-muted');
		$linktext = hesc($user->uid);
		return "<a href=\"$url\" class=\"$class\">$linktext</a>";
	}

	/**
	 * Build an html link pointing to the account page of a given server account.
	 * The result is already properly escaped.
	 *
	 * @param User $account ServerAccount instance to create a link for
	 * @return string Html string for output
	 */
	public static function server_account_link(ServerAccount $account): string {
		$url = hesc(rrurl('/servers/'.urlencode($account->server->hostname).'/accounts/'.urlencode($account->name)));
		$linktext = hesc($account->name.'@'.$account->server->hostname);
		$decommissioned_banner = "";
		if ($account->server->key_management == 'decommissioned') {
			$decommissioned_banner = ' <span class="label label-default">Inactive</span>';
		}
		return "<a href=\"$url\" class=\"serveraccount\">$linktext</a>$decommissioned_banner";
	}
}
