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
 * Output "The server ..." or "All of these servers ...<br>...<br>...",
 * depending on singular, plural.
 *
 * @param array $servers The list containing one or more server
 * @param array $suffix Optional tuple of two strings to append to the result [singular, plural]
 * @return string List of servers with html link, text is already escaped
 */
function server_list(array $servers, array $suffix = ["", ""]): string {
	$html_list = array_map("Format::server_link", $servers);
	$row = implode(", ", $html_list);
	if (count($servers) == 1) {
		return "The server $row{$suffix[0]}";
	} else {
		return "All of these servers ...<br>$row<br>...{$suffix[1]}";
	}
}

?>
<h1>Permissions report</h1>

<h2>Server leaders</h2>
<?php foreach($this->get('report')->get_leaders_report() as $group) { ?>
<div class="panel panel-default">
	<div class="panel-body">
		<p><?php out(server_list($group[1], [" has", " have"]), ESC_NONE) ?> the following leaders:</p>
		<table class="table table-bordered">
			<tr>
				<th colspan="2">Server leaders</th>
			</tr>
			<tr>
				<td colspan="2">
				<?php
					$server_leaders = $group[0]->server_leaders;
					$html_list = array_map("Format::user_link", $server_leaders);
					echo implode(", ", $html_list);
				?>
				<?php if (empty($group[0]->server_leaders)) { ?>
				<em>There are currently no leaders assigned.</em>
				<?php } ?>
				</td>
			</tr>
			<?php if (!empty($group[0]->account_leaders)) { ?>
			<tr>
				<th colspan="2">Account leaders</th>
			</tr>
			<?php foreach ($group[0]->account_leaders as $account_name => $account_leaders) { ?>
			<tr>
				<th><?php out($account_name) ?></th>
				<td>
				<?php
					$html_list = array_map("Format::user_link", $account_leaders);
					echo implode(", ", $html_list);
				?>
				</td>
			</tr>
			<?php } ?>
			<?php } ?>
		</table>
	</div>
</div>
<?php } ?>

<h2>Access rights</h2>
<?php foreach ($this->get('report')->get_access_report() as $access) { ?>
<div class="panel panel-default">
	<div class="panel-body">
		<p><?php out(server_list($access[1], [" has", " have"]), ESC_NONE) ?> the following access rules:</p>
		<?php if (!empty($access[0]->access_rights)) { ?>
		<table class="table table-bordered">
			<?php foreach ($access[0]->access_rights as $account_name => $accessors) { ?>
			<tr>
				<th><?php out($account_name) ?></th>
				<td>
				<?php
					$html_list = array_map("Format::user_link", $accessors);
					echo implode(", ", $html_list);
				?>
				</td>
			</tr>
			<?php } ?>
		</table>
		<?php } else { ?>
		<em>Nobody is allowed to access</em>
		<?php } ?>
	</div>
</div>
<?php } ?>

<h2>Server-to-Server accesses</h2>
<?php foreach ($this->get('report')->get_server_to_server_report() as $access) { ?>
<div class="panel panel-default">
	<div class="panel-body">
		<p><?php out(server_list($access[1]), ESC_NONE) ?> can be accessed by the following other server accounts:</p>
		<?php if (!empty($access[0]->access_rights)) { ?>
		<table class="table table-bordered">
			<?php foreach ($access[0]->access_rights as $account_name => $accessors) { ?>
			<tr>
				<th><?php out($account_name) ?></th>
				<td>
				<?php
					$html_list = array_map("Format::server_account_link", $accessors);
					echo implode(", ", $html_list);
				?>
				</td>
			</tr>
			<?php } ?>
		</table>
		<?php } else { ?>
		<em>No other server accounts are allowed to access</em>
		<?php } ?>
	</div>
</div>
<?php } ?>
