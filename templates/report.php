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
?>
<h1>Permissions report</h1>
<h2>Server leaders</h2>
<?php foreach($this->get('report')->get_leaders_report() as $group) { ?>
<div class="panel panel-default">
	<div class="panel-body">
		<p>All of these servers ...<br>
		<?php
			$servers = $group[1];
			$html_list = array_map("Format::server_link", $servers);
			echo implode(", ", $html_list);
		?>
		<br>... have the following leaders:</p>
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
		<p>All of these servers ...<br>
		<?php
			$servers = $access[1];
			$html_list = array_map("Format::server_link", $servers);
			echo implode(", ", $html_list);
		?>
		<br>... have the following access rules:</p>
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
	</div>
</div>
<?php } ?>
