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

$server_names = $_POST['selected_servers'] ?? [];
$selected_servers = array_map(function($name) {
	global $server_dir;
	return $server_dir->get_server_by_hostname($name);
}, $server_names);

$content = new PageSection('servers_bulk_action');
$content->set('server_names', $server_names);
$content->set('plural', count($server_names) != 1);
$content->set('all_users', $user_dir->list_users());
$content->set('all_groups', $group_dir->list_groups());
$server_admins = [];
foreach ($selected_servers as $server) {
	$admins = $server->list_admins();
	foreach ($admins as $admin) {
		if ($admin instanceof User) {
			$entity_key = "User{$admin->id}";
		} else if ($admin instanceof Group) {
			$entity_key = "Group{$admin->id}";
		} else {
			throw new Exception("Found a server admin that is neither user nor group");
		}
		if (isset($server_admins[$entity_key])) {
			$server_admins[$entity_key][1]++;
		} else {
			$server_admins[$entity_key] = [$admin, 1];
		}
	}
}
$content->set('server_admins', array_values($server_admins));

$page = new PageSection('base');
$page->set('title', 'Bulk Action for Servers');
$page->set('content', $content);
$page->set('alerts', $active_user->pop_alerts());
echo $page->generate();
