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
 * Send a mail, informing that a user or groups has been added as leader for multiple servers
 *
 * @param Entity $entity User or Group that was added as leader
 * @param array $affected_servers Array of servers where the given leader has been added
 */
function send_bulk_add_mail(Entity $entity, array $affected_servers) {
	global $active_user, $config;

	$servers_desc = count($affected_servers) == 1 ? "1 server" : count($affected_servers) . " servers";

	$email = new Email;
	$email->subject = "Leader for $servers_desc";
	$email->add_cc($config['email']['report_address'], $config['email']['report_name']);
	switch(get_class($entity)) {
		case 'User':
			$email->add_recipient($entity->email, $entity->name);
			$email->body = "{$active_user->name} ({$active_user->uid}) has added you as a server leader for the following $servers_desc:\n";
			foreach ($affected_servers as $server) {
				$email->body .= "- {$server->hostname}\n";
			}
			$email->body .= "\nYou can now manage access to " . (count($affected_servers) == 1 ? "this server." : "these servers.");
			break;
		case 'Group':
			foreach($entity->list_members() as $member) {
				if(get_class($member) == 'User') {
					$email->add_recipient($member->email, $member->name);
				}
			}
			$email->body = "{$active_user->name} ({$active_user->uid}) has added the {$entity->name} group as server leader for the following $servers_desc:\n";
			foreach ($affected_servers as $server) {
				$email->body .= "- {$server->hostname}\n";
			}
			$email->body .= "\nYou are a member of the {$entity->name} group, so you can now manage access to " . (count($affected_servers) == 1 ? "this server." : "these servers.");
			break;
		default:
			throw new InvalidArgumentException('Entities of type '.get_class($entity).' cannot be added as server leaders');
	}
	$email->send();
}

if (!$active_user->admin) {
	require('views/error403.php');
	die;
}

$server_names = $_POST['selected_servers'] ?? [];
$selected_servers = array_map(function($name) {
	global $server_dir;
	return $server_dir->get_server_by_hostname($name);
}, $server_names);

$content = null;
if (isset($_POST['add_admin'])) {
	try {
		$entity = $user_dir->get_user_by_uid($_POST['user_name']);
	} catch(UserNotFoundException $e) {
		try {
			$entity = $group_dir->get_group_by_name($_POST['user_name']);
		} catch(GroupNotFoundException $e) {
			$content = new PageSection('user_not_found');
		}
	}
	if (isset($entity)) {
		$affected_servers = [];
		foreach ($selected_servers as $server) {
			if ($server->add_admin($entity, false)) {
				$affected_servers[] = $server;
			}
		}
		if (!empty($affected_servers)) {
			send_bulk_add_mail($entity, $affected_servers);
		}
		$num = count($affected_servers);
		if ($entity instanceof User) {
			$type = "User";
		} else if ($entity instanceof Group) {
			$type = "Group";
		}
		$alert = new UserAlert;
		$alert->content = "{$type} {$entity->name} has been added as a leader for " . ($num == 1 ? "1 server" : "$num servers");
		$active_user->add_alert($alert);
	}
} else if (isset($_POST['delete_admin'])) {
	$entity = Entity::load($_POST['delete_admin']);
	if ($entity === null) {
		$content = new PageSection('user_not_found');
	}
	if (isset($entity)) {
		$affected_servers = [];
		foreach ($selected_servers as $server) {
			if ($server->delete_admin($entity)) {
				$affected_servers[] = $server;
			}
		}
		$num = count($affected_servers);
		if ($entity instanceof User) {
			$type = "User";
		} else if ($entity instanceof Group) {
			$type = "Group";
		}
		$alert = new UserAlert;
		$alert->content = "{$type} {$entity->name} has been removed as a leader from " . ($num == 1 ? "1 server" : "$num servers");
		$active_user->add_alert($alert);
	}
}

if ($content === null) {
	$content = new PageSection('servers_bulk_action');
	$content->set('server_names', $server_names);
	$content->set('plural', count($server_names) != 1);
	$content->set('all_users', $user_dir->list_users());
	$content->set('all_groups', $group_dir->list_groups());
	$server_admins = [];
	foreach ($selected_servers as $server) {
		$admins = $server->list_admins();
		foreach ($admins as $admin) {
			if (isset($server_admins[$admin->id])) {
				$server_admins[$admin->id][1]++;
			} else {
				$server_admins[$admin->id] = [$admin, 1];
			}
		}
	}
	$content->set('server_admins', array_values($server_admins));
}

$page = new PageSection('base');
$page->set('title', 'Bulk Action for Servers');
$page->set('content', $content);
$page->set('alerts', $active_user->pop_alerts());
echo $page->generate();
