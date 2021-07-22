#!/usr/bin/php
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

chdir(__DIR__);
require('../core.php');

$users = $user_dir->list_users();

// Use 'keys-sync' user as the active user
$active_user = User::get_keys_sync_user();

try {
	$sysgrp = $group_dir->get_group_by_name($config['ldap']['admin_group_cn']);
} catch(GroupNotFoundException $e) {
	$sysgrp = new Group;
	$sysgrp->name = $config['ldap']['admin_group_cn'];
	$sysgrp->system = 1;
	$group_dir->add_group($sysgrp);
}
// Add guid of main admin group, if not already stored
if ($sysgrp->ldap_guid === null) {
	$sysgrp_ldap = $ldap->search($config['ldap']['dn_group'],
			LDAP::escape($config['ldap']['group_id']).'='.LDAP::escape($sysgrp->name),
			[strtolower($config['ldap']['group_num'])]);
	if (!empty($sysgrp_ldap)) {
		$sysgrp->ldap_guid = $sysgrp_ldap[0][strtolower($config['ldap']['group_num'])];
		$sysgrp->update();
	}
}

foreach($users as $user) {
	if($user->auth_realm == 'LDAP') {
		$active = $user->active;
		try {
			$user->get_details_from_ldap();
			$user->update();
			if(isset($config['ldap']['user_superior'])) {
				$user->get_superior_from_ldap();
			}
		} catch(UserNotFoundException $e) {
			$user->active = 0;
		}
		$user->update_group_memberships();
		$user->update();
		if($active && !$user->active) {
			// Check for servers that will now be leader-less
			$servers = $user->list_admined_servers();
			foreach($servers as $server) {
				$server_admins = $server->list_effective_admins();
				$total_server_admins = 0;
				foreach($server_admins as $server_admin) {
					if($server_admin->active) $total_server_admins++;
				}
				if($total_server_admins == 0) {
					if(isset($config['ldap']['user_superior'])) {
						$rcpt = $user->superior;
						while(!is_null($rcpt) && !$rcpt->active) {
							$rcpt = $rcpt->superior;
						}
					}
					$email = new Email;
					$email->subject = "Server {$server->hostname} has been orphaned";
					$email->body = "{$user->name} ({$user->uid}) was a leader for {$server->hostname}, but they have now been marked as a former employee and there are no active leaders remaining for this server.\n\n";
					$email->body .= "Please find a replacement owner for this server and inform {$config['email']['admin_address']} ASAP, otherwise the server will be registered for decommissioning.";
					$email->add_reply_to($config['email']['admin_address'], $config['email']['admin_name']);
					if(!isset($rcpt)) {
						$email->subject .= " - NO SUPERIOR EMPLOYEE FOUND";
						$email->body .= "\n\nWARNING: No suitable superior employee could be found!";
						$email->add_recipient($config['email']['report_address'], $config['email']['report_name']);
					} else {
						$email->add_recipient($rcpt->email, $rcpt->name);
						$email->add_cc($config['email']['report_address'], $config['email']['report_name']);
					}
					$email->send();
				}
			}
		}
	}
}

// Update group names
$groups = $group_dir->list_groups();
foreach ($groups as $group) {
	if ($group->ldap_guid !== null) {
		$group_ldap = $ldap->search($config['ldap']['dn_group'],
				LDAP::escape($config['ldap']['group_num']).'='.LDAP::query_encode_guid($group->ldap_guid),
				['name']);
		if (!empty($group_ldap)) {
			$group->name = $group_ldap[0]["name"];
		}
		$group->update();
	}
}
