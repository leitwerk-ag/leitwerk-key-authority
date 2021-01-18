#!/usr/bin/php
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

chdir(__DIR__);
require('../core.php');
$active_user = User::get_keys_sync_user();

$servers = $server_dir->list_servers();
$keys = [];
foreach ($servers as $server) {
	$error_string = "";
	$start_time = date('c');
	try {
		$keys[$server->id] = read_server_keys($server, $error_string);
	} catch (Exception $e) {
		$error_string .= "Exception while reading keys of {$server->hostname}:\n  " . $e->getMessage() . "\n";
	}
	if ($error_string == "") {
		// Empty error set is stored as null in database
		$error_string = null;
	} else {
		// Prepend start time to non-empty error sets
		$error_string = $start_time . "\n" . $error_string;
	}
	if ($error_string !== $server->key_supervision_error) {
		$server->key_supervision_error = $error_string;
		$server->update();
	}
}

// Associative array that maps key contents (base64 strings) to a list of ExternalKey objects.
$found_keys = [];

foreach ($keys as $server_id => $entries) {
	foreach ($entries as $entry) {
		$key_content = $entry['key'];
		if (!isset($found_keys[$key_content])) {
			$found_keys[$key_content] = new ExternalKey(null, [
				'type' => $entry['type'],
				'keydata' => $key_content,
			]);
			$found_keys[$key_content]->occurrence = [];
		}
		$found_keys[$key_content]->occurrence[] = new ExternalKeyOccurrence(null, [
			'server' => $server_id,
			'account_name' => $entry['user'],
			'comment' => $entry['comment'],
		]);
	}
}

$keys_in_db = ExternalKey::list_external_keys();

// Associative array that maps key contents (base64 strings) to a list of ExternalKey objects.
$keys_in_db_assoc = [];
foreach ($keys_in_db as $key) {
	$keys_in_db_assoc[$key->keydata] = $key;
}

foreach ($found_keys as $keydata => $key) {
	// Look for keys that have been found but are not in the database
	if (!isset($keys_in_db_assoc[$keydata])) {
		$key->insert();
	}
}

foreach ($keys_in_db_assoc as $keydata => $key) {
	if (isset($found_keys[$key->keydata])) {
		// Keys are already known and also still in use - update occurrences
		$key->update_occurrences($found_keys[$key->keydata]->occurrence);
	} elseif ($key->status == 'new') {
		// Keys in state 'new' that are no longer on any system will be deleted
		$key->delete();
	} else {
		// For other keys not in state 'new' that are no longer on any system, occurrences will be deleted
		$key->update_occurrences([]);
	}
}

/**
 * Parse a line contained in /etc/passwd
 * This function returns an associative array that contains the following fields:
 * - user:   (string) username
 * - home:   (string) path of the user's home directory
 * - active: (bool) If the user account is enabled (has a valid shell)
 * @param string $line The line to parse
 * @return array Information about the given user entry or null if the entry is invalid
 */
function parse_user_entry(string $line) {
	// remove trailing line feed, if there is one
	if (substr($line, -1, 1) == "\n") {
		$line = substr($line, 0, -1);
	}

	$fields = explode(':', $line);
	if (count($fields) != 7) {
		return null;
	}

	$inactive_shells = [
		'/bin/false',
		'/bin/nologin',
		'/sbin/nologin',
		'/usr/bin/false',
		'/usr/bin/nologin',
		'/usr/sbin/nologin',
	];
	return [
		'user' => $fields[0],
		'home' => $fields[5],
		'active' => !in_array($fields[6], $inactive_shells),
	];
}

/**
 * Read all public-keys of active accounts from the given server that are contained
 * either in ~/.ssh/authorized_keys or in ~/.ssh/authorized_keys2
 * Returns an array of associative arrays that contain the following fields:
 * - user:    (string) username of this key
 * - type:    (string) type part of a key entry, for example "ssh-rsa"
 * - key:     (string) base64 encoded key information
 * - comment: (string) comment field at the end of a key entry
 *
 * @param Server $server The server to read keys from
 * @param string &$error_string Reference to a string variable where error messages are appended
 * @return array of ssh keys that are active on this server
 */
function read_server_keys(Server $server, string &$error_string) {
	global $server_dir;

	echo date('c')." Reading external ssh keys from {$server->hostname}\n";
	$attempts = ['keys-sync', 'root'];
	foreach($attempts as $attempt) {
		try {
			$connection = ssh2_connect($server->hostname, $server->port);
		} catch(ErrorException $e) {
			throw new Exception("Failed to connect.");
		}
		$fingerprint = ssh2_fingerprint($connection, SSH2_FINGERPRINT_MD5 | SSH2_FINGERPRINT_HEX);
		if(is_null($server->rsa_key_fingerprint)) {
			$server->rsa_key_fingerprint = $fingerprint;
			$server->update();
		} else {
			if(strcmp($server->rsa_key_fingerprint, $fingerprint) !== 0) {
				throw new Exception("RSA key validation failed.");
			}
		}
		if(!isset($config['security']) || !isset($config['security']['host_key_collision_protection']) || $config['security']['host_key_collision_protection'] == 1) {
			$matching_servers = $server_dir->list_servers(array(), array('rsa_key_fingerprint' => $server->rsa_key_fingerprint, 'key_management' => array('keys')));
			if(count($matching_servers) > 1) {
				throw new Exception("There are multiple hosts with same host key.");
			}
		}
		try {
			ssh2_auth_pubkey_file($connection, $attempt, 'config/keys-sync.pub', 'config/keys-sync');
			break;
		} catch(ErrorException $e) {
			if($attempt == 'root') {
				throw new Exception("Public key authentication failed.");
			}
		}
	}
	try {
		$sftp = ssh2_sftp($connection);
	} catch(ErrorException $e) {
		throw new Exception("SFTP subsystem setup failed.");
	}
	$user_entries = file("ssh2.sftp://$sftp/etc/passwd");
	$user_entries = array_map('parse_user_entry', $user_entries);
	$user_entries = array_filter($user_entries, function($entry) {
		return $entry['active'];
	});

	$keys = [];
	try {
		foreach ($user_entries as $user) {
			$path = "{$user['home']}/.ssh/authorized_keys";
			add_entries($keys, $user['user'], "ssh2.sftp://{$sftp}", $path, $error_string);
			$path .= '2';
			add_entries($keys, $user['user'], "ssh2.sftp://{$sftp}", $path, $error_string);
		}
	} catch (Exception $e) {
		throw new Exception("Could not parse external keys in $path:\n  " . $e->getMessage());
	}

	return $keys;
}

/**
 * Scan for keys that are contained in an authorized_keys file and add them to
 * the array of key entries.
 *
 * @param array $entries Reference to the array of entries to fill
 * @param string $user Username to add to the entries
 * @param string $sftp_url Resource-URL for the sftp connection to the server
 * @param string $filename Name of the authorized_keys file to scan (If it does not exist, it is ignored)
 * @param string &$error_string Reference to a string variable where error messages are appended
 */
function add_entries(array &$entries, string $user, string $sftp_url, string $filename, string &$error_string) {
	if (!file_exists($sftp_url . $filename)) {
		check_missing_file($sftp_url, $filename, $error_string);
		return;
	}
	try {
		$lines = file($sftp_url . $filename);
	} catch (ErrorException $e) {
		$error_string .= "Failed to read $filename\n  {$e->getMessage()}\n";
		return;
	}
	foreach ($lines as $line) {
		// ignore empty lines and comments
		if ($line !== '' && substr($line, 0, 1) !== '#') {
			if (preg_match('%^([^ ]+ )?((ssh|ecdsa)-[^ ]+) ([a-zA-Z0-9+/=]+)( (.*))?$%', $line, $matches)) {
				$entries[] = [
					'user' => $user,
					'type' => $matches[2],
					'key' => $matches[4],
					'comment' => $matches[6],
				];
			} else {
				throw new Exception("Found an invalid ssh key line:\n  $line");
			}
		}
	}
}

/**
 * Check if the specified file is actually non-existent (in which case nothing happens)
 * If the file is instead not accessible because of permissions, an error message will be appended to $error_string
 * This function works by iteratively checking directories upwards, if they are readable.
 *
 * @param string $sftp_url Resource-URL for the sftp connection to the server
 * @param string $filename Name of the authorized_keys file to scan (If it does not exist, it is ignored)
 * @param string &$error_string Reference to a string variable where error messages are appended
 */
function check_missing_file(string $sftp_url, string $filename, string &$error_string) {
	$dir = $filename;
	do {
		$dir = dirname($dir);
		if (file_exists($sftp_url . $dir)) {
			if (!is_readable($sftp_url . $dir)) {
				// The directory is not readable - could not truly check the existence of the file.
				// This is an error.
				$error_string .= "Could not check if $filename exists, because $dir is not readable.\n";
			} // else: The directory above is readable, so the file does actually not exist. No error.
			return;
		}
	} while ($dir != "/" && $dir != ".");
}
