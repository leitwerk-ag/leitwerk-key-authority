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

$keys_in_db = ExternalKey::list_external_keys();

// Associative array that maps key contents (base64 strings) to a list of ExternalKey objects.
$keys_in_db_assoc = [];
foreach ($keys_in_db as $key) {
	$keys_in_db_assoc[$key->keydata] = $key;
}

$servers = $server_dir->list_servers([], ['key_management' => ['keys']]);
$keys = [];
foreach ($servers as $server) {
	$error_string = "";
	$start_time = date('c');
	$ssh = null;
	$sftp = null;
	try {
		$keys[$server->id] = read_server_keys($server, $error_string, $ssh, $sftp, $keys_in_db_assoc);
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
	if ($sftp !== null) {
		// Avoid false-negative message after a downtime
		// If sync is on error state but key supervision succeeds, this may be because the
		// target server recently recovered from downtime.
		// In this case, no false-negative status file will be placed.
		if ($server->key_supervision_error !== null || $server->sync_status === 'sync success') {
			$server->update_status_file($sftp);
		}
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

foreach ($found_keys as $keydata => $key) {
	// Look for keys that have been found but are not in the database
	if (!isset($keys_in_db_assoc[$keydata])) {
		$key->insert();
		sendmail_appeared_key($key);
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
 * @param &$sftp Reference to a variable, where the sftp handle is stored by this function, if it could be opened successfully.
 * @param array $keys_in_db_assoc Known keys, used to check if some keys need to be removed
 * @return array of ssh keys that are active on this server
 */
function read_server_keys(Server $server, string &$error_string, &$connection, &$sftp, $keys_in_db_assoc) {
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
			add_entries($keys, $user['user'], $connection, "ssh2.sftp://{$sftp}", $path, $error_string, $keys_in_db_assoc);
			$path .= '2';
			add_entries($keys, $user['user'], $connection, "ssh2.sftp://{$sftp}", $path, $error_string, $keys_in_db_assoc);
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
 * @param $ssh The ssh connection resource, will be used to execute a 'test -w' command
 * @param string $sftp_url Resource-URL for the sftp connection to the server
 * @param string $filename Name of the authorized_keys file to scan (If it does not exist, it is ignored)
 * @param string &$error_string Reference to a string variable where error messages are appended
 * @param array $keys_in_db_assoc Known keys, used to check if some keys need to be removed
 */
function add_entries(array &$entries, string $user, $ssh, string $sftp_url, string $filename, string &$error_string, $keys_in_db_assoc) {
	if (!file_exists($sftp_url . $filename)) {
		check_missing_file($sftp_url, $filename, $error_string);
		return;
	}
	try {
		$lines = file($sftp_url . $filename);
		// Use the 'test' shell command to check for writability.
		// The php function is_writable() produces wrong results when using facl.
		$shell_escaped_filename = escapeshellarg($filename);
		$stream = ssh2_exec($ssh, "test -w {$shell_escaped_filename}; echo $?");
		stream_set_blocking($stream, true);
		$output = stream_get_contents($stream);
		if ($output !== "0\n") {
			$error_string .= "The file {$filename} is not writable for the keys-sync user. This will prevent key authority from removing old keys.\n";
		}
	} catch (ErrorException $e) {
		$error_string .= "Failed to read $filename\n  {$e->getMessage()}\n";
		return;
	}
	$file_modified = false;
	$new_filecontent = '';
	$line_num = 1;
	foreach ($lines as $line) {
		$keep_line = true; // Set to false, if line needs to be deleted
		// ignore empty lines and comments
		if (trim($line) !== '' && substr($line, 0, 1) !== '#') {
			if (preg_match('%^([^ ]+ )?((ssh|ecdsa)-[^ ]+) ([a-zA-Z0-9+/=]+)( (.*))?$%', $line, $matches)) {
				$entry = [
					'user' => $user,
					'type' => $matches[2],
					'key' => $matches[4],
					'comment' => $matches[6],
				];
				if (isset($keys_in_db_assoc[$entry['key']]) && $keys_in_db_assoc[$entry['key']]->status == 'denied') {
					$keep_line = false;
				}
				$entries[] = $entry;
			} else {
				$error_string .= "Line $line_num in $filename has an invalid format.\n";
			}
		}
		if ($keep_line) {
			$new_filecontent .= $line;
			$line_num++;
		} else {
			$file_modified = true;
		}
	}
	if ($file_modified) {
		if (file_put_contents($sftp_url . $filename, $new_filecontent) === false) {
			$error_string .= "Removing 'denied' keys from $filename failed: file_put_contents() returned false.\n";
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

/**
 * Send an email to the serveraccount admins and server admins, informing about one new key.
 * @param ExternalKey $appeared_key
 */
function sendmail_appeared_key(ExternalKey $appeared_key)  {
	global $config, $server_dir;

	// Two-dimensional array of affected accounts:
	// First index: server id; Second index: account name; Value: the key comment
	$server_accounts = [];

	foreach ($appeared_key->occurrence as $occurrence) {
		if (!isset($server_accounts[$occurrence->server])) {
			$server_accounts[$occurrence->server] = [];
		}
		if (!isset($server_accounts[$occurrence->server][$occurrence->account_name])) {
			$server_accounts[$occurrence->server][$occurrence->account_name] = $occurrence->comment;
		}
	}

	$to = []; // associative arrays, mapping mail address to user name
	$cc = []; // Users may be added to both (to + cc), in this case they will only be mentioned in To, not in Cc.

	foreach ($server_accounts as $server_id => $account_names) {
		$server = $server_dir->get_server_by_id($server_id);
		$accounts = $server->list_accounts();
		$serveradmins_as_recipients = false;
		foreach ($accounts as $account) {
			$account_admins_informed = false;
			if (isset($account_names[$account->name])) {
				$account_admins = $account->list_admins();
				foreach ($account_admins as $account_admin) {
					$to[$account_admin->email] = $account_admin->name;
					$account_admins_informed = true;
				}
			}
			if (!$account_admins_informed) {
				$serveradmins_as_recipients = true;
			}
		}
		foreach ($server->list_effective_admins() as $server_admin) {
			if ($serveradmins_as_recipients) {
				$to[$server_admin->email] = $server_admin->name;
			} else {
				// If every affected account has own admins, server admins will only be mentioned in cc
				$cc[$server_admin->email] = $server_admin->name;
			}
		}
	}

	$email = new Email;
	foreach ($to as $rcpt_mail => $rcpt_name) {
		$email->add_recipient($rcpt_mail, $rcpt_name);
	}
	foreach ($cc as $cc_rcpt_mail => $cc_rcpt_name) {
		if (!isset($to[$cc_rcpt_mail])) {
			$email->add_cc($cc_rcpt_mail, $cc_rcpt_name);
		}
	}
	$email->add_cc($config['email']['report_address'], $config['email']['report_name']);

	// Create different mail layouts, depending on the number of servers / accounts
	$singleserver = count($server_accounts) == 1;
	$singleaccount = $singleserver && count(reset($server_accounts)) == 1;
	if ($singleserver) {
		$server_id = array_keys($server_accounts)[0];
		$server = $server_dir->get_server_by_id($server_id);
		$hostname = $server->hostname;
		if ($singleaccount) {
			$account_name = array_keys(reset($server_accounts))[0];
			$accounts_comments = reset($server_accounts);
			$comment = reset($accounts_comments);

			$email->subject = "New ssh key appeared on {$account_name}@{$hostname}";
			$email->body = "The following key was found on {$account_name}@{$hostname} during a server scan:\n";
			$email->body .= "{$appeared_key->type} {$appeared_key->keydata} {$comment}\n";
		} else {
			$email->subject = "New ssh key appeared on {$hostname}";
			$email->body = "The following key was found on {$hostname} during a server scan:\n";
			$email->body .= "{$appeared_key->type} {$appeared_key->keydata}\n\n";
			$email->body .= "The following accounts are affected:\n";
			$email->body .= accounts_and_comments_table(reset($server_accounts));
		}
	} else {
		$email->subject = "New ssh key appeared on multiple servers";
		$email->body = "The following key was found during a server scan:\n";
		$email->body .= "{$appeared_key->type} {$appeared_key->keydata}\n\n";
		$email->body .= "The following servers are affected:\n";
		foreach ($server_accounts as $server_id => $accounts) {
			$server = $server_dir->get_server_by_id($server_id);
			$hostname = $server->hostname;
			$email->body .= "\n{$hostname}:\n";
			$email->body .= accounts_and_comments_table($accounts);
		}
	}

	$email->send();
}

/**
 * Create a text-based table with server account names and ssh key comments.
 *
 * @param array $accounts Associative array mapping account names to key comments
 * @return string The resulting table as multi-line string
 */
function accounts_and_comments_table(array $accounts) {
	$account_header = "Account";
	$comment_header = "Key comment";
	$account_column_width = max(iconv_strlen($account_header), ...array_map('iconv_strlen', array_keys($accounts)));
	$comment_column_width = max(iconv_strlen($comment_header), ...array_map('iconv_strlen', array_values($accounts)));

	$row_format = " %-{$account_column_width}s|%-{$comment_column_width}s\n";
	// heading
	$output = sprintf($row_format, $account_header, $comment_header);
	// horizontal line
	$output .= sprintf(" %-'-{$account_column_width}s+%-'-{$comment_column_width}s\n", "", "");
	// data rows
	foreach ($accounts as $account => $comment) {
		$output .= sprintf($row_format, $account, $comment);
	}
	return $output;
}
