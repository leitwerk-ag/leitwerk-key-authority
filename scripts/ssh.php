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

use phpseclib3\Net\SFTP;
use phpseclib3\Crypt\PublicKeyLoader;

class SSHException extends Exception {}

/**
 * An SSH wrapper as an adapter to the actual ssh implementation.
 * Allows to change the used ssh library more easily in future.
 * Currently, the php module ssh2 is used.
 */
class SSH {
	/**
	 * The ssh connection handle as given by ssh2_connect(). Must be set by the constructor.
	 */
	private $connection;

	/**
	 * Create a new ssh connection instance using the given handle
	 * @param resource $connection The opened ssh connection handle
	 */
	private function __construct($connection) {
		$this->connection = $connection;
	}

	/**
	 * Open an ssh connection to the given server using public-key authentication.
	 * The host key is given by reference. Initialize it with null for the first connection.
	 * If null is given, it is modified to the actual host key. In future versions,
	 * it might also be modified if the format or algorithm for the host key changes.
	 *
	 * @param string $host Hostname of the ssh server
	 * @param int $port Port number of the ssh server
	 * @param string $pubkey_file_path Location of the public key file to use
	 * @param string $privkey_file_path Location of the private key file to use
	 * @param string &$host_key Reference to the host key value
	 * @throws SSHException If the connection fails (e.g. host unreachable, wrong fingerprint, failed to authenticate)
	 */
	public static function connect_with_pubkey(
		string $host,
		int $port,
		string $username,
		string $pubkey_file_path,
		string $privkey_file_path,
		?string &$host_key
	): SSH {
		try {
			$ssh = new SFTP($host, $port);
		} catch(ErrorException $e) {
			throw new SSHException("Failed to connect to ssh server", null, $e);
		}
		$received_key = $ssh->getServerPublicHostKey();
		if ($host_key === null || $host_key === "") {
			$host_key = $received_key;
		} else if ($host_key != $received_key) {
			throw new SSHException("SSH host key fingerprint does not match");
		}
		$key = PublicKeyLoader::load(file_get_contents("config/keys-sync"));
		if (!$ssh->login($username, $key)) {
			throw new SSHException("SSH pubkey authentication failed");
		}
		return new SSH($ssh);
	}

	/**
	 * Execute the given command and return its output
	 *
	 * @param string $command Shell command to execute
	 * @throws SSHException If starting the command fails
	 * @return string The output of the command as one string
	 */
	public function exec(string $command): string {
		try {
			return $this->connection->exec($command);
		} catch (ErrorException $e) {
			throw new SSHException("Failed to execute the command: $command", null, $e);
		}
	}

	/**
	 * Load the given file from the ssh server
	 *
	 * @param string $filename Name of the file to load
	 * @throws SSHException If the file does not exist or is not accessible
	 * @return string The file content
	 */
	public function file_get_contents(string $filename): string {
		$result = $this->connection->get($filename);
		if ($result === false) {
			throw new SSHException("Could not read file $filename");
		}
		return $result;
	}

	/**
	 * Load the given file from the ssh server and split at linefeed characters.
	 * The linefeed characters themselves are not included in the returned strings.
	 * One linefeed at the end of file (which should be there, by convention) will
	 * not lead to an empty last element.
	 *
	 * @param string $filename The full path of the file on the target server
	 * @throws SSHException If the file does not exist or is not accessible
	 * @return array All the contained lines, as array of strings
	 */
	public function file_get_lines(string $filename): array {
		$content = $this->file_get_contents($filename);
		$lines = explode("\n", $content);
		if (end($lines) === "") {
			// remove last, empty line
			array_pop($lines);
		}
		reset($lines);
		return $lines;
	}

	/**
	 * Create or overwrite a file on the target server.
	 *
	 * @param string $filename The full file path on the target server
	 * @param string $content The content to store
	 * @throws SSHException If the operation fails
	 */
	public function file_put_contents(string $filename, string $content) {
		if ($this->connection->put($filename, $content) === false) {
			throw new SSHException("Could not write to file $filename");
		}
	}

	/**
	 * Delete the given file from the target server
	 *
	 * @param string $filename The full file path on the target server
	 * @throws SSHException If the delete operation fails
	 */
	public function unlink(string $filename) {
		if ($this->connection->delete($filename) === false) {
			throw new SSHException("Could not unlink file $filename");
		}
	}
}
