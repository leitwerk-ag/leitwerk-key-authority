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
	 * An sftp access handle as given by ssh2_sftp(). Lazily initialized when needed (see get_sftp())
	 */
	private $sftp;

	/**
	 * Create a new ssh connection instance using the given handle
	 * @param resource $connection The opened ssh connection handle
	 */
	private function __construct($connection) {
		$this->connection = $connection;
	}

	/**
	 * Open an ssh connection to the given server using public-key authentication.
	 * The fingerprint is given by reference. Initialize it with null for the first connection.
	 * If null is given, it is modified to the actual fingerprint. In future versions,
	 * it might also be modified if the format or algorithm for the fingerprint changes.
	 *
	 * @param string $host Hostname of the ssh server
	 * @param int $port Port number of the ssh server
	 * @param string $pubkey_file_path Location of the public key file to use
	 * @param string $privkey_file_path Location of the private key file to use
	 * @param string &$fingerprint Reference to the fingerprint value
	 * @throws SSHException If the connection fails (e.g. host unreachable, wrong fingerprint, failed to authenticate)
	 */
	public static function connect_with_pubkey(
		string $host,
		int $port,
		string $username,
		string $pubkey_file_path,
		string $privkey_file_path,
		?string &$fingerprint
	): SSH {
		try {
			$connection = ssh2_connect($host, $port);
		} catch(ErrorException $e) {
			throw new SSHException("Failed to connect to ssh server", null, $e);
		}
		$host_fingerprint = ssh2_fingerprint($connection, SSH2_FINGERPRINT_MD5 | SSH2_FINGERPRINT_HEX);
		if ($fingerprint === null) {
			$fingerprint = $host_fingerprint;
		} else if ($fingerprint != $host_fingerprint) {
			throw new SSHException("SSH host key fingerprint does not match");
		}
		try {
			ssh2_auth_pubkey_file($connection, $username, $pubkey_file_path, $privkey_file_path);
		} catch(ErrorException $e) {
			throw new SSHException("SSH pubkey authentication failed");
		}
		return new SSH($connection);
	}

	/**
	 * Execute the given command and return a stream for communication (stdin, stdout)
	 *
	 * @param string $command Shell command to execute
	 * @throws SSHException If starting the command fails
	 */
	public function exec(string $command) {
		try {
			$stream = ssh2_exec($this->connection, $command);
		} catch (ErrorException $e) {
			throw new SSHException("Failed to execute the command: $command", null, $e);
		}
		stream_set_blocking($stream, true);
		return $stream;
	}

	/**
	 * Load the given file from the ssh server
	 *
	 * @param string $filename Name of the file to load
	 * @throws SSHException If the file does not exist or is not accessible
	 * @return string The file content
	 */
	public function file_get_contents(string $filename): string {
		try {
			$sftp = $this->get_sftp();
			return file_get_contents("ssh2.sftp://$sftp/$filename");
		} catch (ErrorException $e) {
			throw new SSHException("Could not read file $filename", null, $e);
		}
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
		try {
			$sftp = $this->get_sftp();
			file_put_contents("ssh2.sftp://$sftp/$filename", $content);
		} catch (ErrorException $e) {
			throw new SSHException("Could not write to file $filename", null, $e);
		}
	}

	/**
	 * Delete the given file from the target server
	 *
	 * @param string $filename The full file path on the target server
	 * @throws SSHException If the delete operation fails
	 */
	public function unlink(string $filename) {
		try {
			$sftp = $this->get_sftp();
			ssh2_sftp_unlink($sftp, $filename);
		} catch (ErrorException $e) {
			throw new SSHException("Could not unlink file $filename", null, $e);
		}
	}

	/**
	 * Initialize the sftp subsystem if not done already, and return the sftp handle.
	 * @return resource The created or stored handle for sftp access
	 * @throws SSHException If the initialization of the subsystem fails
	 */
	private function get_sftp() {
		if ($this->sftp === null) {
			$sftp = ssh2_sftp($this->connection);
			if ($sftp === false) {
				throw new SSHException("Could not initialize the sftp subsystem");
			}
			$this->sftp = $sftp;
		}
		return $this->sftp;
	}
}
