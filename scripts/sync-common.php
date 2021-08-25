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

/**
 * Represent the message of an exception (that might consist of multiple, chained
 * exceptions) as one string.
 *
 * @param Exception $e The exception to describe
 */
function describe_oneline(Exception $e) {
	$prev = $e->getPrevious();
	if ($prev === null) {
		return $e->getMessage();
	} else {
		return $e->getMessage() . ": " . describe_oneline($prev);
	}
}

/**
 * Read the content from multiple streams in parallel until each stream reached eof.
 *
 * @param array $streams An array of streams to read from.
 * @return array An array of strings (output read from the streams)
 */
function read_streams(array $streams): array {
	$output = [];
	foreach ($streams as $stream) {
		$output[] = "";
		stream_set_blocking($stream, false);
	}
	while (!empty($streams)) {
		$sel_streams = $streams;
		$wr_streams = null;
		$err_streams = null;
		stream_select($sel_streams, $wr_streams, $err_streams, null);
		foreach ($sel_streams as $i => $stream) {
			$output[$i] .= fread($stream, 4096);
			if (feof($stream)) {
				unset($streams[$i]);
			}
		}
	}
	return $output;
}

/**
* Synchronization child process object
*/
class SyncProcess {
	private $handle;
	private $pipes;
	private $finished = false;
	private $output;
	private $errors;
	private $request;
	private $exit_status;

	/**
	* Create a new sync process
	* @param string $command command to run
	* @param array $args arguments
	* @param Request $request object that triggered this sync
	*/
	public function __construct($command, $args, $request = null) {
		global $config;
		$timeout_util = $config['general']['timeout_util'];

		$this->request = $request;
		$this->output = '';
		$descriptorspec = array(
			0 => array("pipe", "r"),  // stdin
			1 => array("pipe", "w"),  // stdout
			2 => array("pipe", "w"),  // stderr
			3 => array("pipe", "w")   //
		);
		switch ($timeout_util) {
			case "BusyBox":
				$commandline = '/usr/bin/timeout -t 60 '.$command.' '.implode(' ', array_map('escapeshellarg', $args));
				break;
			default:
				$commandline = '/usr/bin/timeout 60s '.$command.' '.implode(' ', array_map('escapeshellarg', $args));
		}

		$this->handle = proc_open($commandline, $descriptorspec, $this->pipes);
		stream_set_blocking($this->pipes[1], 0);
		stream_set_blocking($this->pipes[2], 0);
	}

	/**
	* Get data from the child process
	* @return string output from the child process
	*/
	public function get_data() {
		if(isset($this->handle) && is_resource($this->handle)) {
			if (!$this->finished) {
				$data = read_streams([$this->pipes[1], $this->pipes[2]]);
				$this->output = $data[0];
				$this->errors = $data[1];
				$this->finished = true;
			}
			foreach($this->pipes as $ref => $pipe) {
				fclose($this->pipes[$ref]);
			}
			$this->exit_status = proc_close($this->handle);
			unset($this->handle);
			if($this->errors) {
				echo $this->errors;
				$this->output = '';
			}
			return array('done' => true, 'output' => $this->output);
		}
	}

	/**
	 * Check the exit status of the client process.
	 * If the process exited unsuccessfully, set the sync status to failure.
	 * In any case, delete the sync request.
	 */
	public function finish() {
		global $server_dir, $sync_request_dir;
		if(!is_null($this->request)) {
			$this->get_data();
			if ($this->exit_status !== 0) {
				$server = $server_dir->get_server_by_id($this->request->server_id);
				$server->sync_report('sync failure', "Internal error during sync");
				$server->reschedule_sync_request();
				$server->update();
			}
			$sync_request_dir->delete_sync_request($this->request);
		}
	}
}
