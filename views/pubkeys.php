<?php
##
## Copyright 2013-2017 Opera Software AS
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

$defaults = array();
$defaults['fingerprint'] = '';
$defaults['type'] = '';
$defaults['keysize-min'] = '';
$defaults['keysize-max'] = '';
$filter = simplify_search($defaults, $_GET);
$pubkeys = $pubkey_dir->list_public_keys(array(), $filter);

if(isset($router->vars['format']) && $router->vars['format'] == 'json') {
	$page = new PageSection('pubkeys_json');
	$page->set('pubkeys', $pubkeys);
	header('Content-type: text/plain; charset=utf-8');
	echo $page->generate();
} else {
	if (isset($_POST['allow'])) {
		$id = (int)$_POST['allow'];
		$key = ExternalKey::get_by_id($id);
		if ($key != null) {
			$key->status = 'allowed';
			$key->update();
		}
	} elseif (isset($_POST['deny'])) {
		$id = (int)$_POST['deny'];
		$key = ExternalKey::get_by_id($id);
		if ($key != null) {
			$key->status = 'denied';
			$key->update();
		}
	}
	$content = new PageSection('pubkeys');
	$content->set('filter', $filter);
	$content->set('pubkeys', $pubkeys);
	$content->set('admin', $active_user->admin);
	$external_keys = ExternalKey::list_external_keys(true);
	$new_keys = array_filter($external_keys, function($key) { return $key->status == 'new'; });
	$allowed_keys = array_filter($external_keys, function($key) { return $key->status == 'allowed'; });
	$denied_keys = array_filter($external_keys, function($key) { return $key->status == 'denied'; });
	$content->set('new_keys', $new_keys);
	$content->set('supervise_errors', $server_dir->list_servers([], ['key_supervision_error' => 'not-null']));
	$content->set('allowed_keys', $allowed_keys);
	$content->set('denied_keys', $denied_keys);

	$page = new PageSection('base');
	$page->set('title', 'Public keys');
	$page->set('content', $content);
	$page->set('alerts', $active_user->pop_alerts());
	echo $page->generate();
}
