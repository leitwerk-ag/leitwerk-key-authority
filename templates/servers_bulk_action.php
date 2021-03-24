<?php
##
## Copyright 2021 Leitwerk AG
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
?>
<h1>Bulk Action for Servers</h1>
<p>You selected <?php out(count($this->data->server_names)) ?> <?php out($this->data->plural ? 'servers' : 'server') ?> to perform a bulk action.</p>

<div class="panel panel-default">
	<div class="panel-heading">
		<h3 class="panel-title">
			<a data-toggle="collapse" href="#server_list">
				Server list
			</a>
		</h3>
	</div>
	<div id="server_list" class="panel-collapse collapse">
		<div class="panel-body">
			<ul>
			<?php foreach ($this->data->server_names as $server_name) { ?>
				<li><?php out($server_name) ?></li>
			<?php } ?>
			</ul>
		</div>
	</div>
</div>

<form action="<?php outurl($this->data->relative_request_url)?>" method="post" class="form-inline">
	<?php out($this->get('active_user')->get_csrf_field(), ESC_NONE) ?>
	<?php foreach ($this->data->server_names as $server_name) { ?>
		<input type="hidden" name="selected_servers[]" value="<?php out($server_name) ?>">
	<?php } ?>

	<h3>Add a new leader to all selected servers</h3>
	<div class="form-group">
		<label for="user_name" class="sr-only">User or group name</label>
		<input type="text" id="user_name" name="user_name" class="form-control" placeholder="User or group name" required list="userlist">
		<datalist id="userlist">
			<?php foreach($this->get('all_users') as $user) { ?>
			<option value="<?php out($user->uid)?>" label="<?php out($user->name)?>">
			<?php } ?>
			<?php foreach($this->get('all_groups') as $group) { ?>
			<option value="<?php out($group->name)?>" label="<?php out($group->name)?>">
			<?php } ?>
		</datalist>
	</div>
	<button type="submit" name="add_admin" value="1" class="btn btn-primary">Add leader to selected <?php out($this->data->plural ? 'servers' : 'server') ?></button>
</form>

<h3>Remove leaders from all selected servers</h3>
<?php if(count($this->get('server_admins')) == 0) { ?>
<p class="alert alert-danger">The selected <?php out($this->data->plural ? 'servers do' : 'server does') ?> not have any leaders assigned.</p>
<?php } else { ?>
<form method="post" action="<?php outurl($this->data->relative_request_url)?>">
	<?php out($this->get('active_user')->get_csrf_field(), ESC_NONE) ?>
	<?php foreach ($this->data->server_names as $server_name) { ?>
		<input type="hidden" name="selected_servers[]" value="<?php out($server_name) ?>">
	<?php } ?>
	<table class="table table-bordered table-striped">
		<thead>
			<tr>
				<th>Entity</th>
				<th>Name</th>
				<th>Affected servers</th>
				<?php if($this->get('admin')) { ?>
				<th>Actions</th>
				<?php } ?>
			</tr>
		</thead>
		<tbody>
			<?php foreach($this->get('server_admins') as $tuple) {
				$admin = $tuple[0];
				$count_affected = $tuple[1];
				?>
				<?php if(strtolower(get_class($admin)) == "user"){?>
					<tr>
						<td><a href="<?php outurl('/users/'.urlencode($admin->uid))?>" class="user"><?php out($admin->uid) ?></a></td>
						<td><?php out($admin->name); if(!$admin->active) out(' <span class="label label-default">Inactive</span>', ESC_NONE) ?></td>
						<td><?php out($count_affected) ?></td>
						<td>
							<button type="submit" name="delete_admin" value="<?php out($admin->id) ?>" class="btn btn-default btn-xs"><span class="glyphicon glyphicon-trash"></span> Remove leader</button>
						</td>
					</tr>
				<?php } elseif(strtolower(get_class($admin)) == "group"){ ?>
					<tr>
						<td><a href="<?php outurl('/groups/'.urlencode($admin->name))?>" class="group"><?php out($admin->name) ?></a></td>
						<td><?php out($admin->name); if(!$admin->active) out(' <span class="label label-default">Inactive</span>', ESC_NONE) ?></td>
						<td><?php out($count_affected) ?></td>
						<td>
							<button type="submit" name="delete_admin" value="<?php out($admin->id) ?>" class="btn btn-default btn-xs"><span class="glyphicon glyphicon-trash"></span> Remove leader</button>
						</td>
					</tr>
				<?php }} ?>
		</tbody>
	</table>
</form>
<?php } ?>
