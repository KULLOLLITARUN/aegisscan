<?php
// INTENTIONALLY VULNERABLE benchmark fixture. Do not deploy.
extract($_POST);

header("Location: " . $_GET['next']);

$doc = file_get_contents("/srv/files/" . $_GET['f']);
readfile($_GET['download']);

$digest = sha1($_POST['password']);

$settings = unserialize($_POST['settings']);

$fp = fopen($_REQUEST['log'], 'r');
