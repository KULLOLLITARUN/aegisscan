<?php
// The same flows with the standard fix applied to each.
$page = basename($_GET['page']);
include("pages/" . $page);

$name = htmlspecialchars($_GET['name'], ENT_QUOTES);
echo "Hello " . $name;

$host = escapeshellarg($_POST['host']);
shell_exec("ping -c 1 " . $host);

function show($key) {
    $v = (int) $_REQUEST[$key];
    print $v;
}
