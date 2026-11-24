<?php
// A request value reaches a sink through a variable, not in one expression.
$page = $_GET['page'];
include($page);

$name = $_GET['name'];
echo "Hello " . $name;

$host = $_POST['host'];
shell_exec("ping -c 1 " . $host);

function show($key) {
    $v = $_REQUEST[$key];
    print $v;
}
