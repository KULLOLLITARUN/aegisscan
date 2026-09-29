<?php
$db = new mysqli("localhost", "root", "Sup3rS3cret-Prod!", "shop");

$id = $_GET['id'];
$res = $db->query("SELECT * FROM products WHERE id = " . $id);

echo "<h1>Results for " . $_GET['q'] . "</h1>";

include($_GET['page'] . ".php");

$prefs = unserialize($_COOKIE['prefs']);

$hash = md5($_POST['password']);

if (isset($_POST['file'])) {
    system("convert " . $_POST['file'] . " out.png");
}

eval($_POST['formula']);
