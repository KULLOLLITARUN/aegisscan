<?php
$db = new mysqli("localhost", getenv("DB_USER"), getenv("DB_PASS"), "shop");

$stmt = $db->prepare("SELECT * FROM products WHERE id = ?");
$id = (int) ($_GET['id'] ?? 0);
$stmt->bind_param("i", $id);
$stmt->execute();

echo "<h1>Results for " . htmlspecialchars($_GET['q'] ?? '', ENT_QUOTES, 'UTF-8') . "</h1>";

$pages = ['home', 'about', 'contact'];
$page = $_GET['page'] ?? 'home';
if (in_array($page, $pages, true)) {
    include(__DIR__ . "/pages/" . $page . ".php");
}

$prefs = json_decode($_COOKIE['prefs'] ?? '{}', true);

$hash = password_hash($_POST['password'] ?? '', PASSWORD_DEFAULT);

if (isset($_POST['file']) && preg_match('/^[A-Za-z0-9_.-]+$/', $_POST['file'])) {
    system("convert " . escapeshellarg($_POST['file']) . " out.png");
}
