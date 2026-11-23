<?php
// Safe look-alikes for more_sinks.php: nothing here may be flagged.
$allowed = ['name', 'email'];
$data = array_intersect_key($_POST, array_flip($allowed));
extract($data, EXTR_SKIP);

$next = $_GET['next'] ?? '/';
if (strpos($next, '/') !== 0 || strpos($next, '//') === 0) {
    $next = '/';
}
header("Location: " . $next);
header("Content-Type: text/plain");

$f = basename($_GET['f'] ?? '');
$doc = file_get_contents(__DIR__ . "/files/" . $f);
readfile(__DIR__ . "/files/" . basename($_GET['download'] ?? ''));

$digest = password_hash($_POST['password'] ?? '', PASSWORD_DEFAULT);
$etag = md5($doc);
$checksum = sha1($f);

$settings = json_decode($_POST['settings'] ?? '{}', true);
$cached = unserialize(file_get_contents(__DIR__ . "/cache.bin"), ['allowed_classes' => false]);

$fp = fopen(__DIR__ . "/app.log", 'r');
