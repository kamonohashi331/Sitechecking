<?php
session_start();

// Check if admin is logged in
if (!isset($_SESSION['admin_logged_in']) || $_SESSION['admin_logged_in'] !== true) {
    header("Location: admin.php");
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['ip'])) {
    $ip_to_unban = trim($_POST['ip']);
    
    if (file_exists('banned_users.txt')) {
        $banned_users = file('banned_users.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $updated_list = array_diff($banned_users, [$ip_to_unban]);
        
        file_put_contents('banned_users.txt', implode(PHP_EOL, $updated_list));
        $_SESSION['admin_message'] = "User $ip_to_unban has been unbanned";
    }
}

header("Location: admin.php");
exit;