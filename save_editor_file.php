<?php
session_start();

$ip = $_SERVER['REMOTE_ADDR'];
$upload_dir = "uploads/" . md5($ip) . "/";
if (!file_exists($upload_dir)) {
    mkdir($upload_dir, 0777, true);
}

$response = ['success' => false, 'message' => ''];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $filename = basename($_POST['filename']);
    $content = $_POST['file_content'];
    $filepath = $upload_dir . $filename;
    
    if (file_put_contents($filepath, $content)) {
        $response['success'] = true;
        $response['message'] = 'File saved successfully';
        
        $log = date('Y-m-d H:i:s') . " | $ip | $filename (created via editor)\n";
        file_put_contents("upload_log.txt", $log, FILE_APPEND);
    } else {
        $response['message'] = 'Failed to save file';
    }
} else {
    $response['message'] = 'Invalid request method';
}

header('Content-Type: application/json');
echo json_encode($response);
?>