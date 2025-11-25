<?php
session_start();

// Get client IP (considering proxy headers for more accurate IP)
function getClientIP() {
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        return $_SERVER['HTTP_CLIENT_IP'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        return $_SERVER['HTTP_X_FORWARDED_FOR'];
    } else {
        return $_SERVER['REMOTE_ADDR'];
    }
}

$ip = getClientIP();
$is_banned = false;

// Check if IP is banned
if (file_exists('banned_users.txt')) {
    $banned_ips = file('banned_users.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $is_banned = in_array($ip, $banned_ips);
}

// If not banned, redirect to index.php
if (!$is_banned) {
    header("Location: index.php");
    exit;
}

// Log banned access attempt
$log = date('Y-m-d H:i:s') . " | Banned IP tried to access: $ip\n";
file_put_contents('ban_log.txt', $log, FILE_APPEND);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Restricted - SERA HOSTING</title>
    <!-- Bootstrap 5 CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Font Awesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --danger-color: #d63031;
        }
        
        body {
            background-color: #f8f9fa;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            height: 100vh;
            display: flex;
            align-items: center;
        }
        
        .ban-container {
            max-width: 600px;
            margin: 0 auto;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .ban-header {
            background-color: var(--danger-color);
            color: white;
            padding: 2rem;
            text-align: center;
        }
        
        .ban-body {
            background: white;
            padding: 2rem;
        }
        
        .ban-icon {
            font-size: 5rem;
            margin-bottom: 1rem;
            color: var(--danger-color);
        }
        
        .ip-address {
            font-family: monospace;
            background: #f1f1f1;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="ban-container">
            <div class="ban-header">
                <h1><i class="fas fa-ban"></i> Access Restricted</h1>
            </div>
            <div class="ban-body text-center">
                <div class="ban-icon">
                    <i class="fas fa-lock"></i>
                </div>
                <h2 class="mb-3">Your access has been restricted</h2>
                <p class="lead mb-4">
                    The IP address <span class="ip-address"><?= htmlspecialchars($ip) ?></span> has been banned from this service.
                </p>
                
                <div class="alert alert-danger mb-4">
                    <i class="fas fa-exclamation-triangle me-2"></i>
                    You are not allowed to upload or access files on this platform.
                </div>
                
                <div class="d-flex justify-content-center">
                    <a href="mailto:admin@example.com" class="btn btn-outline-danger me-3">
                        <i class="fas fa-envelope me-2"></i>Contact Admin
                    </a>
                    <a href="index.php" class="btn btn-primary">
                        <i class="fas fa-home me-2"></i>Return Home
                    </a>
                </div>
            </div>
        </div>
    </div>

    <!-- Bootstrap JS Bundle with Popper -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>