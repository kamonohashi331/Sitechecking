<?php
session_start();

// Admin credentials (in a real app, store these securely in a database with hashed passwords)
$admin_username = "Alif12";
$admin_password = "127812"; // Change this to a strong password

// Handle admin login
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    if ($_POST['username'] === $admin_username && $_POST['password'] === $admin_password) {
        $_SESSION['admin_logged_in'] = true;
        header("Location: admin.php");
        exit;
    } else {
        $login_error = "Invalid username or password";
    }
}

// Check if admin is logged in
$is_logged_in = isset($_SESSION['admin_logged_in']) && $_SESSION['admin_logged_in'] === true;

// Logout functionality
if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: admin.php");
    exit;
}

// Function to get all user uploads
function getAllUserUploads() {
    $uploads = [];
    $user_folders = glob("uploads/*", GLOB_ONLYDIR);
    
    foreach ($user_folders as $folder) {
        $user_ip = basename($folder);
        $files = array_diff(scandir($folder), ['.', '..']);
        
        foreach ($files as $file) {
            $file_path = "$folder/$file";
            $file_size = filesize($file_path);
            $upload_time = date("Y-m-d H:i:s", filemtime($file_path));
            
            $uploads[] = [
                'user_ip' => $user_ip,
                'filename' => $file,
                'filepath' => $file_path,
                'size' => $file_size,
                'upload_time' => $upload_time,
                'extension' => pathinfo($file, PATHINFO_EXTENSION)
            ];
        }
    }
    
    // Sort by upload time (newest first)
    usort($uploads, function($a, $b) {
        return strtotime($b['upload_time']) - strtotime($a['upload_time']);
    });
    
    return $uploads;
}

// Handle file actions (delete, ban)
if ($is_logged_in && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['delete_file'])) {
        $file_path = $_POST['file_path'];
        if (file_exists($file_path)) {
            unlink($file_path);
            $_SESSION['admin_message'] = "File deleted successfully";
        }
    }
    
    if (isset($_POST['ban_user'])) {
        $user_ip = $_POST['user_ip'];
        $banned_users = file_exists('banned_users.txt') ? file('banned_users.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
        
        if (!in_array($user_ip, $banned_users)) {
            file_put_contents('banned_users.txt', $user_ip . PHP_EOL, FILE_APPEND);
            $_SESSION['admin_message'] = "User $user_ip has been banned";
        } else {
            $_SESSION['admin_message'] = "User $user_ip is already banned";
        }
    }
    
    header("Location: admin.php");
    exit;
}

// Get all uploads if logged in
$all_uploads = $is_logged_in ? getAllUserUploads() : [];
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Panel - SERA HOSTING</title>
    <!-- Bootstrap 5 CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Font Awesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary-color: #6c5ce7;
            --secondary-color: #a29bfe;
            --dark-color: #2d3436;
            --danger-color: #d63031;
        }
        
        body {
            background-color: #f8f9fa;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        .login-container {
            max-width: 400px;
            margin: 100px auto;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        
        .admin-header {
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            color: white;
        }
        
        .file-icon {
            font-size: 1.5rem;
            margin-right: 10px;
        }
        
        .file-row:hover {
            background-color: rgba(108, 92, 231, 0.05);
        }
        
        .badge-html { background-color: #e34f26; }
        .badge-php { background-color: #777bb4; }
        .badge-js { background-color: #f7df1e; color: #000; }
        .badge-css { background-color: #1572b6; }
        .badge-txt { background-color: #6c757d; }
        .badge-other { background-color: #6c757d; }
        
        .file-size {
            font-family: monospace;
        }
    </style>
</head>
<body>
    <?php if (!$is_logged_in): ?>
    <!-- Login Form -->
    <div class="container">
        <div class="card login-container">
            <div class="card-body p-4">
                <h2 class="text-center mb-4">
                    <i class="fas fa-lock me-2"></i>Admin Login
                </h2>
                
                <?php if (isset($login_error)): ?>
                    <div class="alert alert-danger">
                        <?= $login_error ?>
                    </div>
                <?php endif; ?>
                
                <form method="POST">
                    <div class="mb-3">
                        <label for="username" class="form-label">Username</label>
                        <input type="text" class="form-control" id="username" name="username" required>
                    </div>
                    <div class="mb-3">
                        <label for="password" class="form-label">Password</label>
                        <input type="password" class="form-control" id="password" name="password" required>
                    </div>
                    <button type="submit" name="login" class="btn btn-primary w-100">
                        <i class="fas fa-sign-in-alt me-2"></i>Login
                    </button>
                </form>
            </div>
        </div>
    </div>
    <?php else: ?>
    <!-- Admin Panel -->
    <div class="container-fluid p-0">
        <!-- Header -->
        <header class="admin-header p-3">
            <div class="container">
                <div class="d-flex justify-content-between align-items-center">
                    <h1 class="h4 mb-0">
                        <i class="fas fa-user-shield me-2"></i>Admin Panel
                    </h1>
                    <a href="admin.php?logout=1" class="btn btn-light btn-sm">
                        <i class="fas fa-sign-out-alt me-1"></i>Logout
                    </a>
                </div>
            </div>
        </header>
        
        <!-- Main Content -->
        <div class="container py-4">
            <?php if (isset($_SESSION['admin_message'])): ?>
                <div class="alert alert-success alert-dismissible fade show">
                    <?= $_SESSION['admin_message'] ?>
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                </div>
                <?php unset($_SESSION['admin_message']); ?>
            <?php endif; ?>
            
            <div class="card shadow-sm">
                <div class="card-header bg-white">
                    <div class="d-flex justify-content-between align-items-center">
                        <h2 class="h5 mb-0">
                            <i class="fas fa-file-upload me-2"></i>All User Uploads
                        </h2>
                        <span class="badge bg-primary">
                            <?= count($all_uploads) ?> files
                        </span>
                    </div>
                </div>
                <div class="card-body p-0">
                    <div class="table-responsive">
                        <table class="table table-hover mb-0">
                            <thead class="table-light">
                                <tr>
                                    <th>File</th>
                                    <th>User IP</th>
                                    <th>Upload Time</th>
                                    <th>Size</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php if (count($all_uploads) > 0): ?>
                                    <?php foreach ($all_uploads as $upload): 
                                        $icon_class = '';
                                        $badge_class = '';
                                        
                                        switch ($upload['extension']) {
                                            case 'html': $icon_class = 'fab fa-html5'; $badge_class = 'badge-html'; break;
                                            case 'php': $icon_class = 'fab fa-php'; $badge_class = 'badge-php'; break;
                                            case 'js': $icon_class = 'fab fa-js'; $badge_class = 'badge-js'; break;
                                            case 'css': $icon_class = 'fab fa-css3-alt'; $badge_class = 'badge-css'; break;
                                            case 'txt': $icon_class = 'fas fa-file-alt'; $badge_class = 'badge-txt'; break;
                                            default: $icon_class = 'fas fa-file'; $badge_class = 'badge-other'; break;
                                        }
                                        
                                        $size = $upload['size'] < 1024 ? 
                                            $upload['size'] . ' B' : 
                                            round($upload['size'] / 1024, 2) . ' KB';
                                    ?>
                                    <tr class="file-row">
                                        <td>
                                            <div class="d-flex align-items-center">
                                                <i class="<?= $icon_class ?> file-icon"></i>
                                                <div>
                                                    <div class="fw-bold"><?= $upload['filename'] ?></div>
                                                    <span class="badge <?= $badge_class ?>"><?= strtoupper($upload['extension']) ?></span>
                                                </div>
                                            </div>
                                        </td>
                                        <td><?= $upload['user_ip'] ?></td>
                                        <td><?= $upload['upload_time'] ?></td>
                                        <td class="file-size"><?= $size ?></td>
                                        <td>
                                            <div class="d-flex">
                                                <a href="<?= $upload['filepath'] ?>" target="_blank" class="btn btn-sm btn-outline-primary me-2" title="View">
                                                    <i class="fas fa-eye"></i>
                                                </a>
                                                <form method="POST" class="me-2">
                                                    <input type="hidden" name="file_path" value="<?= $upload['filepath'] ?>">
                                                    <button type="submit" name="delete_file" class="btn btn-sm btn-outline-danger" title="Delete" onclick="return confirm('Are you sure you want to delete this file?')">
                                                        <i class="fas fa-trash-alt"></i>
                                                    </button>
                                                </form>
                                                <form method="POST">
                                                    <input type="hidden" name="user_ip" value="<?= $upload['user_ip'] ?>">
                                                    <button type="submit" name="ban_user" class="btn btn-sm btn-outline-dark" title="Ban User" onclick="return confirm('Are you sure you want to ban this user?')">
                                                        <i class="fas fa-ban"></i>
                                                    </button>
                                                </form>
                                            </div>
                                        </td>
                                    </tr>
                                    <?php endforeach; ?>
                                <?php else: ?>
                                    <tr>
                                        <td colspan="5" class="text-center py-4 text-muted">
                                            <i class="fas fa-folder-open fa-3x mb-3"></i>
                                            <p>No files have been uploaded yet.</p>
                                        </td>
                                    </tr>
                                <?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
            
            <!-- Banned Users Section -->
            <div class="card shadow-sm mt-4">
                <div class="card-header bg-white">
                    <h2 class="h5 mb-0">
                        <i class="fas fa-ban me-2"></i>Banned Users
                    </h2>
                </div>
                <div class="card-body">
                    <?php if (file_exists('banned_users.txt')): 
                        $banned_users = file('banned_users.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                    ?>
                        <?php if (count($banned_users) > 0): ?>
                            <div class="list-group">
                                <?php foreach ($banned_users as $ip): ?>
                                <div class="list-group-item d-flex justify-content-between align-items-center">
                                    <span><?= $ip ?></span>
                                    <form method="POST" action="unban_user.php">
                                        <input type="hidden" name="ip" value="<?= $ip ?>">
                                        <button type="submit" class="btn btn-sm btn-success">
                                            <i class="fas fa-check me-1"></i>Unban
                                        </button>
                                    </form>
                                </div>
                                <?php endforeach; ?>
                            </div>
                        <?php else: ?>
                            <p class="text-muted">No banned users.</p>
                        <?php endif; ?>
                    <?php else: ?>
                        <p class="text-muted">No banned users.</p>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>
    <?php endif; ?>

    <!-- Bootstrap JS Bundle with Popper -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>