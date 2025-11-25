<?php
session_start();

// Redirect to index.php after refresh to prevent form resubmission
if (!isset($_SESSION['prevent_duplicate'])) {
    if (isset($_GET['success']) || isset($_GET['error']) || isset($_GET['delete_success']) || isset($_GET['edit_success'])) {
        $_SESSION['prevent_duplicate'] = true;
        header("Refresh:5; url=index.php");
    }
} else {
    unset($_SESSION['prevent_duplicate']);
    header("Location: index.php");
    exit();
}

$ip = $_SERVER['REMOTE_ADDR'];
$upload_dir = "uploads/" . md5($ip) . "/";
if (!file_exists($upload_dir)) {
    mkdir($upload_dir, 0777, true);
}
$uploaded_files = [];

// File Upload Handling
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Handle file upload
    if (isset($_FILES['file'])) {
        $file = $_FILES['file'];
        $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));

        // Allowed extensions (excluding PHP)
        $allowed_extensions = ['html', 'htm', 'js', 'txt', 'css'];
        
        if (in_array($ext, $allowed_extensions)) {
            $filename = time() . "_" . basename($file['name']);
            $destination = $upload_dir . $filename;
            
            // Additional security check for PHP content
            $file_content = file_get_contents($file['tmp_name']);
            if (strpos($file_content, '<?php') !== false) {
                header("Location: index.php?error=2");
                exit;
            }
            
            move_uploaded_file($file['tmp_name'], $destination);

            $log = date('Y-m-d H:i:s') . " | $ip | $filename\n";
            file_put_contents("upload_log.txt", $log, FILE_APPEND);

            header("Location: index.php?success=1");
            exit;
        } else {
            header("Location: index.php?error=1");
            exit;
        }
    }
    
    // Handle file edit/save
    if (isset($_POST['save_file'])) {
        $filename = basename($_POST['filename']);
        $content = $_POST['file_content'];
        $filepath = $upload_dir . $filename;
        
        // Prevent saving PHP content
        if (strpos($content, '<?php') !== false) {
            header("Location: index.php?error=2");
            exit;
        }
        
        if (file_exists($filepath)) {
            file_put_contents($filepath, $content);
            header("Location: index.php?edit_success=1&file=" . urlencode($filename));
            exit;
        }
    }
}

// Handle file deletion
if (isset($_GET['delete'])) {
    $filename = basename($_GET['delete']);
    $filepath = $upload_dir . $filename;
    
    if (file_exists($filepath)) {
        unlink($filepath);
        header("Location: index.php?delete_success=1");
        exit;
    }
}

if (file_exists($upload_dir)) {
    $uploaded_files = array_diff(scandir($upload_dir), ['.', '..']);
}

// Get file content for editing
$file_content = '';
$editing_file = '';
if (isset($_GET['edit'])) {
    $filename = basename($_GET['edit']);
    $filepath = $upload_dir . $filename;
    
    if (file_exists($filepath)) {
        $editing_file = $filename;
        $file_content = htmlspecialchars(file_get_contents($filepath));
    }
}

// Get IP location information
$ip_info = [];
if (function_exists('curl_init')) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "http://ip-api.com/json/{$ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    $response = curl_exec($ch);
    curl_close($ch);
    $ip_info = json_decode($response, true);
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hoster BD - Free Web Hosting</title>
    <!-- Bootstrap 5 CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Font Awesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <!-- Animate.css -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/animate.css/4.1.1/animate.min.css">
    <!-- Highlight.js for code editing -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.7.0/styles/atom-one-dark.min.css">
    <!-- Siliguri Font -->
    <link href="https://fonts.googleapis.com/css2?family=Hind+Siliguri:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary-color: #6c5ce7;
            --secondary-color: #a29bfe;
            --dark-color: #2d3436;
            --light-color: #f5f6fa;
            --success-color: #00b894;
            --danger-color: #d63031;
        }
        
        body {
            background-color: #f8f9fa;
            font-family: 'Hind Siliguri', sans-serif;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }
        
        .navbar-brand {
            font-weight: 700;
            color: var(--primary-color) !important;
        }
        
        .hero-section {
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            color: white;
            padding: 3rem 0;
            border-radius: 0 0 20px 20px;
            margin-bottom: 2rem;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .upload-card {
            border: none;
            border-radius: 15px;
            box-shadow: 0 10px 20px rgba(0,0,0,0.1);
            transition: transform 0.3s, box-shadow 0.3s;
            margin-bottom: 2rem;
            background: white;
            overflow: hidden;
        }
        
        .upload-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 30px rgba(0,0,0,0.15);
        }
        
        .card-header {
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            color: white;
            font-weight: 600;
        }
        
        .file-list {
            max-height: 400px;
            overflow-y: auto;
        }
        
        .file-item {
            transition: all 0.3s;
            border-left: 4px solid var(--primary-color);
            margin-bottom: 10px;
            border-radius: 8px;
        }
        
        .file-item:hover {
            background-color: rgba(108, 92, 231, 0.1);
            transform: translateX(5px);
        }
        
        .file-icon {
            font-size: 1.5rem;
            margin-right: 10px;
            color: var(--primary-color);
        }
        
        .loading-spinner {
            display: none;
            width: 3rem;
            height: 3rem;
        }
        
        footer {
            background-color: var(--dark-color);
            color: white;
            padding: 2rem 0;
            margin-top: auto;
            font-family: 'Hind Siliguri', sans-serif;
        }
        
        /* Drag and drop area */
        .dropzone {
            border: 2px dashed var(--secondary-color);
            border-radius: 10px;
            padding: 2rem;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s;
            background: rgba(162, 155, 254, 0.05);
        }
        
        .dropzone:hover, .dropzone.dragover {
            background: rgba(162, 155, 254, 0.1);
            border-color: var(--primary-color);
        }
        
        .dropzone i {
            font-size: 3rem;
            color: var(--primary-color);
            margin-bottom: 1rem;
        }
        
        /* Code editor */
        .editor-container {
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        
        .editor-header {
            background: var(--dark-color);
            color: white;
            padding: 0.5rem 1rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-family: 'Hind Siliguri', sans-serif;
        }
        
        .editor-body {
            background: #282c34;
        }
        
        textarea.code-editor {
            width: 100%;
            min-height: 300px;
            background: #282c34;
            color: #abb2bf;
            border: none;
            padding: 1rem;
            font-family: 'Courier New', Courier, monospace;
            resize: vertical;
        }
        
        /* Action buttons */
        .btn-action {
            border-radius: 50%;
            width: 40px;
            height: 40px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            margin: 0 5px;
        }
        
        /* IP Info Card */
        .ip-info-card {
            background: linear-gradient(135deg, #2d3436, #636e72);
            color: white;
            border-radius: 10px;
        }
        
        /* Live Preview */
        .preview-container {
            border: 1px solid #ddd;
            border-radius: 5px;
            height: 300px;
            overflow-y: auto;
            background: white;
        }
        
        /* Custom buttons */
        .btn-custom {
            font-family: 'Hind Siliguri', sans-serif;
            font-weight: 500;
            letter-spacing: 0.5px;
            padding: 0.5rem 1.5rem;
            border-radius: 8px;
            transition: all 0.3s;
        }
        
        .btn-primary {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
        }
        
        .btn-primary:hover {
            background-color: #5a4bc2;
            border-color: #5a4bc2;
        }
        
        /* Alert customization */
        .alert {
            font-family: 'Hind Siliguri', sans-serif;
            border-radius: 8px;
        }
        
        @media (max-width: 768px) {
            .hero-section {
                padding: 2rem 0;
            }
            
            .display-4 {
                font-size: 2.2rem;
            }
            
            .dropzone {
                padding: 1.5rem;
            }
        }
    </style>

</head>
<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-light bg-white shadow-sm">
        <div class="container">
            <a class="navbar-brand animate__animated animate__fadeIn" href="index.php">
                <i class="fas fa-cloud-upload-alt me-2"></i>HOSTER BD
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="html-editor.html">
                            <i class="fab fa-html5 me-1"></i>HTML Editor
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="php-editor.html">
                            <i class="fab fa-php me-1"></i>PHP Editor
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="ip-info.html">
                            <i class="fas fa-map-marker-alt me-1"></i>IP Location
                        </a>
                    </li>
                </ul>
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item">
                        <span class="nav-link">
                            <i class="fas fa-user-circle me-1"></i><?= $ip ?>
                        </span>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <!-- Hero Section -->
    <section class="hero-section animate__animated animate__fadeIn">
        <div class="container text-center">
            <h1 class="display-4 fw-bold mb-3">
                <i class="fas fa-cloud me-2"></i>Free File Hosting
            </h1>
            <p class="lead">Upload, edit and share your web files with the world</p>
        </div>
    </section>

    <!-- Main Content -->
    <div class="container mb-5">
        <!-- File Editor (shown when editing) -->
        <?php if ($editing_file): ?>
        <div class="card upload-card animate__animated animate__fadeInUp mb-4">
            <div class="card-header">
                <div class="d-flex justify-content-between align-items-center">
                    <h3 class="card-title mb-0">
                        <i class="fas fa-edit me-2"></i>Editing: <?= $editing_file ?>
                    </h3>
                    <a href="index.php" class="btn btn-outline-light btn-sm">
                        <i class="fas fa-times me-1"></i> Cancel
                    </a>
                </div>
            </div>
            <div class="card-body p-4">
                <?php if (isset($_GET['edit_success'])): ?>
                    <div class="alert alert-success animate__animated animate__bounceIn">
                        <i class="fas fa-check-circle me-2"></i>✅ File saved successfully!
                    </div>
                <?php endif; ?>
                
                <form method="POST">
                    <input type="hidden" name="filename" value="<?= $editing_file ?>">
                    <div class="editor-container">
                        <div class="editor-header">
                            <span><?= $editing_file ?></span>
                            <span class="badge bg-light text-dark">
                                <?= strtoupper(pathinfo($editing_file, PATHINFO_EXTENSION)) ?>
                            </span>
                        </div>
                        <div class="editor-body">
                            <textarea name="file_content" class="code-editor"><?= $file_content ?></textarea>
                        </div>
                    </div>
                    <div class="mt-3 text-end">
                        <button type="submit" name="save_file" class="btn btn-success btn-lg btn-custom">
                            <i class="fas fa-save me-1"></i> Save Changes
                        </button>
                    </div>
                </form>
            </div>
        </div>
        <?php endif; ?>

        <!-- Upload Card (shown when not editing) -->
        <?php if (!$editing_file): ?>
        <div class="card upload-card animate__animated animate__fadeInUp">
            <div class="card-header">
                <h3 class="card-title mb-0">
                    <i class="fas fa-upload me-2"></i>Upload Your Files
                </h3>
            </div>
            <div class="card-body p-4">
                <?php if (isset($_GET['success'])): ?>
                    <div class="alert alert-success animate__animated animate__bounceIn">
                        <i class="fas fa-check-circle me-2"></i>✅ File uploaded successfully!
                        <div class="small mt-1">Page will refresh in 5 seconds...</div>
                    </div>
                <?php elseif (isset($_GET['error'])): ?>
                    <div class="alert alert-danger animate__animated animate__shakeX">
                        <?php if ($_GET['error'] == '1'): ?>
                            <i class="fas fa-exclamation-circle me-2"></i>❌ Only .html, .js, .txt, .css files are allowed!
                        <?php elseif ($_GET['error'] == '2'): ?>
                            <i class="fas fa-exclamation-circle me-2"></i>❌ PHP content is not allowed in files!
                        <?php endif; ?>
                        <div class="small mt-1">Page will refresh in 5 seconds...</div>
                    </div>
                <?php elseif (isset($_GET['delete_success'])): ?>
                    <div class="alert alert-info animate__animated animate__bounceIn">
                        <i class="fas fa-trash-alt me-2"></i>🗑️ File deleted successfully!
                        <div class="small mt-1">Page will refresh in 5 seconds...</div>
                    </div>
                <?php endif; ?>
                
                <div class="dropzone mb-4" id="dropzone">
                    <i class="fas fa-cloud-upload-alt"></i>
                    <h4>Drag & Drop Files Here</h4>
                    <p class="text-muted">or click to browse files</p>
                    <p class="small text-muted">Supported formats: .html, .js, .txt, .css (PHP not allowed)</p>
                </div>
                
                <form method="POST" enctype="multipart/form-data" id="uploadForm">
                    <input type="file" name="file" id="fileInput" class="d-none" required>
                    <div class="d-flex justify-content-between align-items-center">
                        <div id="fileInfo" class="text-muted">No file selected</div>
                        <button type="submit" class="btn btn-primary btn-lg btn-custom" id="uploadBtn">
                            <span id="btnText">Upload File</span>
                            <div class="spinner-border text-light loading-spinner" role="status" id="loadingSpinner">
                                <span class="visually-hidden">Loading...</span>
                            </div>
                        </button>
                    </div>
                </form>
            </div>
        </div>

        <!-- File List -->
        <div class="card animate__animated animate__fadeInUp animate__delay-1s">
            <div class="card-header">
                <div class="d-flex justify-content-between align-items-center">
                    <h3 class="card-title mb-0">
                        <i class="fas fa-folder-open me-2"></i>Your Files
                    </h3>
                    <span class="badge bg-light text-dark">
                        <?= count($uploaded_files) ?> file<?= count($uploaded_files) !== 1 ? 's' : '' ?>
                    </span>
                </div>
            </div>
            <div class="card-body p-4">
                <?php if (count($uploaded_files) > 0): ?>
                    <div class="file-list">
                        <div class="list-group">
                            <?php foreach ($uploaded_files as $file): 
                                $ext = pathinfo($file, PATHINFO_EXTENSION);
                                $icon = '';
                                if ($ext === 'html' || $ext === 'htm') $icon = 'fab fa-html5';
                                elseif ($ext === 'js') $icon = 'fab fa-js';
                                elseif ($ext === 'css') $icon = 'fab fa-css3-alt';
                                elseif ($ext === 'txt') $icon = 'fas fa-file-alt';
                                else $icon = 'fas fa-file';
                                
                                $filesize = filesize($upload_dir . $file);
                                $filesize = $filesize < 1024 ? $filesize . ' bytes' : round($filesize / 1024, 2) . ' KB';
                            ?>
                            <div class="list-group-item file-item mb-2">
                                <div class="d-flex align-items-center">
                                    <i class="<?= $icon ?> file-icon"></i>
                                    <div class="flex-grow-1">
                                        <div class="fw-bold"><?= $file ?></div>
                                        <small class="text-muted"><?= $filesize ?> • <?= date("M d, Y H:i", filemtime($upload_dir . $file)) ?></small>
                                    </div>
                                    <div class="btn-group">
                                        <a href="<?= "uploads/" . md5($ip) . "/$file" ?>" target="_blank" class="btn btn-sm btn-outline-primary" data-bs-toggle="tooltip" title="View">
                                            <i class="fas fa-eye"></i>
                                        </a>
                                        <a href="index.php?edit=<?= urlencode($file) ?>" class="btn btn-sm btn-outline-success" data-bs-toggle="tooltip" title="Edit">
                                            <i class="fas fa-edit"></i>
                                        </a>
                                        <a href="index.php?delete=<?= urlencode($file) ?>" class="btn btn-sm btn-outline-danger" data-bs-toggle="tooltip" title="Delete" onclick="return confirm('Are you sure you want to delete this file?')">
                                            <i class="fas fa-trash-alt"></i>
                                        </a>
                                    </div>
                                </div>
                            </div>
                            <?php endforeach; ?>
                        </div>
                    </div>
                <?php else: ?>
                    <div class="text-center py-4">
                        <i class="fas fa-folder-open fa-3x mb-3 text-muted"></i>
                        <p class="text-muted">No files uploaded yet. Upload your first file above!</p>
                    </div>
                <?php endif; ?>
            </div>
        </div>
        <?php endif; ?>
    </div>

    <!-- Footer -->
    <footer class="animate__animated animate__fadeIn animate__delay-1s">
        <div class="container text-center">
            <h4><i class="fas fa-cloud me-2"></i>HOSTER BD</h4>
            <p class="mb-3">Free file hosting with editing capabilities</p>
            <div class="social-icons mb-3">
                <a href="https://bj-x-coder.top/Free_HosterBD/index.php" class="text-white me-3"><i class="fas fa-globe"></i></a>
                <a href="https://t.me/+QLH5pM1tTs02YWI1" class="text-white me-3"><i class="fab fa-telegram-plane"></i></a>
            </div>
            <p class="small">&copy; <?= date('Y') ?> HOSTER BD. All rights reserved.</p>
        </div>
    </footer>

<script>
// Always show popup on page load
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('join-popup').classList.remove('hidden');

    document.getElementById('close-popup').addEventListener('click', () => {
        document.getElementById('join-popup').classList.add('hidden');
    });
});
</script>

    <!-- Bootstrap JS Bundle with Popper -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <!-- Highlight.js for syntax highlighting -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.7.0/highlight.min.js"></script>
    
    <script>
        // Initialize tooltips
        const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
        
        // Drag and drop functionality
        const dropzone = document.getElementById('dropzone');
        const fileInput = document.getElementById('fileInput');
        
        dropzone.addEventListener('click', () => fileInput.click());
        
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dropzone.addEventListener(eventName, preventDefaults, false);
        });
        
        function preventDefaults(e) {
            e.preventDefault();
            e.stopPropagation();
        }
        
        ['dragenter', 'dragover'].forEach(eventName => {
            dropzone.addEventListener(eventName, highlight, false);
        });
        
        ['dragleave', 'drop'].forEach(eventName => {
            dropzone.addEventListener(eventName, unhighlight, false);
        });
        
        function highlight() {
            dropzone.classList.add('dragover');
        }
        
        function unhighlight() {
            dropzone.classList.remove('dragover');
        }
        
        dropzone.addEventListener('drop', handleDrop, false);
        
        function handleDrop(e) {
            const dt = e.dataTransfer;
            const files = dt.files;
            
            if (files.length) {
                fileInput.files = files;
                updateFileInfo(files[0]);
            }
        }
        
        fileInput.addEventListener('change', function() {
            if (this.files.length) {
                updateFileInfo(this.files[0]);
            }
        });
        
        function updateFileInfo(file) {
            const fileInfo = document.getElementById('fileInfo');
            fileInfo.innerHTML = `
                <i class="fas fa-file me-1"></i>
                <strong>${file.name}</strong> (${formatFileSize(file.size)})
            `;
        }
        
        function formatFileSize(bytes) {
            if (bytes < 1024) return bytes + ' bytes';
            else if (bytes < 1048576) return (bytes / 1024).toFixed(2) + ' KB';
            else return (bytes / 1048576).toFixed(2) + ' MB';
        }
        
        // Upload form handling
        document.getElementById('uploadForm').addEventListener('submit', function() {
            const btn = document.getElementById('uploadBtn');
            const spinner = document.getElementById('loadingSpinner');
            const btnText = document.getElementById('btnText');
            
            btn.disabled = true;
            btnText.textContent = 'Uploading...';
            spinner.style.display = 'inline-block';
        });
        
        // Add animation to file items on page load
        document.addEventListener('DOMContentLoaded', function() {
            const fileItems = document.querySelectorAll('.file-item');
            fileItems.forEach((item, index) => {
                item.style.animationDelay = `${index * 0.1}s`;
                item.classList.add('animate__animated', 'animate__fadeInRight');
            });
            
            // Apply syntax highlighting to code editor
            if (document.querySelector('.code-editor')) {
                document.querySelectorAll('.code-editor').forEach((editor) => {
                    editor.addEventListener('input', function() {
                        // You could add live syntax highlighting here if needed
                    });
                });
            }
        });
    </script>
    
    <script>function startWuiltWidget(){wuilt.initWidget({"appearance":{"content":{"closeText":"Close","openText":"Open","withText":false,"icon":"MessageDotsCircleSolid"},"display":{"showOnMobile":true,"showOnDesktop":true,"position":"Right","orientation":"Vertical","shift":{"horizontal":"22px","vertical":"15px"},"pages":{"type":"AllPages","displayOn":[],"hideOn":[]}},"style":{"size":"50px","radius":"60px","animation":"Bounce","shadow":{"color":"#FFFFF","opacity":0},"background":{"color":"#7A5AF8","gradient":false},"transparent":false,"border":{"color":"#FFFFFF","thickness":"0px"}}},"apps":[{"name":"Custom","value":"https://t.me/AlifXD1_Bot","onHoverText":"Custom","background":{"color":"#1D2939","gradient":false}},{"name":"Telegram","value":"+WKBHKp9Hx-ZhMjA1","onHoverText":"Telegram","background":{"color":"#2AABEE","gradient":false}}]})}</script><script src="https://buttons.wuilt.com/runtime.js" type="module"></script><script src="https://buttons.wuilt.com/widget.js" type="module" onload="startWuiltWidget()"></script>
    
</body>
</html>