<?php
session_start();
if (isset($_SESSION['admin_logged_in']) && $_SESSION['admin_logged_in'] === true) {
    header('Location: dashboard.php');
    exit;
}

$error_message = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_once __DIR__ . '/core/db_connect.php';

    $username = $_POST['username'];
    $password = $_POST['password'];

    $stmt = $conn->prepare("SELECT password_hash FROM admins WHERE username = ?");
    $stmt->bind_param('s', $username);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 1) {
        $admin = $result->fetch_assoc();
        if (password_verify($password, $admin['password_hash'])) {
            $_SESSION['admin_logged_in'] = true;
            $_SESSION['username'] = $username;
            header('Location: dashboard.php');
            exit;
        }
    }
    $error_message = 'Username atau password salah.';
    $stmt->close();
    $conn->close();
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login - JCE Tools</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-dark: #0A0A0A; /* Lebih gelap untuk kesan premium */
            --form-bg: #1A1A1A; /* Sedikit lebih terang dari background */
            --gold: #FFD700;
            --red: #DC3545;
            --text-light: #E0E0E0;
            --text-gold-hover: #FFFACD;
        }

        body {
            background-color: var(--bg-dark);
            color: var(--text-light);
            font-family: 'Montserrat', sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            overflow: hidden; /* Mencegah scroll jika ada efek latar belakang */
        }

        /* Animasi Latar Belakang (Opsional, bisa dihapus jika terlalu berat) */
        .background-animated {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: radial-gradient(circle at top left, rgba(255,215,0,0.1) 0%, transparent 30%),
                        radial-gradient(circle at bottom right, rgba(220,53,69,0.1) 0%, transparent 30%);
            animation: gradientAnim 15s ease infinite;
            z-index: -1;
        }

        @keyframes gradientAnim {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }

        .login-card {
            background-color: var(--form-bg);
            border: 2px solid var(--gold); /* Border emas lebih tebal */
            border-radius: 12px;
            box-shadow: 0 8px 30px rgba(0,0,0,0.7); /* Shadow lebih dalam */
            padding: 2.5rem; /* Padding lebih luas */
            width: 100%;
            max-width: 400px; /* Lebar maksimal form */
            animation: fadeIn 0.8s ease-out; /* Animasi masuk */
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-20px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .login-logo {
            display: block;
            margin: 0 auto 1.5rem auto; /* Atur margin bawah */
            max-height: 150px; /* Ukuran logo */
            width: auto;
        }

        .card-title {
            color: var(--gold);
            font-weight: 700;
            font-size: 1.8rem;
            margin-bottom: 1.5rem;
        }

        .form-label {
            color: var(--text-light);
            font-weight: 600;
            margin-bottom: 0.5rem;
        }

        .form-control {
            background-color: #2A2A2A;
            border: 1px solid #444;
            color: var(--text-light);
            padding: 0.8rem 1rem;
            border-radius: 8px;
            transition: border-color 0.3s ease, box-shadow 0.3s ease;
        }

        .form-control:focus {
            background-color: #333;
            border-color: var(--gold);
            box-shadow: 0 0 0 0.2rem rgba(255, 215, 0, 0.3);
            color: var(--text-light);
        }

        .btn-submit {
            background-color: var(--gold);
            border-color: var(--gold);
            color: var(--bg-dark);
            font-weight: 700;
            padding: 0.8rem 1.5rem;
            border-radius: 8px;
            transition: all 0.3s ease;
            letter-spacing: 0.05em;
            margin-top: 1.5rem;
        }

        .btn-submit:hover {
            background-color: var(--text-gold-hover);
            border-color: var(--text-gold-hover);
            color: #000;
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(255, 215, 0, 0.4);
        }

        .alert-danger {
            background-color: var(--red);
            border-color: var(--red);
            color: white;
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 1.5rem;
        }
    </style>
</head>
<body>
    <div class="background-animated"></div> <div class="login-card">
        <img src="logo.png" alt="Logo JCE Tools" class="login-logo">
        
        <?php if(!empty($error_message)): ?>
            <div class="alert alert-danger text-center"><?php echo $error_message; ?></div>
        <?php endif; ?>
        
        <form action="login.php" method="POST">
            <div class="mb-3">
                <label for="username" class="form-label">Username</label>
                <input type="text" class="form-control" id="username" name="username" required autocomplete="username">
            </div>
            <div class="mb-3">
                <label for="password" class="form-label">Password</label>
                <input type="password" class="form-control" id="password" name="password" required autocomplete="current-password">
            </div>
            <div class="d-grid">
                <button type="submit" class="btn btn-submit">Login</button>
            </div>
        </form>
    </div>
</body>
</html>