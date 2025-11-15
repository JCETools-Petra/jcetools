<?php
/**
 * CLI Password Verification Tool
 *
 * Script sederhana untuk memverifikasi password bcrypt via command line
 *
 * Cara penggunaan:
 * php cli_verify_password.php <password> <hash>
 *
 * Contoh:
 * php cli_verify_password.php "mypassword123" '$2y$10$DWniQEQgAaXV501SyxBsFeC36g4R4JomlYyngftwdysOxD.fhvqn2'
 */

// Cek apakah script dijalankan via CLI
if (php_sapi_name() !== 'cli') {
    die("Script ini hanya bisa dijalankan via command line (CLI)\n");
}

echo "==============================================\n";
echo "   JCETOOLS - Password Verification Tool\n";
echo "==============================================\n\n";

// Cek argumen
if ($argc < 2) {
    echo "Pilih mode:\n";
    echo "1. Verifikasi Password vs Hash\n";
    echo "2. Generate Hash dari Password\n";
    echo "3. Verifikasi dari Database\n\n";

    $mode = readline("Pilih mode (1/2/3): ");

    if ($mode == '1') {
        // Mode verifikasi
        $password = readline("Masukkan password (plain text): ");
        $hash = readline("Masukkan hash bcrypt: ");

        echo "\n--- Hasil Verifikasi ---\n";
        echo "Password: " . $password . "\n";
        echo "Hash: " . $hash . "\n\n";

        if (password_verify($password, $hash)) {
            echo "✅ COCOK! Password sesuai dengan hash.\n";
            exit(0);
        } else {
            echo "❌ TIDAK COCOK! Password tidak sesuai dengan hash.\n";
            exit(1);
        }
    } elseif ($mode == '2') {
        // Mode generate hash
        $password = readline("Masukkan password untuk di-hash: ");

        $hash = password_hash($password, PASSWORD_BCRYPT);

        echo "\n--- Hash yang Dihasilkan ---\n";
        echo $hash . "\n\n";
        echo "Hash ini sudah disalin di atas. Gunakan untuk testing atau simpan ke database.\n";
        exit(0);
    } elseif ($mode == '3') {
        // Mode verifikasi dari database
        require_once __DIR__ . '/core/db_connect.php';

        $username = readline("Masukkan username: ");
        $password = readline("Masukkan password untuk ditest: ");

        $stmt = $conn->prepare("SELECT password FROM licensed_users WHERE username = ?");
        $stmt->bind_param('s', $username);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 0) {
            echo "\n❌ Username tidak ditemukan dalam database.\n";
            exit(1);
        }

        $user_data = $result->fetch_assoc();
        $stored_hash = $user_data['password'];

        echo "\n--- Hasil Verifikasi ---\n";
        echo "Username: " . $username . "\n";
        echo "Password: " . $password . "\n\n";

        if (password_verify($password, $stored_hash)) {
            echo "✅ COCOK! Password sesuai untuk user: " . $username . "\n";
            exit(0);
        } else {
            echo "❌ TIDAK COCOK! Password tidak sesuai untuk user: " . $username . "\n";
            exit(1);
        }
    } else {
        echo "Mode tidak valid.\n";
        exit(1);
    }
} else {
    // Mode dengan argumen langsung
    if ($argc < 3) {
        echo "Usage: php cli_verify_password.php <password> <hash>\n";
        echo "\nContoh:\n";
        echo "php cli_verify_password.php \"mypassword123\" '\$2y\$10\$DWniQEQgAaXV501SyxBsFeC36g4R4JomlYyngftwdysOxD.fhvqn2'\n\n";
        echo "Atau jalankan tanpa argumen untuk mode interaktif.\n";
        exit(1);
    }

    $password = $argv[1];
    $hash = $argv[2];

    echo "Password: " . $password . "\n";
    echo "Hash: " . $hash . "\n\n";

    if (password_verify($password, $hash)) {
        echo "✅ COCOK! Password sesuai dengan hash.\n";
        exit(0);
    } else {
        echo "❌ TIDAK COCOK! Password tidak sesuai dengan hash.\n";
        exit(1);
    }
}
