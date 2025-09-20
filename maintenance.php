<?php
// Mengirim header 503 Service Unavailable agar mesin pencari tahu situs sedang dalam perbaikan
header('HTTP/1.1 503 Service Temporarily Unavailable');
header('Status: 503 Service Temporarily Unavailable');
header('Retry-After: 3600'); // Memberi tahu untuk mencoba lagi setelah 1 jam
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <title>Maintenance</title>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Poppins', sans-serif;
            background-color: #121212;
            color: #e0e0e0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            text-align: center;
            margin: 0;
            padding: 20px;
        }
        .container {
            padding: 40px;
            background-color: #1e1e1e;
            border-radius: 12px;
            border-top: 4px solid #ffd700;
            max-width: 600px;
        }
        img {
            max-width: 150px;
            margin-bottom: 20px;
        }
        h1 {
            color: #ffd700;
            margin-bottom: 20px;
            font-size: 2.5rem;
        }
        p {
            font-size: 1.1rem;
            line-height: 1.6;
        }
    </style>
</head>
<body>
    <div class="container">
        <img src="logo.png" alt="Logo">
        <h1>Segera Kembali</h1>
        <p>
            Maaf, situs kami sedang dalam pemeliharaan untuk meningkatkan layanan. <br>
            Kami akan segera kembali online. Terima kasih atas kesabaran Anda.
        </p>
    </div>
</body>
</html>