<?php
function kirimWhatsApp(string $target, string $pesan): bool {
    // Ambil token dari environment variable yang sudah dimuat
    // Perbaikan: Mengubah nama variabel dari WA_TOKEN menjadi FONNTE_TOKEN
    $token = $_ENV['FONNTE_TOKEN'] ?? null;

    if (!$token) {
        error_log("FONNTE_TOKEN tidak ditemukan di .env");
        return false;
    }

    $curl = curl_init();
    curl_setopt_array($curl, array(
      CURLOPT_URL => 'https://api.fonnte.com/send',
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_ENCODING => '',
      CURLOPT_MAXREDIRS => 10,
      CURLOPT_TIMEOUT => 20, // Timeout 20 detik
      CURLOPT_FOLLOWLOCATION => true,
      CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
      CURLOPT_CUSTOMREQUEST => 'POST',
      CURLOPT_POSTFIELDS => array('target' => $target, 'message' => $pesan),
      CURLOPT_HTTPHEADER => array(
        "Authorization: {$token}"
      ),
    ));
    $response = curl_exec($curl);
    $err = curl_error($curl);
    curl_close($curl);

    if ($err) {
        error_log("cURL Error (WA): " . $err);
        return false;
    }
    
    // Anda bisa menambahkan logika untuk cek isi $response jika perlu
    // Fonnte biasanya return JSON, jadi Anda bisa json_decode($response)
    return true; 
}
?>