<?php
// core/session_starter.php

if (session_status() === PHP_SESSION_NONE) {
    
    $samesite = 'Lax';

    $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
               || (isset($_SERVER['SERVER_PORT']) && $_SERVER['SERVER_PORT'] == 443);

    $host = isset($_SERVER['HTTP_HOST']) ? trim($_SERVER['HTTP_HOST']) : '';

    if ($host !== '') {
        // Remove a port suffix to obtain a clean cookie domain.
        $host = preg_replace('/:\\d+$/', '', $host);

        // Skip invalid cookie domains such as IP addresses or "localhost".
        if ($host === 'localhost' || filter_var($host, FILTER_VALIDATE_IP)) {
            $host = '';
        }
    }

    $params = [
      'lifetime' => 0,
      'path'     => '/',
      'secure'   => $isHttps,
      'httponly' => true,
      'samesite' => $samesite
    ];

     if ($host !== '') {
        // Menambahkan titik di depan untuk membuat cookie tersedia
        // di semua subdomain (misal: www.domain.com dan domain.com)
        $params['domain'] = '.' . $host;
    }

    if (PHP_VERSION_ID >= 70300) {
        session_set_cookie_params($params);
    } else {
        ini_set('session.cookie_secure', $params['secure'] ? '1' : '0');
        ini_set('session.cookie_httponly', $params['httponly'] ? '1' : '0');

        if (isset($params['domain'])) {
            ini_set('session.cookie_domain', $params['domain']);
        }

        session_set_cookie_params(
            $params['lifetime'],
            $params['path'] . '; SameSite=' . $params['samesite']
        );
    }

    session_start();
}
?>