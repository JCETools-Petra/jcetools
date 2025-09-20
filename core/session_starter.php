<?php
// core/session_starter.php

if (session_status() === PHP_SESSION_NONE) {
    
    $samesite = 'Lax';

    $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
               || (isset($_SERVER['SERVER_PORT']) && $_SERVER['SERVER_PORT'] == 443);

    $params = [
      'lifetime' => 0,
      'path'     => '/',
      'domain'   => '', // Dikosongkan untuk fleksibilitas
      'secure'   => $isHttps,
      'httponly' => true,
      'samesite' => $samesite
    ];

    if (PHP_VERSION_ID >= 70300) {
        session_set_cookie_params($params);
    } else {
        session_set_cookie_params(
            $params['lifetime'],
            $params['path'] . '; SameSite=' . $params['samesite'],
            $params['domain'],
            $params['secure'],
            $params['httponly']
        );
    }

    session_start();
}
?>