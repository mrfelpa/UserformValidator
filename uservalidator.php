<?php
/*
Plugin Name: UserformValidator
Description: Validates user permission levels and blocks unauthorized access attempts.
Version: 1.0
Author: 0x5FE
*/

add_action('login_form', 'validate_user_permission');

function validate_user_permission() {
    if (isset($_POST['log']) && isset($_POST['pwd'])) {
        $username = sanitize_user($_POST['log']);
        $password = sanitize_text_field($_POST['pwd']);

        if (!is_user_valid($username)) {
            block_login_attempt('Invalid username.');
        }

        if (is_brute_force_attempt($username)) {
            block_login_attempt('Too many login attempts. Please try again later.');
        }

        if (!is_password_valid($password)) {
            block_login_attempt('Invalid password.');
        }
    }
}

function is_user_valid($username) {
    $user = get_user_by('login', $username);

    if (!$user) {
        return false;
    }

    $allowed_permission_levels = array('administrator', 'editor', 'author');
    if (!in_array($user->roles[0], $allowed_permission_levels)) {
        return false;
    }

    return true;
}

function is_brute_force_attempt($username) {
    $ip = $_SERVER['REMOTE_ADDR'];

    $attempts = get_user_meta($username, 'login_attempts', true);

    if (!$attempts) {
        $attempts = array();
    }

    $max_attempts = 5;
    $ip_attempts = array_filter($attempts, function ($attempt) use ($ip) {
        return $attempt['ip'] === $ip;
    });

    if (count($ip_attempts) >= $max_attempts) {
        return true;
    }

    $attempts[] = array(
        'ip' => $ip,
        'timestamp' => time(),
    );

    update_user_meta($username, 'login_attempts', $attempts);

    return false;
}

function is_password_valid($password) {
    if (strlen($password) < 8) {
        return false;
    }

    $password_checks = array(
        '/[A-Z]/', // At least one uppercase letter
        '/[a-z]/', // At least one lowercase letter
        '/\d/',    // At least one digit
        '/[^A-Za-z0-9]/', // At least one special character
    );

    foreach ($password_checks as $check) {
        if (!preg_match($check, $password)) {
            return false;
        }
    }

    $common_passwords = array('123456', 'password', 'qwerty');
    if (in_array($password, $common_passwords)) {
        return false;
    }

    return true;
}

function block_login_attempt($error_message) {
    $login_url = wp_login_url();
    wp_redirect(add_query_arg('login_error', urlencode($error_message), $login_url));
    exit;
}
