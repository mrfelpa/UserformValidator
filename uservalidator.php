<?php
/*
Plugin Name: UserformValidator
Description: Validates user permission levels and blocks unauthorized access attempts.
Version: 1.3
Author: Mr.Felpa
*/

defined('ABSPATH') or die('No direct access allowed.');

class UserformValidator {

    private $allowed_roles = ['administrator', 'editor', 'author'];
    private $max_login_attempts = 5;
    private $lockout_duration = 300;
    private $password_min_length = 8;
    private $common_passwords = ['123456', 'password', 'qwerty'];

    public function __construct() {
        add_action('login_form', [$this, 'validate_login']);
        add_action('wp_login_failed', [$this, 'log_failed_login']);
    }

    public function validate_login() {
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['log']) && isset($_POST['pwd'])) {
            $username = sanitize_user($_POST['log']);
            $password = $_POST['pwd'];

            if (!$this->is_nonce_valid()) {
                $this->block_login_attempt('Invalid security token.');
            }

            if (!$this->is_user_authorized($username)) {
                $this->block_login_attempt('Unauthorized access.');
            }

            if ($this->is_brute_force_attempt($username)) {
                $this->block_login_attempt('Too many login attempts. Please try again later.');
            }

            if (!$this->is_password_strong($password)) {
                $this->block_login_attempt('Weak password. Please choose a stronger one.');
            }
        }
    }

    private function is_nonce_valid() {
        return isset($_POST['_wpnonce']) && wp_verify_nonce(sanitize_text_field($_POST['_wpnonce']), 'login_form');
    }

    private function is_user_authorized($username) {
        $user = get_user_by('login', $username);
        if (!$user) {
            return false;
        }

        $user_roles = (array) $user->roles;
        return count(array_intersect($this->allowed_roles, $user_roles)) > 0;
    }

    private function is_password_strong($password) {
        if (strlen($password) < $this->password_min_length) {
            return false;
        }

        if (!preg_match('/[A-Z]/', $password)) {
            return false;
        }

        if (!preg_match('/[a-z]/', $password)) {
            return false;
        }

        if (!preg_match('/\d/', $password)) {
            return false;
        }

        if (!preg_match('/[^A-Za-z0-9]/', $password)) {
            return false;
        }

        if (in_array($password, $this->common_passwords, true)) {
            return false;
        }

        return true;
    }

    private function is_brute_force_attempt($username) {
        $ip = $this->get_user_ip();
        $transient_key = 'login_attempts_' . $username . '_' . $ip;
        $attempts = get_transient($transient_key);

        if ($attempts === false) {
            $attempts = 0;
        }

        if ($attempts >= $this->max_login_attempts) {
            return true;
        }

        $attempts++;
        set_transient($transient_key, $attempts, $this->lockout_duration);
        return false;
    }

    private function block_login_attempt($error_message) {
        $login_url = wp_login_url();
        $redirect_url = add_query_arg('login_error', urlencode($error_message), $login_url);
        wp_safe_redirect($redirect_url);
        exit;
    }

    private function log_failed_login($username) {
        $ip = $this->get_user_ip();
        error_log(sprintf('Failed login attempt for user "%s" from IP "%s"', $username, $ip));
    }

    private function get_user_ip() {
        if (isset($_SERVER["HTTP_CF_CONNECTING_IP"])) {
            $_SERVER['REMOTE_ADDR'] = $_SERVER["HTTP_CF_CONNECTING_IP"];
        }

        return sanitize_text_field($_SERVER['REMOTE_ADDR']);
    }
}

new UserformValidator();
