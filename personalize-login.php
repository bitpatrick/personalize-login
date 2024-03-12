<?php

/** 
 * Plugin Name: Personalize Login 
 * Description: A plugin that replaces the WordPress login flow with a custom page. 
 * Version: 1.0.0 
 * Author: Jarkko Laine 
 * License: GPL-2.0+ 
 * Text Domain: personalize-login 
 */

/*
 * NOTE LOGIN
 * 
 * you can access the WordPress login page by adding /login/, /admin/, or wp-login.php to the end of your site URL.
 * 
 * By default, when you try to access the WordPress admin, or click on a Log In link on you WordPress site (assuming your them displays one), WordPress sends you to wp-login.php,
 * the default version of the WordPress login page.
 * 
 * As WordPress provides a filter for returning the redirect URL after a successful login, 
 * all we need to do is to create a function that checks the current user's capabilities and returns the correct redirect URL accordingly.
 */

/*
  * NOTE AUTHENTICATION
  * In WordPress, user authentication happens through a function called wp_authenticate —  located in pluggable.php
  * The function does some basic sanitization of parameters and then calls the filters attached to the filter hook authenticate.
  * This is to allow plugins to replace the authentication flow with their own functionality,
  * even the WordPress default authentication is done through this filter. 
  * we are not interested in replacing the authentication, but the filter hook is still useful as it gives us a chance to collect the errors from other filters
  */

/**
 * NOTE LOGOUT
 * 
 * Once the user has been logged out from your site, in the function wp_logout, WordPress fires the action wp_logout.
 */

require_once 'Messanger.php';
require_once 'Captcha.php';

class Personalize_Login_Plugin
{

    private $login_template_name = 'lunapark_login_template';
    private $account_template_name = 'custom_account_template';
    private $registration_template_name = 'lunapark_registration_template';

    /** 
     * Initializes the plugin. 
     * 
     * To keep the initialization fast, only add filter and action 
     * hooks in the constructor. 
     */
    public function __construct()
    {

        /**
         *  Questo filtro viene utilizzato all'inizio del processo di autenticazione. 
         * Si attiva prima che WordPress esegua qualsiasi controllo sull'utente, 
         * inclusa la verifica dell'esistenza dello username e della correttezza della password.
         */
        add_filter('wp_authenticate_user', array($this, 'validate_login_nonce'), 10, 2);

        add_filter('authenticate', array($this, 'maybe_redirect_at_authenticate'), 101, 3); // redirect user after default word press authentication

        add_action('init', array($this, 'activate_user_account')); // checking user activation

        add_action('login_form_register', array($this, 'user_registration_process')); // user registration process

        add_action('login_form_register',  array($this, 'redirect_to_custom_url_register')); // redirect user to custom url register 

        add_action('login_form_login', array($this, 'redirect_to_custom_url_login')); // redirect user to custom login url

        add_filter('login_redirect', array($this, 'redirect_after_login'), 10, 3); // redirect user after login

        add_action('wp_logout', array($this, 'redirect_after_logout')); // redirect user after logout

        add_filter('template_include', array($this, 'render_custom_template')); // show custom page to user

        add_filter('admin_init', array('Captcha', 'register_settings_fields')); // captcha
    }

    public function validate_login_nonce($user, $password)
    {
        // Verifica se il nonce è presente e valido
        if (isset($_POST['user_login_nonce']) && !wp_verify_nonce($_POST['user_login_nonce'], 'user-login')) {
            // Il nonce non è valido o non è presente
            return new WP_Error('invalid_nonce', __('Invalid nonce provided.', 'personalize-login'));
        }

        // Se tutto è corretto, ritorna l'oggetto $user per continuare il processo di autenticazione
        return $user;
    }

    /** 
     * Plugin activation hook. 
     * 
     * Creates all WordPress pages needed by the plugin. 
     */
    public static function plugin_activated()
    {
    }

    public function activate_user_account()
    {
        if (isset($_GET['key']) && isset($_GET['user'])) {
            $user_id = intval($_GET['user']);
            $activation_code = get_user_meta($user_id, 'activation_code', true);

            if ($activation_code === $_GET['key']) {
                // Elimina il codice di attivazione in quanto non sarà più necessario
                delete_user_meta($user_id, 'activation_code');

                // Attiva l'account dell'utente
                update_user_meta($user_id, 'account_activated', 1);

                $redirect_to = add_query_arg('activation', 'successful', home_url());

                // Reindirizza l'utente a una pagina con un messaggio di attivazione riuscita
                wp_redirect($redirect_to);
                exit;
            }
        }
    }

    /** 
     * Redirects the user to the custom registration page instead 
     * of wp-login.php?action=register. 
     */
    public function redirect_to_custom_url_register()
    {
        if ('GET' == $_SERVER['REQUEST_METHOD']) {
            if (is_user_logged_in()) {
                $this->redirect_logged_in_user();
            } else {
                wp_redirect(home_url('member-register'));
            }
            exit;
        }
    }

    /** 
     * Handles the registration of a new user. 
     * 
     * Used through the action hook "login_form_register" activated on wp-login.php 
     * when accessed through the registration action. 
     */
    public function user_registration_process()
    {
        if ('POST' == $_SERVER['REQUEST_METHOD']) {

            $redirect_url = home_url('member-register');

            if (!get_option('users_can_register')) {
                // Registration closed, display error 
                $redirect_url = add_query_arg('register-errors', 'closed', $redirect_url);
            } elseif (!isset($_POST['user_register_nonce']) || !wp_verify_nonce($_POST['user_register_nonce'], 'user-registration')) {
                // Nonce non valido, mostrare un messaggio di errore o reindirizzare
                $redirect_url = add_query_arg('register-errors', 'nonce_failed', $redirect_url);
            } elseif (!Captcha::verify_recaptcha()) {
                // Recaptcha check failed, display error 
                $redirect_url = add_query_arg('register-errors', 'captcha', $redirect_url);
            } elseif ($_POST["password"] != $_POST["confirm_password"]) {
                // compare error passwords
                $redirect_url = add_query_arg('register-errors', 'compare-passwords', $redirect_url);
            } else {

                $user_login        = sanitize_user($_POST["username"]);
                $user_email        = sanitize_email($_POST["email"]);
                $user_first_name   = sanitize_text_field($_POST["first_name"]);
                $user_last_name    = sanitize_text_field($_POST["last_name"]);
                $user_pass         = $_POST["password"];
                // $red_role         = sanitize_text_field($_POST["role"]);

                $result = $this->create_user($user_login, $user_email, $user_first_name, $user_last_name, $user_pass);
                if (is_wp_error($result)) {
                    // Parse errors into a string and append as parameter to redirect 
                    $errors = join(',', $result->get_error_codes());
                    $redirect_url = add_query_arg('register-errors', $errors, $redirect_url);
                } else {

                    // Success, redirect to login page. 
                    $redirect_url = home_url('member-login');
                    $redirect_url = add_query_arg('registered', $user_email, $redirect_url);
                }
            }

            wp_safe_redirect($redirect_url);
            exit;
        }
    }

    /** 
     * Validates and then completes the new user signup process if all went well. 
     * 
     * @param string $email The new user's email address 
     * @param string $first_name The new user's first name 
     * @param string $last_name The new user's last name 
     * 
     * @return int|WP_Error The id of the user that was created, or error if failed. 
     */
    private function create_user($user_login, $user_email, $user_first_name, $user_last_name, $user_pass)
    {
        $errors = new WP_Error();
        // Email address is used as both username and email. It is also the only 
        // parameter we need to validate 
        if (!is_email($user_email)) {
            $errors->add('email', Messanger::get_error_message('email'));
        }
        if (username_exists($user_login)) {
            $errors->add('username_exists', Messanger::get_error_message('username_exists'));
        }
        if (email_exists($user_email)) {
            $errors->add('email_exists', Messanger::get_error_message('email_exists'));
        }
        // Verifica se sono stati aggiunti errori
        if ($errors->has_errors()) {
            return $errors;
        }

        // Generate the password so that the subscriber will have to check email... 
        $user_data = array(
            'user_login'    => $user_login,
            'user_email'    => $user_email,
            'user_pass'     => $user_pass,
            'first_name'    => $user_first_name,
            'last_name'     => $user_last_name,
            'nickname'      => $user_login,
        );
        $user_id = wp_insert_user($user_data);

        if (!is_wp_error($user_id)) {

            // Imposta l'utente come non attivo
            add_user_meta($user_id, 'account_activated', 0);

            // Genera un token di attivazione univoco
            $activation_code = sha1($user_login . time());

            // Salva il codice di attivazione nei metadati dell'utente
            add_user_meta($user_id, 'activation_code', $activation_code, true);

            // Crea il link di attivazione
            $activation_link = add_query_arg(array(
                'key' => $activation_code,
                'user' => $user_id
            ), home_url('activate'));

            // Invia l'email di attivazione
            $this->send_activation_email($user_email, $activation_link);
        }

        return $user_id;
    }

    private function send_activation_email($user_email, $activation_link)
    {
        $subject = 'Attiva il tuo account';
        $message = 'Clicca su questo link per attivare il tuo account: ' . $activation_link;
        $headers = 'From: Your Name <your-email@example.com>' . "\r\n";

        wp_mail($user_email, $subject, $message, $headers);
    }

    public function render_custom_template($template)
    {
        if ($_SERVER['REQUEST_METHOD'] == 'GET') {

            $url_requested = $_SERVER['REQUEST_URI'];

            $login_slug = 'member-login';
            $registration_slug = 'member-register';
            $account_slug = 'member-account';

            $template_name = null;

            if (strpos($url_requested, $login_slug) !== false && !is_user_logged_in()) {

                // LOGIN PAGE
                $template_name = $this->login_template_name;
            } elseif (strpos($url_requested, $registration_slug) !== false && !is_user_logged_in()) {

                // REGISTRATION PAGE
                $template_name = $this->registration_template_name;

                // SETTING CAPTCHA
                add_action('wp_print_footer_scripts', array('Captcha', 'add_captcha_js_to_footer'));
            } else if (strpos($url_requested, $account_slug) !== false && is_user_logged_in()) {

                // recupera id utente
                $user_id = get_current_user_id();

                if ($this->account_activated($user_id)) {

                    // ACCOUNT ATTIVO
                    $template_name = $this->account_template_name;
                } else {

                    // ACCOUNT NON ATTIVO
                    wp_safe_redirect(home_url());
                    exit;
                }
            }

            // Verifica l'esistenza del template e imposta lo status header a 200
            $custom_template = plugin_dir_path(__FILE__) . 'templates/' . $template_name . '.php';
            if (file_exists($custom_template)) {

                // Imposta l'header della risposta HTTP a 200 OK
                status_header(200);

                // ottieni attributi template
                $attributes = $this->get_attributes();

                // Retrieve recaptcha key 
                $attributes['recaptcha_site_key']  = get_option('personalize-login-recaptcha-site-key', null);

                // Passa gli attributi al template
                extract($attributes);

                // load css
                $this->load_css($template_name);

                include $custom_template;
                exit;
            }
        }

        return $template; // Restituisce il template originale se nessuna pagina custom è stata trovata
    }

    private function load_css($template_name)
    {

        switch ($template_name) {

            case 'lunapark_login_template':

            case 'lunapark_registration_template':
                // LOADING CSS
                wp_enqueue_style('login-style', plugin_dir_url(__FILE__) . 'css/lunapark-style.css');
                wp_enqueue_style('boxicons', 'https://unpkg.com/boxicons@2.1.4/css/boxicons.min.css', array(), '2.1.4');

                break;
        }
    }

    private function account_activated($user_id)
    {

        $activation_code = get_user_meta($user_id, 'account_activated', true);

        if ($activation_code === 1) {

            return true;
        }

        return false;
    }

    private function get_attributes(): array
    {
        $attributes = array();
        // Retrieve recaptcha key 
        $attributes['recaptcha_site_key'] = get_option('personalize-login-recaptcha-site-key', null);

        $messages = [];

        // Check if user just logged out
        if (isset($_GET['logged_out']) && $_GET['logged_out'] == 'true') {
            $info_message = Messanger::get_info_message('successful_logout');
            $messages['logged_out'] = $info_message;
        }

        // Check for any error message during user login
        if (isset($_GET['login'])) {
            $error_message = Messanger::get_error_message($_GET['login']);
            // Assign the error message to the error_messages array
            $messages['errors'][] = $error_message;
        }

        // Retrieve possible errors from request parameters 
        if (isset($_GET['register-errors'])) {
            $error_codes = explode(',', $_GET['register-errors']);
            foreach ($error_codes as $error_code) {
                $messages['errors'][] = Messanger::get_error_message($error_code);
            }
        }

        // Qui inserisci l'array messages dentro l'array attributes
        $attributes['messages'] = $messages;

        return $attributes;
    }

    /** 
     * Redirects the user to the login URL instead page of wp-login.php. 
     */
    function redirect_to_custom_url_login()
    {
        if ($_SERVER['REQUEST_METHOD'] == 'GET') {

            $redirect_to = isset($_REQUEST['redirect_to']) ? $_REQUEST['redirect_to'] : null;

            if (is_user_logged_in()) {

                /**
                 * UTENTE LOGGATO CHE STA PROVANDO AD ACCEDERE ALLA PAGINA DI LOGIN VIENE REINDIRIZZATO
                 */
                $this->redirect_logged_in_user($redirect_to);
                exit;
            }
            // The rest are redirected to the login page 
            $login_url = home_url('member-login');
            if (!empty($redirect_to)) {
                $login_url = add_query_arg('redirect_to', $redirect_to, $login_url);
            }
            wp_safe_redirect($login_url);
            exit;
        }
    }

    /** 
     * Redirects the user to the correct page depending on whether he / she 
     * is an admin or not. 
     * 
     * @param string $redirect_to An optional redirect_to URL for admin users 
     */
    private function redirect_logged_in_user($redirect_to = null)
    {
        $user = wp_get_current_user();
        if (user_can($user, 'manage_options')) {
            if ($redirect_to) {
                wp_safe_redirect($redirect_to);
            } else {
                wp_redirect(admin_url());
            }
        } else {
            wp_redirect(home_url('member-account'));
        }
    }

    /** 
     * Redirect the user after authentication if there were any errors. 
     * 
     * @param Wp_User|Wp_Error $user The signed in user, or the errors that have occurred during login. 
     * @param string $username The user name used to log in. 
     * @param string $password The password used to log in. 
     * 
     * @return Wp_User|Wp_Error The logged in user, or error information if there were errors. 
     */
    function maybe_redirect_at_authenticate($user, $username, $password)
    {
        // Check if the earlier authenticate filter (most likely, 
        // the default WordPress authentication) functions have found errors 
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            if (is_wp_error($user)) {
                $error_codes = join(',', $user->get_error_codes());
                $login_url = home_url('member-login');
                $login_url = add_query_arg('login', $error_codes, $login_url);
                wp_redirect($login_url);
                exit;
            }
        }
        return $user;
    }

    /** 
     * Redirect to custom login page after the user has been logged out. 
     */
    public function redirect_after_logout()
    {
        $redirect_url = home_url('member-login?logged_out=true');
        wp_safe_redirect($redirect_url);
        exit;
    }

    /** 
     * Returns the URL to which the user should be redirected after the (successful) login. 
     * 
     * @param string $redirect_to The redirect destination URL. 
     * @param string $requested_redirect_to The requested redirect destination URL passed as a parameter. 
     * @param WP_User|WP_Error $user WP_User object if login was successful, WP_Error object otherwise. 
     * 
     * @return string Redirect URL 
     */
    public function redirect_after_login($redirect_to, $requested_redirect_to, $user)
    {
        $redirect_url = home_url();
        if (!isset($user->ID)) {
            return $redirect_url;
        }
        if (user_can($user, 'manage_options')) {
            // Use the redirect_to parameter if one is set, otherwise redirect to admin dashboard. 
            if ($requested_redirect_to == '') {
                $redirect_url = admin_url();
            } else {
                $redirect_url = $requested_redirect_to;
            }
        } else {
            // Non-admin users always go to their account page after login 
            $redirect_url = home_url('member-account');
        }
        return wp_validate_redirect($redirect_url, home_url());
    }
}

// initialize captcha
$captcha = new Captcha();

// Initialize the plugin 
$personalize_login_pages_plugin = new Personalize_Login_Plugin();

// Create the custom pages at plugin activation 
register_activation_hook(__FILE__, array('Personalize_Login_Plugin', 'plugin_activated'));
