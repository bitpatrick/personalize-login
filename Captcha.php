<?php

class Captcha
{

    /** 
     * Registers the settings fields needed by the plugin. 
     */
    public static function register_settings_fields()
    {
        // Create settings fields for the two keys used by reCAPTCHA 
        register_setting('general', 'personalize-login-recaptcha-site-key');
        register_setting('general', 'personalize-login-recaptcha-secret-key');
        add_settings_field(
            'personalize-login-recaptcha-site-key',
            '<label for="personalize-login-recaptcha-site-key">' . __('reCAPTCHA site key', 'personalize-login') . '</label>',
            array('Captcha', 'render_recaptcha_site_key_field'),
            'general'
        );
        add_settings_field(
            'personalize-login-recaptcha-secret-key',
            '<label for="personalize-login-recaptcha-secret-key">' . __('reCAPTCHA secret key', 'personalize-login') . '</label>',
            array('Captcha', 'render_recaptcha_secret_key_field'),
            'general'
        );
    }
    public static function render_recaptcha_site_key_field()
    {
        $value = get_option('personalize-login-recaptcha-site-key', '');
        echo '<input type="text" id="personalize-login-recaptcha-site-key" name="personalize-login-recaptcha-site-key" value="' . esc_attr($value) . '" />';
    }
    public static function render_recaptcha_secret_key_field()
    {
        $value = get_option('personalize-login-recaptcha-secret-key', '');
        echo '<input type="text" id="personalize-login-recaptcha-secret-key" name="personalize-login-recaptcha-secret-key" value="' . esc_attr($value) . '" />';
    }

    /** 
     * An action function used to include the reCAPTCHA JavaScript file 
     * at the end of the page. 
     */
    public static function add_captcha_js_to_footer()
    {
        echo "<script src='https://www.google.com/recaptcha/api.js'></script>";
    }

    /** 
     * Checks that the reCAPTCHA parameter sent with the registration 
     * request is valid. 
     * 
     * @return bool True if the CAPTCHA is OK, otherwise false. 
     */
    public static function verify_recaptcha()
    {
        // This field is set by the recaptcha widget if check is successful 
        if (isset($_POST['g-recaptcha-response'])) {
            $captcha_response = $_POST['g-recaptcha-response'];
        } else {
            return false;
        }
        // Verify the captcha response from Google 
        $response = wp_remote_post(
            'https://www.google.com/recaptcha/api/siteverify',
            array(
                'body' => array(
                    'secret' => get_option('personalize-login-recaptcha-secret-key'),
                    'response' => $captcha_response
                )
            )
        );
        $success = false;
        if ($response && is_array($response)) {
            $decoded_response = json_decode($response['body']);
            $success = $decoded_response->success;
        }
        return $success;
    }
}

?>