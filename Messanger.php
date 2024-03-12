<?php


class Messanger
{

    /** 
     * Finds and returns a matching error message for the given error code. 
     * 
     * @param string $error_code The error code to look up. 
     * 
     * @return string An error message. 
     */
    public static function get_error_message($error_code)
    {

        switch ($error_code) {

            case 'captcha':
                return __( 'The Google reCAPTCHA check failed. Are you a robot?', 'personalize-login' );
            case 'email':
                return __('The email address you entered is not valid.', 'personalize-login');
            case 'email_exists':
                return __('An account exists with this email address.', 'personalize-login');
            case 'closed':
                return __('Registering new users is currently not allowed.', 'personalize-login');
            case 'empty_username':
                return __('You do have an email address, right?', 'personalize-login');
            case 'empty_password':
                return __('You need to enter a password to login.', 'personalize-login');
            case 'invalid_username':
                return __(
                    "We don't have any users with that email address. Maybe you used a different one when signing up?",
                    'personalize-login'
                );
            case 'incorrect_password':
                $err = __(
                    "The password you entered wasn't quite right. <a href='%s'>Did you forget your password</a>?",
                    'personalize-login'
                );
                return sprintf($err, wp_lostpassword_url());
            default:
                break;
        }

        return __('An unknown error occurred. Please try again later.', 'personalize-login');
    }

    public static function get_info_message($code)
    {

        switch ($code) {

            case 'successful_logout':
                return __('You have successfully logged out.', 'personalize-login');
            default:
                break;
        }
    }
}
