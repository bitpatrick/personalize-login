<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Registration</title>
    <?php wp_head(); ?>
</head>

<body>

    <div class="wrapper">

        <?php
        if (!empty($attributes['messages']['errors'])) {
            echo '<ul class="registration-errors">';
            foreach ($attributes['messages']['errors'] as $error_message) {
                echo '<li class="error-message">' . esc_html($error_message) . '</li>';
            }
            echo '</ul>';
        }
        ?>

        <form id="signupform" action="<?php echo wp_registration_url(); ?>" method="post">
            <h1>Registration</h1>
            <div class="input-box">
                <label for="username"><?php _e('Username', 'personalize-login'); ?> <strong>*</strong></label>
                <input type="text" name="username" id="username" required>
            </div>
            <div class="input-box">
                <label for="email"><?php _e('Email', 'personalize-login'); ?> <strong>*</strong></label>
                <input type="email" name="email" id="email" required>
            </div>
            <div class="input-box">
                <label for="first_name"><?php _e('First Name', 'personalize-login'); ?></label>
                <input type="text" name="first_name" id="first-name">
            </div>
            <div class="input-box">
                <label for="last_name"><?php _e('Last Name', 'personalize-login'); ?></label>
                <input type="text" name="last_name" id="last-name">
            </div>
            <div class="input-box">
                <label for="password"><?php _e('Password', 'personalize-login'); ?> <strong>*</strong></label>
                <input type="password" name="password" id="password" required>
            </div>
            <div class="input-box">
                <label for="confirm_password"><?php _e('Confirm Password', 'personalize-login'); ?> <strong>*</strong></label>
                <input type="password" name="confirm_password" id="confirm_password" required>
            </div>
            <?php if ($attributes['recaptcha_site_key']) : ?>
                <div class="recaptcha-container">
                    <div class="g-recaptcha" data-sitekey="<?php echo $attributes['recaptcha_site_key']; ?>"></div>
                </div>
            <?php endif; ?>
            <?php wp_nonce_field('user-registration', 'user_register_nonce'); ?>
            <button type="submit" name="submit" class="btn register-button" value="<?php _e('Register', 'personalize-login'); ?>"><?php _e('Register', 'personalize-login'); ?></button>
        </form>
    </div>

    <?php wp_footer(); ?>
</body>

</html>