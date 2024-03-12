<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <?php wp_head(); ?>
  <title>Login</title>
</head>

<body>

  <div class="wrapper">

    <?php
    // Verifica se ci sono messaggi di errore
    if (!empty($attributes['messages']['errors'])) {
      // Cicla su ogni messaggio di errore
      foreach ($attributes['messages']['errors'] as $error_message) {
        // Stampa il messaggio di errore
        echo '<div class="error-message">' . $error_message . '</div>';
      }
    }
    ?>

    <?php
    if (!empty($attributes['messages']['logged_out'])) {
      echo '<p class="login-info">' . __('You have signed out. Would you like to sign in again?', 'personalize-login') . '</p>';
    }
    ?>

    <form method="post" action="<?php echo wp_login_url(); ?>">
      <h1>Login</h1>
      <div class="input-box">
        <input type="text" name="log" id="user_login" placeholder="Username" required>
        <i class="bx bxs-user"></i>
      </div>
      <div class="input-box">
        <input type="password" name="pwd" id="user_pass" placeholder="Password" required>
        <i class="bx bxs-lock-alt"></i>
      </div>
      <div class="remember-forgot">
        <label for="remember-me"><input id="remember-me" type="checkbox">Remember Me</label>
        <a href="<?php echo wp_lostpassword_url(); ?>">Forgot password?</a>
      </div>
      <button type="submit" class="btn" name="wp-submit" id="wp-submit" value="<?php _e('Sign In', 'personalize-login'); ?>"><?php _e('Sign In', 'personalize-login'); ?></button>
      <?php wp_nonce_field('user-login', 'user_login_nonce'); ?>
      <div class="register-link">
        <p>Don't have an account? <a href="<?php echo wp_registration_url(); ?>">Register</a></p>
      </div>
    </form>
  </div>

    <?php wp_footer(); ?>
</body>

</html>