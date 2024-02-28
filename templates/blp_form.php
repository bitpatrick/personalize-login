  <div class="wrapper">

    <?php if ($attributes['show_title']) : ?>
      <h2><?php _e('Sign In', 'personalize-login'); ?></h2>
    <?php endif; ?>

    <!-- Show errors if there are any -->
    <?php if (count($attributes['errors']) > 0) : ?>
      <?php foreach ($attributes['errors'] as $error) : ?>
        <p class="login-error">
          <?php echo $error; ?>
        </p>
      <?php endforeach; ?>
    <?php endif; ?>

    <!-- Show logged out message if user just logged out -->
    <?php if ($attributes['logged_out']) : ?>
      <p class="login-info">
        <?php _e('You have signed out. Would you like to sign in again?', 'personalize-login'); ?>
      </p>
    <?php endif; ?>

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
        <a href="">Forgot password?</a>
      </div>
      <button type="submit" class="btn" name="wp-submit" id="wp-submit" value="<?php _e('Sign In', 'personalize-login'); ?>"><?php _e('Sign In', 'personalize-login'); ?></button>
      <div class="register-link">
        <p>Don't have an account? <a href="#">Register</a></p>
      </div>
    </form>
  </div>