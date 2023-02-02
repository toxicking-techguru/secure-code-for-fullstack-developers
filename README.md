# secure-code-for-fullstack-developers
this code is sanized and reviewed by bug hunters and developers take a look;
Security
# SQL Injection Protection
using  mysqli prepared statements for all database interactions, which eliminates most risks of SQL injection. There is no raw SQL query used anywhere, and moreover, all data input by user is verified and checked before being used in any application functionality. Hence further hardening the security measures.

// example database query

$sql = "DELETE FROM auth_tokens WHERE user_email=? AND auth_type='account_verify';";
$stmt = mysqli_stmt_init($conn);
if (!mysqli_stmt_prepare($stmt, $sql)) {

    $_SESSION['ERRORS']['sqlerror'] = 'SQL ERROR';
    header("Location: ../");
    exit();
}
else {

    mysqli_stmt_bind_param($stmt, "s", $email);
    mysqli_stmt_execute($stmt);
}
# Header & Email Injection Protection
 the _cleaninjections() function defined in the assets/includes/security_functions.php to filter and validate data. Any and all data entered by users for any functionality is checked for header injection before being used. The filter functions remove any character(s) that may prove to be a threat, thus rendering any malicious script or data harmless.

On all back functionality, each and every single value being passed in the POST body is checked for possible injection. The same holds for emails, preventing users to add additional email-specific fields in it. This greatly reduces the risk of Header or Email injection.

// Securing against Header Injection

foreach($_POST as $key => $value){

  $_POST[$key] = _cleaninjections(trim($value));
}
# CSRF Protection
There are also heavy protection measures against CSRF attempts. A secure csrf token is generated on session start, and sent as a hidden value in the post body for all forms, where it is validated and only allows the script to proceed if the validation succeeds. The csrf protection works for all forms regardless of whether the user is logged in or not.

The csrf token is handled by the functions present in the assets/includes/security_functions.php file. The token is encrypted to keep it from being extracted and exploited.

// csrf token generation

function generate_csrf_token() {
  if (!isset($_SESSION)) {
      session_start();
  }
  if (empty($_SESSION['token'])) {
      $_SESSION['token'] = bin2hex(random_bytes(32));
  }
}
Secure Remember-me Cookie
The cookie set for the remember-me feature uses encrypted selector and validator values that keep it from being interfered with or exploited. The token itself is not stored as-is in the database as well, eliminating risk of info leak in case of database breach. The authentication token and selector are stored in the auth_tokens table in the database.

Secure Account Activation & Password Reset
The features for account activation and password reset both use a link sent via email which also uses encrypted encrypted selector and validator values. All three features, namely remember-me cookies, account activation and password reset use the auth_tokens table to store the encrypted tokens and selector. Each of the tokens have an expiry time, meaning that once expired, they cannot be used. All tokens are deleted on being used, so they cannot be used over and over again.

# Login | Signup
when developing an app you should support a default and secure login and signup system. The user can signup to make a new account, and then will be prompted to login to the new account with his credentials. The user can also set his profile image on signup. To make a new account, the user must set a unique username and email. There are also additional information fields available, but they are optional and can be skipped.

The login system also supports a remember me feature, which will keep the user logged in for a certain time (currently a month) even if the browser or system is turned off.

Automatic Logout on Inactivity
including  a jquery snippet in assets/js/check_inactive.js which continously checks if the user is inactive. When the user is inactive for more than the specified time, it automatically logs the user out and redirects to the login page. The allowed inactivity time period is currently 1 hr, specified in assets/setup/env.php in the ALLOWED_INACTIVITY_TIME constant. The js script calls the script in assets/includes/checkinactive.ajax.php via AJAX call, where the user's inactivity is checked.

// checkinactive.ajax.php

session_start();
if (isset($_SESSION['auth']) && !isset($_COOKIE['rememberme'])){
    if(time() > $_SESSION['expire']){
        session_unset();
        session_destroy();
        echo 'logout_redirect';
    }
}
#User Profile | Profile Editing
A developer must supports a proper user profile accessible on registration. Currently only a few extra-information fields have been put into the database, namely the user's first name, last name, gender, profile headline and bio. These are only meant to showcase the use of additional user information, and as such, are optional fields and can be skipped during signup. The user also has a profile image that he can choose/set at signup and can also update it later.

There is also a profile update system, in which the user can update all of his information. In current system, the user must have a unique username and email, so the system confirms the availability of new username or email if they were changed for profile updation.

The system can also update the user's profile image, and deletes the old image afterwards to prevent useless images piling up in the server's file system.

There is also a separate check for the password updation, which requires the user to input the current password and confirm the new password as well. Once password is updated, a notification email is sent to the user on his (now) current email address.

#Email Verification | Account Activation
On signup / registration, the system gives the user access to the new account, but with limited access. On successful signup, a confirmation mail is sent to the user's email, with a secure verification link. Once the link is accessed, the account is unlocked/activated and the user can access all the additional functionalities. The link is created with encrypted selector and token fields, while the respective entry is created in the database for verification for whenever the link is accessed.

The database fields which determines if the account is verified/unlocked or not is the verified_at column. If the column is NULL, then the account is not verified. The verification email sent to the user sets that column value to the current Date/Time at that point, hence unlocking the account.

On login, the script checks the verified_at column and sets the value of $_SESSION['auth'] accordingly. If the user is unverified, he is redirected to the APPLICATION_PATH/verify page where he is prompted to activate his account with the sent email. In case that the user did not receive the email, an option is provided for him to resend that email. Once the account is activated and the page is refreshed, the user will be redirected away from the verify page to the default APPLICATION_PATH/home page.

# Password Resetting
There is also a password reset system, or by well known terminology, a forgot password? feature. Link to that feature is present on the login page below the login form, and requires that the user input his email with which he had signed up. If the email is not present in the database, the request is ignored, and if it is, a highly secure confirmation email is sent to the user. The user can access the link provided in that email, which will force him to recreate his password, and once done, will prompt the user to log in with the new credentials.

The confirmation / reset email uses the auth_tokens table in the database to create a secure selector and token for the user, then appends them to the reset link after encryption. The token has a certain expiry time (currently 1 hour), after which it becomes invalid.

Auth Verification
The system handles authentication checks with the help of specific functions stored in assets/includes/auth_functions.php. There are multiple functions to determine current state of the user. And the checks can be applied to any page in just one like by simply calling the respective function at the top of the file.

The available authentication functions (as of right now) are:

function check_logged_in() { ... }
function check_logged_in_butnot_verified() { ... }
function check_logged_out() { ... }
function check_verified() { ... }
function check_remember_me() { ... }
function force_login($email) { ... }
Each page can be set to accept users in a certain state by simply calling the respective function at the top of the file.

// Home page, only meant for verified users

define('TITLE', "Home");
include '../assets/layouts/header.php';
check_verified();
Remember Me Feature
The system's login system has a remember me feature, which keeps the user logged in even if the browser or device is shutdown. During logging in, if the user checked the rememer me option, the feature sets a secure cookie with encrypted selector and token values, and creates the respective values in the auth_tokens table in the database.

$selector = bin2hex(random_bytes(8));
$token = random_bytes(32);
setcookie(
  'rememberme',
  $selector.':'.bin2hex($token),
  time() + 864000,
  '/',
  NULL,
  false, 
  true  
);
To validate the cookie, the system uses the check_remember_me() function in the assets/includes/auth_functions.php file. Once the encrypted values are verified against the ones stored in the database, it calls the force_login() method which simply creates the relevant session variables for the user and logs him/her into the application.

# GLOBAL temporary ERROR & STATUS values
developer  must use a global ERROR and STATUS variable for any errors and page status, assigned as an associative array to $_SESSION['ERRORS'] and $_SESSION['STATUS'], with the keys being error/status names and values being the messages. These values are temporary, meaning that the error values disappear when the page is refreshed, returning the page to its original state. This keeps the URLs clean (by not using URL queries) and the associative array means that on occurence of any error, a new key with any name could be created and given the error message as the value, and could easily be dealt with on the frontend files as well.

For example, an example of creating an error and assigning it to $_SESSION['ERRORS'] in a backend script is:

// checking email availability

if ($_SESSION['email'] != $email && !availableEmail($conn, $email)) {

  $_SESSION['ERRORS']['emailerror'] = 'email already taken';
  header("Location: ../");
  exit();
}
Similarly, this is how the error can be accessed on the visible frontend file:

// profile update form with email field

<div class="form-group">
  <label for="email">Email address</label>
  <input type="email" id="email" name="email" ... >
  <sub class="text-danger">
    <?php
        if (isset($_SESSION['ERRORS']['emailerror']))
            echo $_SESSION['ERRORS']['emailerror'];
    ?>
  </sub>
</div>
