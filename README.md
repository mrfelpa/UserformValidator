# Usage Instructions:


    Install and activate the plugin in your WordPress site.
    
    Once activated, the plugin will automatically validate user permission levels and block unauthorized access attempts during login.
    
    If a user does not exist in the WordPress database or has an invalid permission level, they will be blocked from logging in.
    
    The plugin also tracks failed login attempts and blocks IP addresses that exceed the maximum allowed attempts.
    
    Custom password validation rules are applied to ensure strong passwords are used.


# Possible Problems and Solutions:


***Plugin not working:***


- Ensure that the plugin is installed and activated correctly.

- Check for any conflicting plugins or themes that may interfere with the User Permission Validator plugin.

- Verify that the WordPress version is compatible with the plugin.


***False-positive blocking:***


- Adjust the maximum allowed failed attempts in the ***is_brute_force_attempt($username) function*** to a suitable value for your site's security needs.

- Keep an eye on the IP addresses being blocked and manually unblock legitimate users if necessary.


***Custom password rules not meeting requirements:***


- Modify the ***is_password_valid($password) function*** to suit your specific password requirements.

- Add or remove password checks as needed.

# Contributions

Community contributions are encouraged and valued. If you are interested in contributing feel free.
