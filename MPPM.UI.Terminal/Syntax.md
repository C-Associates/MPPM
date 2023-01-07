# Global Commands
## Managing Passwords
### Adding a new password

Terminal.exe --add "Password name / title" --password "PasswordForPassword"

### Removing a password

Terminal.exe --remove "Password name" // delete password from vault
Terminal.exe --revoke "Password name" // unshare password and flag for password change

### Updating a password 

Terminal.exe --update "Password name" --password "Updated Password"

### Sharing a password

Terminal.exe --share --password="Password Title" --shareWith="AccountSnowflake / User"

## Creating custom fields
### Adding custom fields

Terminal.exe --addField --key "Custom field" --value "Field Value"

## Managing TOTP Tokens
### Fetching a current TOTP Token