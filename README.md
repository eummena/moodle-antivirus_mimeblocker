# moodle-antivirus_mimeblocker

An "antivirus" for Moodle that will accurately check the mimetype and allow only specific types of file uploads.

## Installing MIME Blocker

### Installing directly from the Moodle plugins directory
Login as an admin and go to Site administration > Plugins > Install plugins. (If you can't find this location, then plugin installation is prevented on your site.)
Click the button 'Install plugins from Moodle plugins directory'.
Search for MIME Blocker  with an Install button, click the Install button then click Continue.
Confirm the installation request
Check the plugin validation report

### Installing via uploaded ZIP file
Go to the Moodle plugins directory, select your current Moodle version, then choose MIME Blocker with a Download button and download the ZIP file.
Login to your Moodle site as an admin and go to Administration > Site administration > Plugins > Install plugins.
Upload the ZIP file. You should only be prompted to add extra details (in the Show more section) if your plugin is not automatically detected.
If your target directory is not writeable, you will see a warning message.
Check the plugin validation report

### Installing manually at the server
Please unzip the MIME Blocker plugin in your moodle lib/antivirus folder.Now you can safely install the plugin.
If you are already logged in just refreshing the browser should trigger your Moodlesite to begin the install 'Plugins Check'.
If not then navigate to Administration > Notifications.

## Configuration
To configure antivirus please go to the the MIME Blocker configuration page Site administration > Plugins > Antivirus plugins > Mime Blocker antivirus and add the list of allowed types, all types separated by semicolon (;)


## Note
To see wether  antivirus is successfully installed go to the Plugins page in Administration > Site Administration > Plugins > Plugins overview lists all installed plugins, together with the version number,release, availability (enabled or disabled) and settings link

## Release logs

### Version 2019082904
- Validate input MIME types in setting page with Moodle core MIME types
- Ignore course backup MIME in code as this MIME not added in Moodle core
