<?php
// A simple and insecure PHP script vulnerable to command injection
// WARNING: This script is for educational purposes only. Do not deploy on any live environment.

if (isset($_GET['cmd'])) {
    $cmd = $_GET['cmd'];
    echo "<pre>";
    // Vulnerability: Directly passing user input to the system command
    system($cmd);
    echo "</pre>";
} else {
    echo "Please provide a command to execute using the 'cmd' query parameter. E.g., ?cmd=ls";
}
?>
