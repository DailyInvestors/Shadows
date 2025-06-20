<?php

/**
 * network_monitor_agent.php
 *
 * This script functions as a dedicated network monitoring agent in PHP.
 * It listens on specified ports (SSH, Telnet, FTP, SMTP) for incoming connections,
 * analyzes initial connection behavior for unusual activity, and logs findings.
 *
 * Requires root privileges to bind to privileged ports (ports < 1024).
 *
 * Usage:
 * sudo php network_monitor_agent.php
 *
 * NOTE: For production, consider using a process manager like systemd or Supervisor
 * to run this script as a daemon. PHP is generally not the first choice for
 * long-running, low-level network daemons compared to languages like Go, Node.js, or Python,
 * but it is capable.
 */

// --- Agent Configuration ---
define('LOG_FILE', 'network_monitor_agent.log');
define('BUFFER_SIZE', 1024); // Size of buffer for reading incoming data
define('CONNECTION_TIMEOUT', 5); // Seconds to wait for initial data from a new connection

// Ports to monitor and their associated protocol names
$monitorPorts = [
    22 => "SSH",
    23 => "TELNET",
    21 => "FTP",
    25 => "SMTP",
    // Add more ports as needed, e.g., 80, 443, 8080 => "HTTP"
    // For testing, you might use a high port like 8000 => "TEST_HTTP"
];

// Heuristics for Unusual Activity / Odd Behaviors
// These are very basic and serve as conceptual examples.
// In a real IDS, these would be sophisticated rulesets.

// Regex patterns for common protocol banners. If no matching banner or unexpected data, it's suspicious.
$protocolBanners = [
    22 => '/SSH-\d\.\d-/i', // SSH banner starts with SSH-x.x-
    23 => '/^\S+\s+login:/i', // Telnet login prompt
    21 => '/220\s+\S+\s+FTP\s+server/i', // FTP server welcome message
    25 => '/220\s+\S+\s+ESMTP/i' // SMTP server welcome message
];

// Threshold for non-printable characters (heuristic for binary payloads/exploits)
define('MIN_PRINTABLE_RATIO_THRESHOLD', 0.7); // If less than 70% of chars are printable, might be binary data/exploit

/**
 * Logs a message with a timestamp and severity to both console and file.
 * @param string $level Severity level (INFO, WARNING, ERROR, CRITICAL).
 * @param string $message The message to log.
 */
function custom_log(string $level, string $message): void
{
    $timestamp = date('Y-m-d H:i:s');
    $logEntry = sprintf("%s - NETWORK_MONITOR_AGENT - %s - %s\n", $timestamp, $level, $message);

    // Log to console (stdout)
    echo $logEntry;

    // Log to file
    file_put_contents(LOG_FILE, $logEntry, FILE_APPEND);
}

/**
 * Performs basic heuristic analysis on incoming data.
 * @param int $port The destination port of the connection.
 * @param string $data The initial data received from the client.
 * @return bool True if suspicious activity is detected, False otherwise.
 */
function analyzeIncomingData(int $port, string $data): bool
{
    global $protocolBanners;
    global $monitorPorts;

    $isSuspicious = false;
    // Attempt to decode, ignoring invalid UTF-8 characters (common in binary data)
    $decodedData = mb_convert_encoding($data, 'UTF-8', 'UTF-8');
    if ($decodedData === false) {
        $decodedData = $data; // Fallback to raw if conversion fails
    }

    // 1. Check for expected protocol banners
    if (isset($protocolBanners[$port])) {
        if (!preg_match($protocolBanners[$port], $decodedData)) {
            custom_log('WARNING', sprintf("  Suspicious: Port %d (%s): Unexpected banner/initial data. Data: %s...", $port, $monitorPorts[$port], substr($decodedData, 0, 50)));
            $isSuspicious = true;
        } else {
            custom_log('INFO', sprintf("  Info: Port %d (%s): Expected banner found.", $port, $monitorPorts[$port]));
        }
    }

    // 2. Check for non-printable characters (heuristic for binary payloads/exploits)
    $printableChars = 0;
    for ($i = 0; $i < strlen($decodedData); $i++) {
        $char = $decodedData[$i];
        $ascii = ord($char);
        if (($ascii >= 32 && $ascii <= 126) || in_array($ascii, [9, 10, 13])) { // ASCII printable + tab, newline, carriage return
            $printableChars++;
        }
    }
    if (strlen($decodedData) > 0 && ($printableChars / strlen($decodedData)) < MIN_PRINTABLE_RATIO_THRESHOLD) {
        custom_log('WARNING', sprintf("  Suspicious: Port %d (%s): Low printable character ratio (%.2f). Potentially binary data.", $port, $monitorPorts[$port], ($printableChars / strlen($decodedData))));
        $isSuspicious = true;
    }

    // 3. Check for unusually long initial data for specific protocols (e.g., port scan payload)
    if (strlen($data) > 200 && in_array($port, [21, 23, 25])) { // FTP, Telnet, SMTP usually have short banners
        custom_log('WARNING', sprintf("  Suspicious: Port %d (%s): Unusually long initial data (%d bytes).", $port, $monitorPorts[$port], strlen($data)));
        $isSuspicious = true;
    }

    // Add more sophisticated checks here:
    // - Rapid connection attempts from a single source (port scanning) - requires stateful tracking
    // - Unexpected commands/strings for the protocol (e.g., HTTP GET on SMTP port)
    // - Known exploit signatures within the data

    return $isSuspicious;
}

/**
 * Handles a new incoming connection.
 * Reads initial data and performs analysis.
 * @param resource $connSocket The client socket connection.
 * @param array $addr Client address information (IP, port).
 * @param int $port The port the connection was made to.
 */
function handleConnection($connSocket, array $addr, int $port): void
{
    global $monitorPorts;

    custom_log('INFO', sprintf("New connection from %s:%d to port %d (%s)", $addr[0], $addr[1], $port, $monitorPorts[$port]));
    try {
        // Set a timeout for reading initial data
        socket_set_option($connSocket, SOL_SOCKET, SO_RCVTIMEO, ['sec' => CONNECTION_TIMEOUT, 'usec' => 0]);
        $data = socket_read($connSocket, BUFFER_SIZE, PHP_BINARY_READ);

        if ($data !== false && strlen($data) > 0) {
            custom_log('INFO', sprintf("  Received %d bytes of initial data.", strlen($data)));
            $suspicious = analyzeIncomingData($port, $data);
            if ($suspicious) {
                custom_log('ERROR', sprintf("  CRITICAL: Suspicious activity detected from %s on port %d!", $addr[0], $port));
                // --- CONCEPTUAL STRACE INTEGRATION ---
                // In a real IDS, if this connection was handled by a known process (e.g., sshd),
                // you might trigger a `strace -p <PID>` on that process.
                // However, for an arbitrary incoming connection where the process handling it
                // is not necessarily known or stable, dynamic strace is highly complex and intrusive.
                // `strace` is primarily for analyzing an *already running process's system calls*.
                // For network forensics, you'd typically capture packets (like with Scapy/tcpdump)
                // or analyze logs.
                custom_log('INFO', sprintf("  Conceptual Next Step: Investigate process listening on port %d " .
                                            "at time of incident using tools like `sudo ss -tulpn` to find PID, " .
                                            "then `sudo strace -p <PID>` for system call tracing if feasible and safe.", $port));
                custom_log('INFO', sprintf("  More practical: Capture full packet data for forensic analysis (e.g., `sudo tcpdump -i any host %s and port %d`).", $addr[0], $port));
            } else {
                custom_log('INFO', "  Initial connection behavior appears normal.");
            }
        } else if ($data === false) {
            custom_log('WARNING', sprintf("  Error reading data from connection: %s", socket_strerror(socket_last_error($connSocket))));
        } else { // $data is empty string, meaning connection closed or no data
            custom_log('INFO', "  No initial data received before timeout, or connection closed quickly.");
        }

    } catch (Throwable $e) {
        custom_log('ERROR', sprintf("  Error handling connection from %s:%d to port %d: %s", $addr[0], $addr[1], $port, $e->getMessage()));
    } finally {
        socket_close($connSocket);
        custom_log('INFO', sprintf("  Connection from %s:%d to port %d closed.", $addr[0], $addr[1], $port));
    }
}


/**
 * Initializes and runs the network monitoring agent.
 * Listens on configured ports for incoming connections.
 */
function startNetworkMonitorAgent(): void
{
    global $monitorPorts;
    $sockets = [];
    $read = []; // For select/stream_select

    foreach ($monitorPorts as $port => $protoName) {
        try {
            $sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
            if ($sock === false) {
                custom_log('ERROR', sprintf("socket_create() failed for port %d: %s", $port, socket_strerror(socket_last_error())));
                continue;
            }

            // Allow reusing address to avoid "Address already in use" errors
            socket_set_option($sock, SOL_SOCKET, SO_REUSEADDR, 1);

            if (socket_bind($sock, '0.0.0.0', $port) === false) {
                custom_log('ERROR', sprintf("socket_bind() failed for port %d: %s", $port, socket_strerror(socket_last_error())));
                if (socket_last_error() == SOCKET_EACCES) { // Permission denied
                    custom_log('ERROR', sprintf("Permission denied to bind to port %d. Run with sudo.", $port));
                }
                socket_close($sock);
                continue;
            }

            if (socket_listen($sock, 5) === false) { // Max 5 pending connections
                custom_log('ERROR', sprintf("socket_listen() failed for port %d: %s", $port, socket_strerror(socket_last_error())));
                socket_close($sock);
                continue;
            }

            // Make the socket non-blocking for use with socket_select
            socket_set_nonblock($sock);

            $sockets[$port] = $sock;
            custom_log('INFO', sprintf("Listening on port %d (%s)...", $port, $protoName));

        } catch (Throwable $e) {
            custom_log('ERROR', sprintf("Error setting up listener on port %d: %s", $port, $e->getMessage()));
        }
    }

    if (empty($sockets)) {
        custom_log('CRITICAL', "No sockets could be bound. Exiting network monitor agent.");
        return;
    }

    custom_log('INFO', "Network monitoring agent started. Waiting for incoming connections...");
    $clientSockets = []; // Array to hold connected client sockets

    // Signal handler for graceful shutdown (Ctrl+C)
    pcntl_signal(SIGINT, function() {
        custom_log('INFO', "Network monitoring agent stopped by user (Ctrl+C).");
        exit(0); // Exit gracefully
    });

    while (true) {
        $read = $sockets; // Add all listening sockets to the read array
        $read = array_merge($read, $clientSockets); // Also include active client sockets if doing further non-blocking I/O

        // Use socket_select to wait for activity on any socket
        // $write and $except are not used for this simple listener
        $num_changed_sockets = socket_select($read, $write, $except, 1); // Timeout 1 second

        if ($num_changed_sockets === false) {
            custom_log('ERROR', sprintf("socket_select() failed: %s", socket_strerror(socket_last_error())));
            break; // Exit loop on error
        } elseif ($num_changed_sockets > 0) {
            foreach ($read as $sock) {
                // Check if it's one of our listening sockets
                if (in_array($sock, $sockets)) {
                    // New connection on a listening socket
                    $conn = socket_accept($sock);
                    if ($conn !== false) {
                        socket_getpeername($conn, $address, $port_client);
                        handleConnection($conn, [$address, $port_client], socket_getsockname($sock, $null, $bound_port));
                        // In a real non-blocking server, you might add $conn to $clientSockets
                        // for further communication. For this monitoring agent, we handle
                        // initial data and close.
                    } else {
                        custom_log('ERROR', sprintf("socket_accept() failed: %s", socket_strerror(socket_last_error())));
                    }
                }
                // If you were handling persistent client connections, you'd add logic here
                // to read from $sock if it's in $clientSockets.
            }
        }
        pcntl_signal_dispatch(); // Process signals
    }

    // Clean up
    foreach ($sockets as $s) {
        socket_close($s);
    }
    foreach ($clientSockets as $cs) { // Close any lingering client sockets
        socket_close($cs);
    }
    custom_log('INFO', "All sockets closed. Network monitoring agent exited.");
}

// Start the agent
startNetworkMonitorAgent();

?>
