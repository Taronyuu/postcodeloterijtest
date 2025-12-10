<?php
/**
 * Reverse SOCKS5 Proxy Client - Web Version (All-in-one)
 * 
 * Access: http://yourserver/client_web.php?server=host:port&run=1
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

$server = $_GET['server'] ?? 'localhost:9000';
$verbose = isset($_GET['verbose']);
$run = isset($_GET['run']);
$debug = isset($_GET['debug']);

// Sanitize
$server = preg_replace('/[^a-zA-Z0-9\.\-\:]/', '', $server);

// ============== Protocol Definitions ==============

class MessageType {
    const REGISTER = 0x01;
    const NEW_CONN = 0x02;
    const CONNECT = 0x03;
    const CONNECT_REPLY = 0x04;
    const DATA = 0x05;
    const CLOSE = 0x06;
    const HEARTBEAT = 0x07;
}

class AddressType {
    const IPV4 = 0x01;
    const DOMAIN = 0x03;
    const IPV6 = 0x04;
}

// ============== Logging ==============

function webLog(string $msg): void {
    echo date('Y-m-d H:i:s') . " - $msg\n";
    @ob_flush();
    @flush();
}

// ============== Protocol Functions ==============

function readExact($stream, int $n): ?string {
    if ($n === 0) return '';
    $data = '';
    $remaining = $n;
    $attempts = 0;
    while ($remaining > 0 && $attempts < 1000) {
        $chunk = @fread($stream, $remaining);
        if ($chunk === false) {
            webLog("ERROR: fread failed");
            return null;
        }
        if ($chunk === '') {
            if (feof($stream)) {
                webLog("DEBUG: EOF reached");
                return null;
            }
            $attempts++;
            usleep(10000);
            continue;
        }
        $data .= $chunk;
        $remaining -= strlen($chunk);
        $attempts = 0;
    }
    return strlen($data) === $n ? $data : null;
}

function writeMessage($stream, int $msgType, int $connId, string $payload = ''): bool {
    $header = pack('C', $msgType) . pack('N', $connId) . pack('N', strlen($payload)) . $payload;
    $written = @fwrite($stream, $header);
    if ($written === false) {
        webLog("ERROR: fwrite failed");
        return false;
    }
    @fflush($stream);
    return true;
}

function readMessage($stream): ?array {
    $header = readExact($stream, 9);
    if ($header === null || strlen($header) < 9) {
        return null;
    }
    $msgType = ord($header[0]);
    $connId = unpack('N', substr($header, 1, 4))[1];
    $length = unpack('N', substr($header, 5, 4))[1];
    $payload = '';
    if ($length > 0) {
        $payload = readExact($stream, $length);
        if ($payload === null) {
            return null;
        }
    }
    return [$msgType, $connId, $payload];
}

function unpackAddress(string $data): ?array {
    if (strlen($data) < 1) return null;
    $atype = ord($data[0]);
    if ($atype === AddressType::IPV4) {
        if (strlen($data) < 7) return null;
        $addr = inet_ntop(substr($data, 1, 4));
        $port = unpack('n', substr($data, 5, 2))[1];
        return [$atype, $addr, $port];
    } elseif ($atype === AddressType::DOMAIN) {
        if (strlen($data) < 2) return null;
        $length = ord($data[1]);
        if (strlen($data) < 4 + $length) return null;
        $addr = substr($data, 2, $length);
        $port = unpack('n', substr($data, 2 + $length, 2))[1];
        return [$atype, $addr, $port];
    } elseif ($atype === AddressType::IPV6) {
        if (strlen($data) < 19) return null;
        $addr = inet_ntop(substr($data, 1, 16));
        $port = unpack('n', substr($data, 17, 2))[1];
        return [$atype, $addr, $port];
    }
    return null;
}

// ============== Client Implementation ==============

class WebReverseClient {
    private string $serverHost;
    private int $serverPort;
    private $serverStream = null;
    private array $tunnels = [];
    private bool $verbose;
    
    public function __construct(string $serverHost, int $serverPort, bool $verbose = false) {
        $this->serverHost = $serverHost;
        $this->serverPort = $serverPort;
        $this->verbose = $verbose;
    }
    
    public function run(): void {
        webLog("INFO: Starting reverse SOCKS5 client");
        webLog("INFO: Target server: {$this->serverHost}:{$this->serverPort}");
        
        try {
            if ($this->connectToServer()) {
                $this->handleServerMessages();
            }
        } catch (Throwable $e) {
            webLog("ERROR: " . $e->getMessage());
            webLog("DEBUG: " . $e->getTraceAsString());
        }
        
        $this->cleanup();
        webLog("INFO: Connection ended. Use the Reconnect button to try again.");
    }
    
    private function connectToServer(): bool {
        webLog("INFO: Connecting to {$this->serverHost}:{$this->serverPort}...");
        
        $errno = 0;
        $errstr = '';
        
        $ctx = stream_context_create([
            'socket' => [
                'tcp_nodelay' => true,
            ]
        ]);
        
        $this->serverStream = @stream_socket_client(
            "tcp://{$this->serverHost}:{$this->serverPort}",
            $errno,
            $errstr,
            30,
            STREAM_CLIENT_CONNECT,
            $ctx
        );
        
        if ($this->serverStream === false) {
            webLog("ERROR: Failed to connect: $errstr (errno: $errno)");
            return false;
        }
        
        webLog("INFO: TCP connection established");
        
        // Set stream options
        stream_set_blocking($this->serverStream, true);
        stream_set_timeout($this->serverStream, 30);
        
        // Send registration
        webLog("INFO: Sending registration...");
        if (!writeMessage($this->serverStream, MessageType::REGISTER, 0, 'webclient')) {
            webLog("ERROR: Failed to send registration");
            return false;
        }
        
        webLog("INFO: Connected and registered with server");
        return true;
    }
    
    private function handleServerMessages(): void {
        $lastHeartbeat = time();
        $loopCount = 0;
        
        webLog("INFO: Entering message loop");
        
        while (true) {
            $loopCount++;
            
            // Check for client disconnect every 100 iterations
            if ($loopCount % 100 === 0 && connection_aborted()) {
                webLog("INFO: Client disconnected");
                break;
            }
            
            // Build arrays for stream_select
            $readStreams = [$this->serverStream];
            foreach ($this->tunnels as $tunnel) {
                if ($tunnel['stream'] !== null) {
                    $readStreams[] = $tunnel['stream'];
                }
            }
            $writeStreams = [];
            $exceptStreams = [];
            
            $changed = @stream_select($readStreams, $writeStreams, $exceptStreams, 1);
            
            if ($changed === false) {
                webLog("ERROR: stream_select failed");
                break;
            }
            
            // Check server stream
            if (in_array($this->serverStream, $readStreams)) {
                $meta = @stream_get_meta_data($this->serverStream);
                if (!empty($meta['eof']) || @feof($this->serverStream)) {
                    webLog("INFO: Server closed connection");
                    break;
                }
                
                $msg = readMessage($this->serverStream);
                if ($msg === null) {
                    webLog("INFO: Failed to read message, connection may be closed");
                    break;
                }
                
                [$msgType, $connId, $payload] = $msg;
                $this->handleServerMessage($msgType, $connId, $payload);
            }
            
            // Check tunnel streams
            foreach ($this->tunnels as $connId => $tunnel) {
                if ($tunnel['stream'] !== null && in_array($tunnel['stream'], $readStreams)) {
                    $this->forwardFromTarget($connId);
                }
            }
            
            // Heartbeat every 30 seconds
            if (time() - $lastHeartbeat >= 30) {
                if ($this->verbose) webLog("DEBUG: Sending heartbeat");
                writeMessage($this->serverStream, MessageType::HEARTBEAT, 0);
                $lastHeartbeat = time();
            }
        }
    }

    private function handleServerMessage(int $msgType, int $connId, string $payload): void {
        switch ($msgType) {
            case MessageType::CONNECT:
                $this->handleConnect($connId, $payload);
                break;
            case MessageType::DATA:
                if (isset($this->tunnels[$connId]) && $this->tunnels[$connId]['stream'] !== null) {
                    @fwrite($this->tunnels[$connId]['stream'], $payload);
                    @fflush($this->tunnels[$connId]['stream']);
                }
                break;
            case MessageType::CLOSE:
                $this->closeTunnel($connId);
                break;
            case MessageType::HEARTBEAT:
                if ($this->verbose) webLog("DEBUG: Received heartbeat");
                writeMessage($this->serverStream, MessageType::HEARTBEAT, 0);
                break;
            default:
                webLog("WARNING: Unknown message type: $msgType");
        }
    }
    
    private function handleConnect(int $connId, string $payload): void {
        $addrInfo = unpackAddress($payload);
        if ($addrInfo === null) {
            webLog("ERROR: Failed to unpack address for conn $connId");
            writeMessage($this->serverStream, MessageType::CONNECT_REPLY, $connId, chr(0x01));
            return;
        }
        
        [$atype, $addr, $port] = $addrInfo;
        webLog("INFO: Connect request #$connId -> $addr:$port");
        
        // Resolve domain
        $target = $addr;
        if ($atype === AddressType::DOMAIN) {
            $resolved = @gethostbyname($addr);
            if ($resolved === $addr) {
                webLog("WARNING: Failed to resolve $addr");
                writeMessage($this->serverStream, MessageType::CONNECT_REPLY, $connId, chr(0x04));
                return;
            }
            $target = $resolved;
            if ($this->verbose) webLog("DEBUG: Resolved $addr -> $target");
        }
        
        // Connect
        $errno = 0;
        $errstr = '';
        $stream = @stream_socket_client("tcp://$target:$port", $errno, $errstr, 30);
        
        if ($stream === false) {
            webLog("WARNING: Connection #$connId to $addr:$port failed: $errstr");
            $reply = chr(0x01);
            if ($errno === 111 || $errno === 10061) $reply = chr(0x05);
            elseif ($errno === 113 || $errno === 10065) $reply = chr(0x04);
            elseif ($errno === 101 || $errno === 10051) $reply = chr(0x03);
            writeMessage($this->serverStream, MessageType::CONNECT_REPLY, $connId, $reply);
            return;
        }
        
        stream_set_blocking($stream, false);
        $this->tunnels[$connId] = ['stream' => $stream, 'addr' => $addr, 'port' => $port];
        writeMessage($this->serverStream, MessageType::CONNECT_REPLY, $connId, chr(0x00));
        webLog("INFO: Connection #$connId established to $addr:$port");
    }
    
    private function forwardFromTarget(int $connId): void {
        if (!isset($this->tunnels[$connId])) return;
        
        $stream = $this->tunnels[$connId]['stream'];
        if (@feof($stream)) {
            $this->closeTunnel($connId);
            return;
        }
        
        $data = @fread($stream, 65536);
        if ($data === false || ($data === '' && @feof($stream))) {
            $this->closeTunnel($connId);
            return;
        }
        
        if ($data !== '') {
            writeMessage($this->serverStream, MessageType::DATA, $connId, $data);
        }
    }
    
    private function closeTunnel(int $connId): void {
        if (!isset($this->tunnels[$connId])) return;
        
        if ($this->verbose) webLog("DEBUG: Closing tunnel #$connId");
        
        $tunnel = $this->tunnels[$connId];
        if ($tunnel['stream'] !== null) {
            @fclose($tunnel['stream']);
        }
        unset($this->tunnels[$connId]);
        writeMessage($this->serverStream, MessageType::CLOSE, $connId);
    }
    
    private function cleanup(): void {
        foreach ($this->tunnels as $connId => $tunnel) {
            if (isset($tunnel['stream']) && is_resource($tunnel['stream'])) {
                @fclose($tunnel['stream']);
            }
        }
        $this->tunnels = [];
        
        if ($this->serverStream !== null && is_resource($this->serverStream)) {
            @fclose($this->serverStream);
        }
        $this->serverStream = null;
        webLog("INFO: Cleanup complete");
    }
}

// ============== Test Mode ==============

if (isset($_GET['test'])) {
    header('Content-Type: application/json');
    
    $result = ['success' => false, 'message' => '', 'details' => []];
    
    // Parse server
    if (strpos($server, ':') !== false) {
        $parts = explode(':', $server);
        $port = (int)array_pop($parts);
        $host = implode(':', $parts);
    } else {
        $host = $server;
        $port = 9000;
    }
    
    $result['details']['host'] = $host;
    $result['details']['port'] = $port;
    
    // Test DNS resolution
    $ip = @gethostbyname($host);
    $result['details']['resolved_ip'] = $ip;
    $result['details']['dns_ok'] = ($ip !== $host || filter_var($host, FILTER_VALIDATE_IP));
    
    if (!$result['details']['dns_ok']) {
        $result['message'] = "DNS resolution failed for $host";
        echo json_encode($result);
        exit;
    }
    
    // Test TCP connection
    $errno = 0;
    $errstr = '';
    $start = microtime(true);
    $conn = @stream_socket_client("tcp://$host:$port", $errno, $errstr, 5);
    $elapsed = round((microtime(true) - $start) * 1000);
    
    $result['details']['connect_time_ms'] = $elapsed;
    $result['details']['errno'] = $errno;
    $result['details']['errstr'] = $errstr;
    
    if ($conn === false) {
        $result['message'] = "Connection failed: $errstr (errno: $errno)";
        
        // Common error explanations
        if ($errno === 99) {
            $result['message'] .= "\n\nError 99 'Cannot assign requested address' - you're likely in a container (Docker).";
            $result['message'] .= "\n\nIf server runs on host machine, try:";
            $result['message'] .= "\n  • host.docker.internal:9000 (Docker Desktop)";
            $result['message'] .= "\n  • 172.17.0.1:9000 (Docker Linux default gateway)";
            $result['message'] .= "\n  • Your host's actual LAN IP (e.g., 192.168.x.x:9000)";
        } elseif ($errno === 63) {
            $result['message'] .= "\n\nError 63 means outbound TCP connections are blocked.";
            $result['message'] .= "\nThis is common on shared hosting. You may need a VPS.";
        } elseif ($errno === 111 || $errno === 10061) {
            $result['message'] .= "\n\nConnection refused - server may not be running on $host:$port";
        } elseif ($errno === 110 || $errno === 10060) {
            $result['message'] .= "\n\nConnection timed out - server may be firewalled or unreachable";
        }
    } else {
        $result['success'] = true;
        $result['message'] = "Connected successfully to $host:$port in {$elapsed}ms";
        fclose($conn);
    }
    
    echo json_encode($result, JSON_PRETTY_PRINT);
    exit;
}

// ============== Run Mode ==============

if ($run) {
    // Disable limits
    @set_time_limit(0);
    @ini_set('max_execution_time', '0');
    ignore_user_abort(false);
    
    // Disable buffering
    @ini_set('output_buffering', 'off');
    @ini_set('zlib.output_compression', false);
    @ini_set('implicit_flush', true);
    while (@ob_end_clean());
    
    header('Content-Type: text/plain; charset=utf-8');
    header('X-Accel-Buffering: no');
    header('Cache-Control: no-cache, no-store');
    
    echo "========================================\n";
    echo "Reverse SOCKS5 Client - Web Edition\n";
    echo "========================================\n";
    echo "Server: $server\n";
    echo "Verbose: " . ($verbose ? 'yes' : 'no') . "\n";
    echo "PHP Version: " . phpversion() . "\n";
    echo "Started: " . date('Y-m-d H:i:s T') . "\n";
    echo "========================================\n\n";
    flush();
    
    // Parse server
    if (strpos($server, ':') !== false) {
        $parts = explode(':', $server);
        $port = (int)array_pop($parts);
        $host = implode(':', $parts);
    } else {
        $host = $server;
        $port = 9000;
    }
    
    // Run client
    $client = new WebReverseClient($host, $port, $verbose);
    $client->run();
    
    echo "\n========================================\n";
    echo "Client stopped at " . date('Y-m-d H:i:s T') . "\n";
    exit;
}

// ============== Web UI ==============
?>
<!DOCTYPE html>
<html>
<head>
    <title>Reverse SOCKS5 Client</title>
    <style>
        * { box-sizing: border-box; }
        body { font-family: 'Consolas', 'Monaco', monospace; background: #0d1117; color: #c9d1d9; padding: 20px; margin: 0; }
        .container { max-width: 1000px; margin: 0 auto; }
        h1 { color: #58a6ff; margin-bottom: 5px; }
        .subtitle { color: #8b949e; margin-bottom: 20px; }
        .panel { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 16px; margin-bottom: 16px; }
        .panel h2 { color: #58a6ff; font-size: 14px; margin: 0 0 12px 0; text-transform: uppercase; }
        .row { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
        input[type="text"] { background: #0d1117; border: 1px solid #30363d; color: #c9d1d9; padding: 8px 12px; border-radius: 4px; width: 280px; font-family: inherit; }
        input[type="text"]:focus { border-color: #58a6ff; outline: none; }
        label { color: #8b949e; cursor: pointer; }
        input[type="checkbox"] { margin-right: 5px; }
        button { padding: 8px 16px; border: none; border-radius: 4px; font-family: inherit; font-weight: 600; cursor: pointer; }
        .btn-start { background: #238636; color: #fff; }
        .btn-start:hover { background: #2ea043; }
        .btn-stop { background: #da3633; color: #fff; }
        .btn-stop:hover { background: #f85149; }
        .btn-clear { background: #30363d; color: #c9d1d9; }
        .btn-clear:hover { background: #484f58; }
        table { width: 100%; border-collapse: collapse; }
        td { padding: 6px 0; border-bottom: 1px solid #21262d; }
        td:first-child { color: #8b949e; width: 180px; }
        .ok { color: #3fb950; }
        .error { color: #f85149; }
        .warn { color: #d29922; }
        #output { background: #0d1117; border: 1px solid #30363d; border-radius: 4px; padding: 12px; height: 400px; overflow-y: auto; white-space: pre-wrap; word-wrap: break-word; font-size: 13px; line-height: 1.5; }
        .status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 8px; }
        .status-dot.stopped { background: #484f58; }
        .status-dot.running { background: #3fb950; animation: pulse 1.5s infinite; }
        .status-dot.connecting { background: #d29922; animation: pulse 0.5s infinite; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }
        .debug-info { font-size: 11px; color: #6e7681; margin-top: 8px; }
    </style>
</head>
<body>
<div class="container">
    <h1>🔌 Reverse SOCKS5 Client</h1>
    <p class="subtitle">Web-based client - runs directly in browser request</p>
    
    <div class="panel">
        <h2>Configuration</h2>
        <div class="row">
            <input type="text" id="serverInput" value="<?= htmlspecialchars($server) ?>" placeholder="server:port">
            <label><input type="checkbox" id="verboseInput" <?= $verbose ? 'checked' : '' ?>> Verbose</label>
            <label><input type="checkbox" id="autoReconnect"> Auto-reconnect</label>
        </div>
        <div class="row" style="margin-top: 10px;">
            <button class="btn-start" id="connectBtn" onclick="toggleConnection()">▶ Connect</button>
            <button class="btn-clear" onclick="clearOutput()">Clear</button>
        </div>
        <div class="debug-info">
            Client runs in this page via streaming HTTP. Close tab or click Disconnect to terminate.
        </div>
    </div>

    <div class="panel">
        <h2>System</h2>
        <table>
            <tr><td>PHP Version</td><td><?= phpversion() ?></td></tr>
            <tr><td>Max Execution Time</td><td><?= ini_get('max_execution_time') ?>s (disabled when running)</td></tr>
            <tr><td>allow_url_fopen</td><td class="<?= ini_get('allow_url_fopen') ? 'ok' : 'error' ?>"><?= ini_get('allow_url_fopen') ? 'Enabled' : 'Disabled' ?></td></tr>
            <tr><td>Server Time</td><td><?= date('Y-m-d H:i:s T') ?></td></tr>
            <tr><td>Container/Hostname</td><td><?= gethostname() ?></td></tr>
            <tr><td>Server IP</td><td><?= $_SERVER['SERVER_ADDR'] ?? 'unknown' ?></td></tr>
        </table>
    </div>

    <div class="panel">
        <h2>Network Test</h2>
        <div class="row">
            <button class="btn-clear" onclick="testConnection()">Test Connection</button>
            <span id="testResult" style="margin-left:10px;"></span>
        </div>
        <div class="debug-info">
            Tests if PHP can make outbound TCP connections to the target server.
            Error 63 "Operation not permitted" means outbound connections are blocked.
        </div>
    </div>

    <div class="panel">
        <h2><span class="status-dot stopped" id="statusDot"></span>Status: <span id="statusText">Stopped</span></h2>
        <div id="output">Ready. Click Start to connect to server.\n\nMake sure the Python server is running:\n  python server.py -c 9000 -s 1080</div>
    </div>
</div>

<script>
let controller = null;
let connected = false;
let reconnectTimeout = null;

async function toggleConnection() {
    const btn = document.getElementById('connectBtn');
    
    // If connected, disconnect
    if (connected && controller) {
        controller.abort();
        appendOutput('\n[USER] Disconnect requested\n');
        return;
    }
    
    // Cancel any pending reconnect
    if (reconnectTimeout) {
        clearTimeout(reconnectTimeout);
        reconnectTimeout = null;
    }
    
    const server = document.getElementById('serverInput').value.trim();
    const verbose = document.getElementById('verboseInput').checked;
    
    if (!server) {
        alert('Please enter server address');
        return;
    }
    
    setStatus('connecting', 'Connecting...');
    document.getElementById('output').textContent = '';
    btn.textContent = '■ Disconnect';
    btn.className = 'btn-stop';
    
    controller = new AbortController();
    
    try {
        const url = `?server=${encodeURIComponent(server)}&run=1${verbose ? '&verbose=1' : ''}`;
        const response = await fetch(url, { signal: controller.signal });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        
        connected = true;
        setStatus('running', 'Running');
        
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            appendOutput(decoder.decode(value));
        }
    } catch (e) {
        if (e.name !== 'AbortError') {
            appendOutput('\n[CLIENT ERROR] ' + e.message + '\n');
        }
    }
    
    connected = false;
    controller = null;
    
    const autoReconnect = document.getElementById('autoReconnect').checked;
    if (autoReconnect) {
        btn.textContent = 'Reconnecting in 3s...';
        btn.className = 'btn-start';
        btn.disabled = true;
        setStatus('connecting', 'Reconnecting...');
        
        reconnectTimeout = setTimeout(() => {
            reconnectTimeout = null;
            if (document.getElementById('autoReconnect').checked) {
                toggleConnection();
            } else {
                btn.textContent = '▶ Reconnect';
                btn.disabled = false;
                setStatus('stopped', 'Stopped');
            }
        }, 3000);
    } else {
        btn.textContent = '▶ Reconnect';
        btn.className = 'btn-start';
        btn.disabled = false;
        setStatus('stopped', 'Stopped');
    }
}

function setStatus(state, text) {
    const dot = document.getElementById('statusDot');
    dot.className = 'status-dot ' + state;
    document.getElementById('statusText').textContent = text;
}

function appendOutput(text) {
    const el = document.getElementById('output');
    el.textContent += text;
    el.scrollTop = el.scrollHeight;
}

function clearOutput() {
    document.getElementById('output').textContent = '';
}

async function testConnection() {
    const server = document.getElementById('serverInput').value.trim();
    const resultEl = document.getElementById('testResult');
    
    if (!server) {
        resultEl.innerHTML = '<span class="error">Enter server address first</span>';
        return;
    }
    
    resultEl.innerHTML = '<span class="warn">Testing...</span>';
    
    try {
        const response = await fetch(`?server=${encodeURIComponent(server)}&test=1`);
        const data = await response.json();
        
        if (data.success) {
            resultEl.innerHTML = `<span class="ok">✓ ${data.message}</span>`;
        } else {
            resultEl.innerHTML = `<span class="error">✗ ${data.message.replace(/\n/g, '<br>')}</span>`;
        }
        
        // Also log details
        console.log('Connection test details:', data.details);
    } catch (e) {
        resultEl.innerHTML = `<span class="error">Test failed: ${e.message}</span>`;
    }
}

window.addEventListener('beforeunload', () => {
    if (controller) controller.abort();
    if (reconnectTimeout) clearTimeout(reconnectTimeout);
});
</script>
</body>
</html>
