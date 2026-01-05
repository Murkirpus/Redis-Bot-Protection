<?php
/**
 * Test API for Bot Protection Web Interface
 * Обробляє тестові запити і повертає результати через Server-Sent Events
 */

// Disable output buffering for SSE
if (ob_get_level()) ob_end_clean();
header('Content-Type: text/event-stream');
header('Cache-Control: no-cache');
header('X-Accel-Buffering: no');

// Get parameters
$test = $_GET['test'] ?? 'burst';
$url = $_GET['url'] ?? 'https://dj-x.info/index.php?action=search';
$timeout = (int)($_GET['timeout'] ?? 10);
$verbose = $_GET['verbose'] === 'true';

// Send SSE message
function sendEvent($data) {
    echo "data: " . json_encode($data) . "\n\n";
    flush();
}

// HTTP Client
class HTTPClient {
    private $url;
    private $timeout;
    private $cookieFile;
    
    public function __construct($url, $timeout) {
        $this->url = $url;
        $this->timeout = $timeout;
        $this->cookieFile = tempnam(sys_get_temp_dir(), 'bot_test_');
    }
    
    public function request($userAgent = null, $useCookies = false) {
        $ch = curl_init($this->url);
        
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, $this->timeout);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        
        if ($userAgent) {
            curl_setopt($ch, CURLOPT_USERAGENT, $userAgent);
        }
        
        if ($useCookies) {
            curl_setopt($ch, CURLOPT_COOKIEJAR, $this->cookieFile);
            curl_setopt($ch, CURLOPT_COOKIEFILE, $this->cookieFile);
        }
        
        $startTime = microtime(true);
        $response = curl_exec($ch);
        $duration = microtime(true) - $startTime;
        
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        
        curl_close($ch);
        
        return [
            'http_code' => $httpCode,
            'duration' => round($duration, 3),
            'error' => $error
        ];
    }
    
    public function __destruct() {
        if (file_exists($this->cookieFile)) {
            unlink($this->cookieFile);
        }
    }
}

// Run test
$client = new HTTPClient($url, $timeout);

switch ($test) {
    case 'burst':
        runBurstTest($client, $verbose);
        break;
    case 'ratelimit':
        runRateLimitTest($client, $verbose);
        break;
    case 'ua-rotation':
        runUARotationTest($client, $verbose);
        break;
    case 'cookie':
        runCookieTest($client, $verbose);
        break;
    case 'googlebot':
        runGoogleBotTest($client, $verbose);
        break;
    default:
        sendEvent(['type' => 'error', 'message' => 'Unknown test']);
}

// =============================================================================
// BURST DETECTION TEST
// =============================================================================
function runBurstTest($client, $verbose) {
    $total = 25;
    $blockedAt = null;
    
    for ($i = 1; $i <= $total; $i++) {
        sendEvent(['type' => 'progress', 'current' => $i, 'total' => $total]);
        
        $result = $client->request("TestBot-Burst/1.0");
        
        if ($verbose) {
            $status = $result['http_code'] == 200 ? 'OK' : 'BLOCKED';
            sendEvent([
                'type' => 'log',
                'message' => "Request #$i: HTTP {$result['http_code']} ({$result['duration']}s) - $status",
                'level' => $result['http_code'] == 200 ? 'success' : 'error'
            ]);
        }
        
        if ($result['http_code'] == 502) {
            $blockedAt = $i;
            break;
        }
        
        usleep(100000); // 0.1s
    }
    
    if ($blockedAt !== null && $blockedAt <= 21) {
        sendEvent([
            'type' => 'result',
            'success' => true,
            'message' => "Burst Detection працює! Блокування на запиті #$blockedAt",
            'blocked_at' => $blockedAt
        ]);
    } elseif ($blockedAt !== null) {
        sendEvent([
            'type' => 'result',
            'success' => true,
            'message' => "Блокування на запиті #$blockedAt (очікувалось 21)",
            'blocked_at' => $blockedAt
        ]);
    } else {
        sendEvent([
            'type' => 'result',
            'success' => false,
            'message' => "Burst Detection НЕ спрацював! Всі $total запитів пройшли"
        ]);
    }
}

// =============================================================================
// RATE LIMIT TEST
// =============================================================================
function runRateLimitTest($client, $verbose) {
    $total = 65;
    $blockedAt = null;
    
    for ($i = 1; $i <= $total; $i++) {
        sendEvent(['type' => 'progress', 'current' => $i, 'total' => $total]);
        
        $result = $client->request("TestBot-RateLimit/1.0");
        
        if ($verbose || $i <= 3 || $i % 10 == 0 || $i >= 58 || $result['http_code'] == 502) {
            $status = $result['http_code'] == 200 ? 'OK' : 'BLOCKED';
            sendEvent([
                'type' => 'log',
                'message' => "Request #$i: HTTP {$result['http_code']} - $status",
                'level' => $result['http_code'] == 200 ? 'success' : 'error'
            ]);
        }
        
        if ($result['http_code'] == 502) {
            $blockedAt = $i;
            break;
        }
        
        usleep(900000); // 0.9s
    }
    
    if ($blockedAt !== null && $blockedAt >= 60 && $blockedAt <= 65) {
        sendEvent([
            'type' => 'result',
            'success' => true,
            'message' => "Rate Limit працює! Блокування на запиті #$blockedAt",
            'blocked_at' => $blockedAt
        ]);
    } elseif ($blockedAt !== null) {
        sendEvent([
            'type' => 'result',
            'success' => true,
            'message' => "Блокування на запиті #$blockedAt (очікувалось 61-65)",
            'blocked_at' => $blockedAt
        ]);
    } else {
        sendEvent([
            'type' => 'result',
            'success' => false,
            'message' => "Rate Limit НЕ спрацював! Всі $total запитів пройшли"
        ]);
    }
}

// =============================================================================
// UA ROTATION TEST
// =============================================================================
function runUARotationTest($client, $verbose) {
    $userAgents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X) Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Safari/604.1",
        "Mozilla/5.0 (Windows NT 10.0) Edge/120.0.0.0",
        "Mozilla/5.0 (Linux; Android 13) Chrome/119.0 Mobile",
        "Mozilla/5.0 (iPad; CPU OS 17_0) Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) Opera/105.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0) Brave/1.60.0",
        "Mozilla/5.0 (Macintosh) Vivaldi/6.4.0",
        "TestBot-1/1.0",
        "TestBot-2/1.0",
        "TestBot-3/1.0",
        "TestBot-4/1.0",
        "TestBot-5/1.0",
    ];
    
    $total = count($userAgents);
    $blockedAt = null;
    
    foreach ($userAgents as $i => $ua) {
        $requestNum = $i + 1;
        sendEvent(['type' => 'progress', 'current' => $requestNum, 'total' => $total]);
        
        $result = $client->request($ua);
        
        $shortUA = substr($ua, 0, 40) . (strlen($ua) > 40 ? '...' : '');
        $status = $result['http_code'] == 200 ? 'OK' : 'BLOCKED';
        
        sendEvent([
            'type' => 'log',
            'message' => "Request #$requestNum: HTTP {$result['http_code']} - $shortUA",
            'level' => $result['http_code'] == 200 ? 'success' : 'error'
        ]);
        
        if ($result['http_code'] == 502) {
            $blockedAt = $requestNum;
            break;
        }
        
        usleep(300000); // 0.3s
    }
    
    if ($blockedAt !== null && $blockedAt >= 11 && $blockedAt <= 15) {
        sendEvent([
            'type' => 'result',
            'success' => true,
            'message' => "UA Rotation працює! Блокування на запиті #$blockedAt",
            'blocked_at' => $blockedAt
        ]);
    } elseif ($blockedAt !== null) {
        sendEvent([
            'type' => 'result',
            'success' => true,
            'message' => "Блокування на запиті #$blockedAt (очікувалось 11-15)",
            'blocked_at' => $blockedAt
        ]);
    } else {
        sendEvent([
            'type' => 'result',
            'success' => false,
            'message' => "UA Rotation НЕ спрацював! Можливо функція вимкнена"
        ]);
    }
}

// =============================================================================
// COOKIE MULTIPLIER TEST
// =============================================================================
function runCookieTest($client, $verbose) {
    // Test without cookies
    sendEvent(['type' => 'log', 'message' => 'Тест БЕЗ cookie...', 'level' => 'info']);
    
    $blockedWithout = null;
    for ($i = 1; $i <= 25; $i++) {
        sendEvent(['type' => 'progress', 'current' => $i, 'total' => 70]);
        
        $result = $client->request("TestBot-Cookie/1.0", false);
        
        if ($result['http_code'] == 502) {
            $blockedWithout = $i;
            sendEvent(['type' => 'log', 'message' => "Без cookie: заблоковано на #$i", 'level' => 'error']);
            break;
        }
        
        usleep(100000);
    }
    
    sleep(3); // Clear counters
    
    // Test with cookies
    sendEvent(['type' => 'log', 'message' => 'Тест З cookie...', 'level' => 'info']);
    
    $blockedWith = null;
    for ($i = 1; $i <= 45; $i++) {
        sendEvent(['type' => 'progress', 'current' => 25 + $i, 'total' => 70]);
        
        $result = $client->request("TestBot-Cookie/1.0", true);
        
        if ($result['http_code'] == 502) {
            $blockedWith = $i;
            sendEvent(['type' => 'log', 'message' => "З cookie: заблоковано на #$i", 'level' => 'error']);
            break;
        }
        
        usleep(100000);
    }
    
    if ($blockedWith > $blockedWithout) {
        $diff = $blockedWith - $blockedWithout;
        sendEvent([
            'type' => 'result',
            'success' => true,
            'message' => "Cookie Multiplier працює! З cookie на $diff запитів більше",
            'without_cookie' => $blockedWithout,
            'with_cookie' => $blockedWith,
            'diff' => $diff
        ]);
    } else {
        sendEvent([
            'type' => 'result',
            'success' => false,
            'message' => "Cookie Multiplier може не працювати"
        ]);
    }
}

// =============================================================================
// GOOGLE BOT TEST
// =============================================================================
function runGoogleBotTest($client, $verbose) {
    $ua = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
    $total = 30;
    $allPassed = true;
    
    for ($i = 1; $i <= $total; $i++) {
        sendEvent(['type' => 'progress', 'current' => $i, 'total' => $total]);
        
        $result = $client->request($ua);
        
        if ($verbose || $i <= 3 || $i % 10 == 0 || $i == 30) {
            $status = $result['http_code'] == 200 ? 'OK' : 'BLOCKED';
            sendEvent([
                'type' => 'log',
                'message' => "GoogleBot Request #$i: HTTP {$result['http_code']} - $status",
                'level' => $result['http_code'] == 200 ? 'success' : 'error'
            ]);
        }
        
        if ($result['http_code'] != 200) {
            $allPassed = false;
            break;
        }
        
        usleep(100000);
    }
    
    if ($allPassed) {
        sendEvent([
            'type' => 'result',
            'success' => true,
            'message' => "Google Bot Whitelist працює! Всі $total запитів пройшли"
        ]);
    } else {
        sendEvent([
            'type' => 'result',
            'success' => false,
            'message' => "Googlebot заблоковано (можливо IP не в whitelist)"
        ]);
    }
}