<?php
/**
 * MurKir Security - Cleanup Script
 * Version: 1.1 (PHP 7.4 compatible)
 * Compatibility: SimpleBotProtection v3.3.1
 * 
 * Автоматичне розблокування IP через API коли TTL в Redis спливає
 */

// ============================================================================
// НАЛАШТУВАННЯ
// ============================================================================

$config = array(
    // Redis
    'redis_host'     => '127.0.0.1',
    'redis_port'     => 6379,
    'redis_password' => null,
    'redis_database' => 1,
    'redis_prefix'   => 'bot_protection:',
    'rdns_prefix'    => 'rdns:',
    
    // API для iptables - УВІМКНЕНО!
    'api_enabled'    => true,
    'api_url'        => 'https://mysite.com/redis-bot_protection/API/iptables.php',
    'api_key'        => '123456',
    'api_timeout'    => 5,
    'api_user_agent' => 'MurKir-Cleanup/1.1',
    
    // Параметри очистки
    'ttl_threshold'  => 300,    // Розблокувати якщо TTL < 5 хв
    'batch_size'     => 100,
    'api_delay_ms'   => 100,    // Затримка між API викликами (мс)
    
    // TTL для очистки різних типів записів
    'rate_ttl'       => 3600,
    'rdns_ttl'       => 1800,
    'tracking_ttl'   => 7200,
);

// ============================================================================
// ВИЗНАЧЕННЯ РЕЖИМУ ЗАПУСКУ
// ============================================================================

$isCLI = (php_sapi_name() === 'cli');
$isWeb = !$isCLI;

// Веб-режим - без пароля
if ($isWeb) {
    header('Content-Type: text/plain; charset=utf-8');
    @ini_set('output_buffering', 'off');
    @ini_set('implicit_flush', 'on');
    if (ob_get_level()) {
        ob_end_flush();
    }
}

// ============================================================================
// КЛАС ОЧИСТКИ
// ============================================================================

class MurKirCleanup {
    private $redis;
    private $config;
    private $isWeb;
    private $startTime;
    
    private $stats = array(
        'blocks_checked'      => 0,
        'blocks_expired'      => 0,
        'blocks_unblocked'    => 0,
        'blocks_api_success'  => 0,
        'blocks_api_failed'   => 0,
        'blocks_api_skipped'  => 0,
        'rate_cleaned'        => 0,
        'rdns_cleaned'        => 0,
        'tracking_cleaned'    => 0,
        'ua_tracking_cleaned' => 0,
        'api_errors'          => array(),
    );
    
    public function __construct($config, $isWeb = false) {
        $this->config = $config;
        $this->isWeb = $isWeb;
        $this->startTime = microtime(true);
        $this->connectRedis();
    }
    
    private function output($message) {
        echo $message;
        if ($this->isWeb) {
            flush();
        }
    }
    
    private function connectRedis() {
        try {
            $this->redis = new Redis();
            
            if (!$this->redis->connect($this->config['redis_host'], $this->config['redis_port'], 2)) {
                throw new Exception("Cannot connect to Redis");
            }
            
            if ($this->config['redis_password']) {
                $this->redis->auth($this->config['redis_password']);
            }
            
            $this->redis->select($this->config['redis_database']);
            $this->redis->setOption(Redis::OPT_SERIALIZER, Redis::SERIALIZER_PHP);
            
            $this->output("✓ Connected to Redis (db: " . $this->config['redis_database'] . ")\n");
            
        } catch (Exception $e) {
            $this->output("✗ Redis connection failed: " . $e->getMessage() . "\n");
            throw $e;
        }
    }
    
    /**
     * Виклик API для розблокування IP
     */
    private function unblockViaAPI($ip) {
        if (!$this->config['api_enabled']) {
            return array('status' => 'disabled', 'message' => 'API disabled');
        }
        
        $url = $this->config['api_url'] . '?' . http_build_query(array(
            'action'  => 'unblock',
            'ip'      => $ip,
            'api_key' => $this->config['api_key'],
            'api'     => '1',
        ));
        
        $ch = curl_init($url);
        curl_setopt_array($ch, array(
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => $this->config['api_timeout'],
            CURLOPT_CONNECTTIMEOUT => $this->config['api_timeout'],
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_USERAGENT      => $this->config['api_user_agent'],
            CURLOPT_HTTPHEADER     => array(
                'Accept: application/json',
                'Cache-Control: no-cache',
            ),
        ));
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);
        
        if ($curlError) {
            return array('status' => 'error', 'message' => 'CURL: ' . $curlError);
        }
        
        if ($httpCode !== 200) {
            return array('status' => 'error', 'message' => 'HTTP ' . $httpCode);
        }
        
        $data = json_decode($response, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            return array('status' => 'error', 'message' => 'Invalid JSON');
        }
        
        // Перевірка відповіді
        if (isset($data['status'])) {
            if ($data['status'] === 'success') {
                return array('status' => 'success', 'data' => $data);
            }
            // "not blocked" - це нормально, IP вже розблоковано
            $msg = isset($data['message']) ? $data['message'] : '';
            if (stripos($msg, 'not blocked') !== false || stripos($msg, 'не заблокирован') !== false) {
                return array('status' => 'not_blocked', 'message' => $msg);
            }
        }
        
        return array('status' => 'success', 'data' => $data);
    }
    
    /**
     * 1. Очистка блокувань з малим TTL + API розблокування
     */
    private function cleanExpiredBlocks() {
        $this->output("\n========================================\n");
        $this->output("1. CLEANING EXPIRED BLOCKS\n");
        $this->output("   TTL threshold: < " . $this->config['ttl_threshold'] . " sec\n");
        $this->output("   API: " . ($this->config['api_enabled'] ? 'ENABLED' : 'DISABLED') . "\n");
        $this->output("========================================\n");
        
        $prefix = $this->config['redis_prefix'];
        $patterns = array(
            $prefix . 'blocked:*',
            $prefix . 'ua_rotation_blocked:*',
        );
        
        foreach ($patterns as $pattern) {
            $this->output("\nScanning: " . $pattern . "\n");
            
            $keys = $this->redis->keys($pattern);
            if (!is_array($keys) || empty($keys)) {
                $this->output("  No keys found\n");
                continue;
            }
            
            $this->output("  Found: " . count($keys) . " keys\n\n");
            
            foreach ($keys as $key) {
                $this->stats['blocks_checked']++;
                
                $ttl = $this->redis->ttl($key);
                
                // Пропускаємо якщо TTL більший за поріг
                if ($ttl > $this->config['ttl_threshold']) {
                    continue;
                }
                
                $this->stats['blocks_expired']++;
                
                // Отримуємо дані про блокування
                $data = $this->redis->get($key);
                $ip = null;
                
                if (is_array($data) && isset($data['ip'])) {
                    $ip = $data['ip'];
                } else {
                    $ip = $this->extractIP($key);
                }
                
                $this->output("  → " . str_pad($ip, 15) . " TTL: " . str_pad($ttl . "s", 6));
                
                // Виклик API для розблокування
                if ($this->config['api_enabled'] && $ip && filter_var($ip, FILTER_VALIDATE_IP)) {
                    $apiResult = $this->unblockViaAPI($ip);
                    
                    if ($apiResult['status'] === 'success') {
                        $this->output(" [API:OK]");
                        $this->stats['blocks_api_success']++;
                    } elseif ($apiResult['status'] === 'not_blocked') {
                        $this->output(" [API:SKIP]");
                        $this->stats['blocks_api_skipped']++;
                    } elseif ($apiResult['status'] === 'disabled') {
                        $this->stats['blocks_api_skipped']++;
                    } else {
                        $this->output(" [API:FAIL]");
                        $this->stats['blocks_api_failed']++;
                        $this->stats['api_errors'][] = $ip . ': ' . $apiResult['message'];
                    }
                    
                    // Затримка між API викликами
                    usleep($this->config['api_delay_ms'] * 1000);
                }
                
                // Видаляємо з Redis
                $this->redis->del($key);
                $this->stats['blocks_unblocked']++;
                
                $this->output(" [DELETED]\n");
            }
        }
        
        $this->output("\n  Summary: checked=" . $this->stats['blocks_checked']);
        $this->output(", expired=" . $this->stats['blocks_expired']);
        $this->output(", unblocked=" . $this->stats['blocks_unblocked']);
        if ($this->config['api_enabled']) {
            $this->output(", api_ok=" . $this->stats['blocks_api_success']);
            $this->output(", api_fail=" . $this->stats['blocks_api_failed']);
        }
        $this->output("\n");
    }
    
    /**
     * 2. Очистка rate limit записів
     */
    private function cleanRateLimitRecords() {
        $this->output("\n========================================\n");
        $this->output("2. CLEANING RATE LIMIT RECORDS\n");
        $this->output("========================================\n");
        
        $prefix = $this->config['redis_prefix'];
        $pattern = $prefix . 'rate:*';
        
        $keys = $this->redis->keys($pattern);
        if (!is_array($keys) || empty($keys)) {
            $this->output("  No rate limit keys found\n");
            return;
        }
        
        $this->output("  Found: " . count($keys) . " keys\n");
        
        foreach ($keys as $key) {
            $ttl = $this->redis->ttl($key);
            
            // Видаляємо якщо немає TTL або TTL занадто малий
            if ($ttl === -1 || $ttl < 60) {
                $this->redis->del($key);
                $this->stats['rate_cleaned']++;
            }
        }
        
        $this->output("  Cleaned: " . $this->stats['rate_cleaned'] . " records\n");
    }
    
    /**
     * 3. Очистка rDNS кешу
     */
    private function cleanRDNSCache() {
        $this->output("\n========================================\n");
        $this->output("3. CLEANING rDNS CACHE\n");
        $this->output("========================================\n");
        
        $patterns = array(
            $this->config['redis_prefix'] . $this->config['rdns_prefix'] . '*',
            'admin:rdns:*',
        );
        
        foreach ($patterns as $pattern) {
            $keys = $this->redis->keys($pattern);
            if (!is_array($keys)) {
                continue;
            }
            
            foreach ($keys as $key) {
                $ttl = $this->redis->ttl($key);
                
                if ($ttl === -1 || $ttl < 300) {
                    $this->redis->del($key);
                    $this->stats['rdns_cleaned']++;
                }
            }
        }
        
        $this->output("  Cleaned: " . $this->stats['rdns_cleaned'] . " cache entries\n");
    }
    
    /**
     * 4. Очистка UA tracking записів
     */
    private function cleanUATracking() {
        $this->output("\n========================================\n");
        $this->output("4. CLEANING UA TRACKING\n");
        $this->output("========================================\n");
        
        $prefix = $this->config['redis_prefix'];
        $patterns = array(
            $prefix . 'ua_rotation_5min:*',
            $prefix . 'ua_rotation_hour:*',
            $prefix . 'ua_tracking:*',
        );
        
        foreach ($patterns as $pattern) {
            $keys = $this->redis->keys($pattern);
            if (!is_array($keys)) {
                continue;
            }
            
            foreach ($keys as $key) {
                $ttl = $this->redis->ttl($key);
                
                if ($ttl === -1 || $ttl < 60) {
                    $this->redis->del($key);
                    $this->stats['ua_tracking_cleaned']++;
                }
            }
        }
        
        $this->output("  Cleaned: " . $this->stats['ua_tracking_cleaned'] . " records\n");
    }
    
    /**
     * 5. Очистка tracking записів
     */
    private function cleanTrackingRecords() {
        $this->output("\n========================================\n");
        $this->output("5. CLEANING TRACKING RECORDS\n");
        $this->output("========================================\n");
        
        $prefix = $this->config['redis_prefix'];
        $patterns = array(
            $prefix . 'tracking:*',
            $prefix . 'ip_tracking:*',
        );
        
        foreach ($patterns as $pattern) {
            $keys = $this->redis->keys($pattern);
            if (!is_array($keys)) {
                continue;
            }
            
            foreach ($keys as $key) {
                $ttl = $this->redis->ttl($key);
                
                if ($ttl === -1) {
                    $this->redis->del($key);
                    $this->stats['tracking_cleaned']++;
                }
            }
        }
        
        $this->output("  Cleaned: " . $this->stats['tracking_cleaned'] . " records\n");
    }
    
    /**
     * 6. Оновлення глобальної статистики
     */
    private function updateGlobalStats() {
        $this->output("\n========================================\n");
        $this->output("6. CURRENT STATUS\n");
        $this->output("========================================\n");
        
        $prefix = $this->config['redis_prefix'];
        
        $rateKeys = $this->redis->keys($prefix . 'rate:*');
        $blockedKeys = $this->redis->keys($prefix . 'blocked:*');
        $uaBlockedKeys = $this->redis->keys($prefix . 'ua_rotation_blocked:*');
        $rdnsKeys = $this->redis->keys($this->config['redis_prefix'] . $this->config['rdns_prefix'] . '*');
        
        $totalBlocked = (is_array($blockedKeys) ? count($blockedKeys) : 0) +
                        (is_array($uaBlockedKeys) ? count($uaBlockedKeys) : 0);
        
        $this->output("  Active sessions:    " . (is_array($rateKeys) ? count($rateKeys) : 0) . "\n");
        $this->output("  Blocked IPs:        " . $totalBlocked . "\n");
        $this->output("    - Rate limit:     " . (is_array($blockedKeys) ? count($blockedKeys) : 0) . "\n");
        $this->output("    - UA rotation:    " . (is_array($uaBlockedKeys) ? count($uaBlockedKeys) : 0) . "\n");
        $this->output("  rDNS cache:         " . (is_array($rdnsKeys) ? count($rdnsKeys) : 0) . "\n");
        
        // Зберігаємо статистику очистки
        $stats = array(
            'last_cleanup'    => time(),
            'cleanup_stats'   => $this->stats,
            'total_blocked'   => $totalBlocked,
            'total_tracked'   => is_array($rateKeys) ? count($rateKeys) : 0,
        );
        
        $this->redis->set($prefix . 'cleanup:stats', $stats);
    }
    
    /**
     * Допоміжна функція для вилучення IP з ключа
     */
    private function extractIP($key) {
        // Спробуємо знайти IPv4
        if (preg_match('/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/', $key, $matches)) {
            return $matches[1];
        }
        // Спробуємо знайти IPv6
        if (preg_match('/([a-fA-F0-9:]+)/', $key, $matches)) {
            if (filter_var($matches[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                return $matches[1];
            }
        }
        return null;
    }
    
    /**
     * Запуск повної очистки
     */
    public function run() {
        $this->cleanExpiredBlocks();
        $this->cleanRateLimitRecords();
        $this->cleanRDNSCache();
        $this->cleanUATracking();
        $this->cleanTrackingRecords();
        $this->updateGlobalStats();
        $this->printSummary();
    }
    
    /**
     * Примусове розблокування конкретного IP
     */
    public function forceUnblock($ip) {
        $this->output("\n========================================\n");
        $this->output("FORCE UNBLOCK: " . $ip . "\n");
        $this->output("========================================\n");
        
        $prefix = $this->config['redis_prefix'];
        $deleted = 0;
        
        // Шукаємо всі можливі ключі для цього IP
        $patterns = array(
            $prefix . 'blocked:*' . $ip . '*',
            $prefix . 'blocked:' . md5('ip:' . $ip),
            $prefix . 'blocked:' . md5('user:' . $ip . '*'),
            $prefix . 'ua_rotation_blocked:' . $ip,
            $prefix . 'rate:*' . $ip . '*',
        );
        
        foreach ($patterns as $pattern) {
            if (strpos($pattern, '*') !== false) {
                $keys = $this->redis->keys($pattern);
                if (is_array($keys)) {
                    foreach ($keys as $key) {
                        $this->redis->del($key);
                        $deleted++;
                        $this->output("  Deleted: " . $key . "\n");
                    }
                }
            } else {
                if ($this->redis->exists($pattern)) {
                    $this->redis->del($pattern);
                    $deleted++;
                    $this->output("  Deleted: " . $pattern . "\n");
                }
            }
        }
        
        // Виклик API
        if ($this->config['api_enabled']) {
            $this->output("\n  Calling API...\n");
            $apiResult = $this->unblockViaAPI($ip);
            if ($apiResult['status'] === 'success') {
                $this->output("  API unblock: SUCCESS ✓\n");
            } elseif ($apiResult['status'] === 'not_blocked') {
                $this->output("  API unblock: Already unblocked ✓\n");
            } else {
                $msg = isset($apiResult['message']) ? $apiResult['message'] : 'FAILED';
                $this->output("  API unblock: " . $msg . " ✗\n");
            }
        }
        
        $this->output("\n  Total deleted from Redis: " . $deleted . " keys\n");
        
        return $deleted;
    }
    
    /**
     * Виведення підсумкової статистики
     */
    private function printSummary() {
        $duration = microtime(true) - $this->startTime;
        
        $this->output("\n");
        $this->output("========================================\n");
        $this->output("         CLEANUP SUMMARY                \n");
        $this->output("========================================\n");
        $this->output(" Blocks checked:     " . $this->stats['blocks_checked'] . "\n");
        $this->output(" Blocks expired:     " . $this->stats['blocks_expired'] . "\n");
        $this->output(" Blocks unblocked:   " . $this->stats['blocks_unblocked'] . "\n");
        
        if ($this->config['api_enabled']) {
            $this->output("----------------------------------------\n");
            $this->output(" API successful:     " . $this->stats['blocks_api_success'] . "\n");
            $this->output(" API failed:         " . $this->stats['blocks_api_failed'] . "\n");
            $this->output(" API skipped:        " . $this->stats['blocks_api_skipped'] . "\n");
        }
        
        $this->output("----------------------------------------\n");
        $this->output(" Rate limit cleaned: " . $this->stats['rate_cleaned'] . "\n");
        $this->output(" rDNS cleaned:       " . $this->stats['rdns_cleaned'] . "\n");
        $this->output(" UA tracking cleaned:" . $this->stats['ua_tracking_cleaned'] . "\n");
        $this->output(" Tracking cleaned:   " . $this->stats['tracking_cleaned'] . "\n");
        $this->output("----------------------------------------\n");
        $this->output(" Duration:           " . number_format($duration, 2) . "s\n");
        $this->output("========================================\n");
        
        // Помилки API
        if (!empty($this->stats['api_errors'])) {
            $this->output("\nAPI ERRORS:\n");
            $errors = array_slice($this->stats['api_errors'], 0, 10);
            foreach ($errors as $error) {
                $this->output("  - " . $error . "\n");
            }
            $remaining = count($this->stats['api_errors']) - 10;
            if ($remaining > 0) {
                $this->output("  ... and " . $remaining . " more\n");
            }
        }
    }
    
    public function getStats() {
        return $this->stats;
    }
}

// ============================================================================
// API РЕЖИМ (JSON відповідь)
// ============================================================================

if ($isWeb && isset($_GET['action'])) {
    header('Content-Type: application/json; charset=utf-8');
    
    $action = isset($_GET['action']) ? $_GET['action'] : '';
    
    try {
        $cleanup = new MurKirCleanup($config, false);
        
        switch ($action) {
            case 'unblock':
                $ip = isset($_GET['ip']) ? $_GET['ip'] : '';
                if (!$ip || !filter_var($ip, FILTER_VALIDATE_IP)) {
                    echo json_encode(array('error' => 'Invalid IP address'));
                    exit;
                }
                ob_start();
                $deleted = $cleanup->forceUnblock($ip);
                ob_end_clean();
                echo json_encode(array(
                    'success' => true,
                    'ip' => $ip,
                    'deleted_keys' => $deleted,
                ));
                break;
                
            case 'stats':
                ob_start();
                $cleanup->run();
                ob_end_clean();
                echo json_encode(array(
                    'success' => true,
                    'stats' => $cleanup->getStats(),
                ));
                break;
                
            case 'run':
                ob_start();
                $cleanup->run();
                $output = ob_get_clean();
                echo json_encode(array(
                    'success' => true,
                    'stats' => $cleanup->getStats(),
                    'output' => $output,
                ));
                break;
                
            default:
                echo json_encode(array('error' => 'Unknown action. Use: unblock, stats, run'));
        }
        
    } catch (Exception $e) {
        echo json_encode(array('error' => $e->getMessage()));
    }
    
    exit;
}

// ============================================================================
// ОСНОВНИЙ РЕЖИМ
// ============================================================================

try {
    echo "========================================\n";
    echo "  MurKir Security - Cleanup v1.1\n";
    echo "  PHP " . PHP_VERSION . " compatible\n";
    echo "========================================\n\n";
    
    echo "Started: " . date('Y-m-d H:i:s') . "\n";
    echo "Mode: " . ($isCLI ? "CLI" : "WEB") . "\n";
    
    echo "\nConfiguration:\n";
    echo "  Redis: " . $config['redis_host'] . ":" . $config['redis_port'];
    echo " (db: " . $config['redis_database'] . ")\n";
    echo "  Prefix: " . $config['redis_prefix'] . "\n";
    echo "  API: " . ($config['api_enabled'] ? $config['api_url'] : 'Disabled') . "\n";
    echo "  TTL threshold: " . $config['ttl_threshold'] . " sec\n";
    
    // Перевірка на примусове розблокування IP (CLI)
    if ($isCLI && isset($argv[1])) {
        $ip = $argv[1];
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            $cleanup = new MurKirCleanup($config, false);
            $cleanup->forceUnblock($ip);
            exit(0);
        } else {
            echo "\nError: Invalid IP address: " . $ip . "\n";
            exit(1);
        }
    }
    
    // Запуск повної очистки
    $cleanup = new MurKirCleanup($config, $isWeb);
    $cleanup->run();
    
    echo "\nCompleted: " . date('Y-m-d H:i:s') . "\n";
    
    if ($isWeb) {
        echo "\n========================================\n";
        echo "API ENDPOINTS:\n";
        echo "========================================\n";
        echo "Force unblock IP:\n";
        echo "  ?action=unblock&ip=1.2.3.4\n\n";
        echo "Run cleanup (JSON):\n";
        echo "  ?action=run\n\n";
        echo "Get stats (JSON):\n";
        echo "  ?action=stats\n\n";
        echo "CRON setup:\n";
        echo "*/5 * * * * php " . __FILE__ . " >> /var/log/cleanup.log 2>&1\n";
    }
    
    exit(0);
    
} catch (Exception $e) {
    echo "\nERROR: " . $e->getMessage() . "\n";
    exit(1);
}