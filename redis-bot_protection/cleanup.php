<?php

// ============================================================================
// ВИПРАВЛЕНИЙ CLEANUP - РОЗБЛОКОВУЄ ВСІ IP ЧЕРЕЗ API
// ============================================================================
// Версія: 1.5 (КРИТИЧНЕ ВИПРАВЛЕННЯ)
// Дата: 2025-12-11
// Зміни v1.5:
//   - ВИПРАВЛЕНО: Тепер API розблокування викликається для ВСІХ IP
//   - Видалено перевірку $wasApiAttempted яка пропускала IP з api_blocked=false
//   - Спрощена логіка: якщо це IP і useAPI=true → завжди викликати API
// ============================================================================

// ============================================================================
// НАСТРОЙКИ - ИЗМЕНИТЕ НА СВОИ!
// ============================================================================

// Redis настройки
define('REDIS_HOST', '127.0.0.1');
define('REDIS_PORT', 6379);
define('REDIS_PASSWORD', null);  // или ваш пароль
define('REDIS_DATABASE', 0);
define('REDIS_PREFIX', 'bot_protection:');

// API настройки (должны совпадать с inline_check.php)
define('API_ENABLED', true);
define('API_URL', 'https://midomain.com/redis-bot_protection/API/iptables.php');
define('API_KEY', '12345');  // Ваш API ключ
define('API_TIMEOUT', 5);
define('API_USER_AGENT', 'uptimerobot');  // User-Agent для API запросов

// Настройки очистки
define('TTL_THRESHOLD', 300);  // Разблокировать если TTL < 5 минут (300 сек)
define('BATCH_SIZE', 100);     // Обрабатывать по 100 ключей за раз
define('API_DELAY_MS', 100);   // Задержка между API запросами (100ms)

// Настройки для тяжелых операций (ОБНОВЛЕНО для v2.5.0)
define('CLEANUP_THRESHOLD', 5000);           // Порог для запуска очистки
define('CLEANUP_BATCH_SIZE', 100);           // Размер батча для очистки
define('MAX_CLEANUP_TIME_MS', 200);          // Максимальное время на очистку
define('TRACKING_TTL', 5400);                // TTL для tracking записей (1.5 часа - v2.5)
define('EXTENDED_TRACKING_TTL', 21600);      // TTL для extended tracking (6 часов - v2.5)
define('LOGS_TTL', 86400);                   // TTL для логов (1 день - v2.5)
define('RDNS_CACHE_TTL', 1800);              // TTL для rDNS кеша (30 минут)
define('SLOW_BOT_THRESHOLD_HOURS', 2);       // Порог для медленных ботов (v2.5: 2 часа)
define('SLOW_BOT_MIN_REQUESTS', 10);         // Минимум запросов для анализа (v2.5: 10)
define('VIOLATIONS_TTL', 3600);              // TTL для violations (1 час)

// Защита от несанкционированного доступа через браузер (опционально)
// Раскомментируйте если хотите защитить скрипт паролем при запуске через браузер
// define('WEB_ACCESS_KEY', 'your_secret_key_here');

// ============================================================================
// ОПРЕДЕЛЕНИЕ РЕЖИМА ЗАПУСКА
// ============================================================================

$isCLI = (php_sapi_name() === 'cli');
$isWeb = !$isCLI;

// Если запуск через браузер и установлен ключ доступа - проверяем его
if ($isWeb && defined('WEB_ACCESS_KEY')) {
    $providedKey = $_GET['key'] ?? '';
    if ($providedKey !== WEB_ACCESS_KEY) {
        http_response_code(403);
        die("Access denied. Provide correct key parameter.");
    }
}

// Установка заголовков для веб-режима
if ($isWeb) {
    header('Content-Type: text/plain; charset=utf-8');
    @ini_set('output_buffering', 'off');
    @ini_set('implicit_flush', 'on');
    @ini_set('zlib.output_compression', 0);
    if (function_exists('apache_setenv')) {
        @apache_setenv('no-gzip', 1);
    }
    if (ob_get_level()) {
        ob_end_flush();
    }
}

// ============================================================================
// РАСШИРЕННЫЙ КЛАСС ОЧИСТКИ
// ============================================================================

class AdvancedCleanup {
    private $redis;
    private $stats = array(
        'checked' => 0,
        'expired' => 0,
        'unblocked_success' => 0,
        'unblocked_failed' => 0,
        'unblocked_was_api_blocked' => 0,
        'unblocked_not_api_blocked' => 0, // НОВОЕ v1.5
        'unblocked_had_api_error' => 0,
        'unblocked_no_api_field' => 0,
        'api_errors' => array(),
        'tracking_cleaned' => 0,
        'rdns_cleaned' => 0,
        'slow_bots_cleaned' => 0,
        'logs_cleaned' => 0,
        'global_metrics_updated' => 0,
        'rate_limit_cleaned' => 0,
        'extended_tracking_cleaned' => 0,
        'whitelist_cleaned' => 0,
        'block_history_cleaned' => 0,
        'api_call_records_cleaned' => 0,
        'violations_cleaned' => 0,
        'global_rate_limit_cleaned' => 0,
        'burst_cleaned' => 0
    );
    private $isWeb;
    private $startTime;
    
    public function __construct($isWeb = false) {
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
            
            if (!$this->redis->connect(REDIS_HOST, REDIS_PORT, 2)) {
                throw new Exception("Cannot connect to Redis");
            }
            
            if (REDIS_PASSWORD) {
                $this->redis->auth(REDIS_PASSWORD);
            }
            
            $this->redis->select(REDIS_DATABASE);
            $this->redis->setOption(Redis::OPT_SERIALIZER, Redis::SERIALIZER_JSON);
            
            $this->output("✓ Connected to Redis\n");
            
        } catch (Exception $e) {
            $this->output("✗ Redis connection failed: " . $e->getMessage() . "\n");
            throw $e;
        }
    }
    
    /**
     * Вызов API для разблокировки IP
     */
    private function unblockViaAPI($ip) {
        if (!API_ENABLED) {
            return array('status' => 'disabled', 'message' => 'API disabled');
        }
        
        $params = array(
            'action' => 'unblock',
            'ip' => $ip,
            'api' => '1',
            'api_key' => API_KEY
        );
        
        $url = API_URL . '?' . http_build_query($params);
        
        $ch = curl_init($url);
        curl_setopt_array($ch, array(
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => API_TIMEOUT,
            CURLOPT_CONNECTTIMEOUT => API_TIMEOUT,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_USERAGENT => API_USER_AGENT,
            CURLOPT_HTTPHEADER => array(
                'Accept: application/json',
                'Cache-Control: no-cache'
            )
        ));
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);
        
        if ($curlError) {
            return array('status' => 'error', 'message' => "CURL error: $curlError");
        }
        
        if ($httpCode !== 200) {
            return array('status' => 'error', 'message' => "HTTP $httpCode");
        }
        
        $data = json_decode($response, true);
        
        if (!$data) {
            return array('status' => 'error', 'message' => 'Invalid JSON response');
        }
        
        if (isset($data['status'])) {
            if ($data['status'] === 'success') {
                return array('status' => 'success', 'message' => 'Unblocked');
            }
            
            if ($data['status'] === 'error' && 
                isset($data['message']) && 
                stripos($data['message'], 'not blocked') !== false) {
                return array('status' => 'not_blocked', 'message' => 'Not blocked');
            }
            
            if (isset($data['message'])) {
                return array('status' => 'error', 'message' => $data['message']);
            }
        }
        
        return array('status' => 'success', 'message' => 'Unblocked');
    }
    
    /**
     * ГЛАВНЫЙ МЕТОД - Запускает все операции очистки
     */
    public function runFullCleanup() {
        $this->output("\n╔════════════════════════════════════════════════════════════════╗\n");
        $this->output("║           FULL CLEANUP - ALL OPERATIONS (v1.5)                 ║\n");
        $this->output("║              КРИТИЧНЕ ВИПРАВЛЕННЯ: API для всіх IP             ║\n");
        $this->output("╚════════════════════════════════════════════════════════════════╝\n\n");
        
        // 1. Очистка блокировок с истекшим TTL
        $this->cleanupExpiredBlocks();
        
        // 2. Очистка старых tracking записей
        $this->cleanupTracking();
        
        // 3. Очистка rDNS кеша
        $this->cleanupRDNSCache();
        
        // 4. Очистка медленных ботов
        $this->cleanupSlowBots();
        
        // 5. Очистка старых логов
        $this->cleanupLogs();
        
        // 6. Очистка rate limit ключей
        $this->cleanupRateLimitKeys();
        
        // 7. Очистка extended tracking
        $this->cleanupExtendedTracking();
        
        // 8. Очистка whitelist и block history
        $this->cleanupMiscKeys();
        
        // 9. Очистка violations
        $this->cleanupViolations();
        
        // 10. Очистка global rate limit
        $this->cleanupGlobalRateLimit();
        
        // 11. Обновление глобальных метрик
        $this->updateGlobalMetrics();
        
        // 12. Проверка и очистка при превышении лимитов
        $this->checkAndCleanupIfNeeded();
        
        $this->printStats();
    }
    
    /**
     * 1. ОЧИСТКА БЛОКИРОВОК С ИСТЕКШИМ TTL (ВИПРАВЛЕНА ВЕРСІЯ v1.5)
     */
    private function cleanupExpiredBlocks() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("1. CLEANING EXPIRED BLOCKS (v1.5 - FIXED API LOGIC)\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
        
        $blockTypes = array(
            'ip' => array(
                'pattern' => REDIS_PREFIX . 'blocked:ip:*',
                'description' => 'Blocked IPs',
                'api_unblock' => true
            ),
            'user_hash' => array(
                'pattern' => REDIS_PREFIX . 'user_hash:blocked:*',
                'description' => 'Blocked Hashes',
                'api_unblock' => false
            ),
            'cookie' => array(
                'pattern' => REDIS_PREFIX . 'cookie:blocked:*',
                'description' => 'Blocked Cookies',
                'api_unblock' => false
            )
        );
        
        foreach ($blockTypes as $type => $config) {
            $this->output("\n→ {$config['description']}\n");
            $this->cleanupPattern($config['pattern'], $config['api_unblock'], $type);
        }
    }
    
    /**
     * Очистка блокировок по паттерну (ВИПРАВЛЕНА v1.5)
     * КРИТИЧНА ЗМІНА: Тепер API викликається для ВСІХ IP, незалежно від api_blocked
     */
    private function cleanupPattern($pattern, $useAPI, $type) {
        $iterator = null;
        $foundInThisPattern = 0;
        
        do {
            $keys = $this->redis->scan($iterator, $pattern, BATCH_SIZE);
            
            if ($keys === false) {
                break;
            }
            
            foreach ($keys as $key) {
                $this->stats['checked']++;
                $foundInThisPattern++;
                
                $ttl = $this->redis->ttl($key);
                
                if ($ttl === -2) {
                    continue;
                }
                
                $shouldCleanup = false;
                
                if ($ttl === -1) {
                    $this->output("  ⚠ Found key without TTL: " . basename($key) . "\n");
                    $shouldCleanup = true;
                } elseif ($ttl <= TTL_THRESHOLD) {
                    $shouldCleanup = true;
                }
                
                if ($shouldCleanup) {
                    $this->stats['expired']++;
                    $blockData = $this->redis->get($key);
                    
                    if (!$blockData) {
                        $this->redis->del($key);
                        continue;
                    }
                    
                    $identifier = $this->getIdentifier($blockData);
                    $ttlDisplay = ($ttl === -1) ? "NO TTL" : "{$ttl}s";
                    
                    // Збір статистики про тип блокування
                    $wasApiBlocked = isset($blockData['api_blocked']) && $blockData['api_blocked'];
                    $hasNoApiField = !isset($blockData['api_blocked']);
                    $wasNotApiBlocked = isset($blockData['api_blocked']) && !$blockData['api_blocked'];
                    
                    // ═══════════════════════════════════════════════════════════
                    // КРИТИЧНА ЗМІНА v1.5: Спрощена логіка
                    // Якщо це IP і useAPI=true → ЗАВЖДИ викликати API
                    // ═══════════════════════════════════════════════════════════
                    if ($useAPI && isset($blockData['ip'])) {
                        $ip = $blockData['ip'];
                        
                        // Показуємо детальну інформацію про стан блокування
                        $apiStatusInfo = '';
                        if ($wasApiBlocked) {
                            $apiStatusInfo = ' [was API blocked]';
                        } elseif ($wasNotApiBlocked) {
                            $apiStatusInfo = ' [was NOT API blocked - WILL UNBLOCK NOW]';
                        } elseif ($hasNoApiField) {
                            $apiStatusInfo = ' [no api_blocked field]';
                        }
                        
                        $this->output("  Unblocking IP: $ip (TTL: {$ttlDisplay}){$apiStatusInfo}... ");
                        
                        $result = $this->unblockViaAPI($ip);
                        
                        if ($result['status'] === 'success' || $result['status'] === 'not_blocked') {
                            $this->stats['unblocked_success']++;
                            
                            // Статистика по типу блокування
                            if ($wasApiBlocked) {
                                $this->stats['unblocked_was_api_blocked']++;
                            } elseif ($wasNotApiBlocked) {
                                $this->stats['unblocked_not_api_blocked']++; // НОВИЙ ЛІЧИЛЬНИК
                            } elseif ($hasNoApiField) {
                                $this->stats['unblocked_no_api_field']++;
                            }
                            
                            $this->output("✓\n");
                            $this->redis->del($key);
                        } else {
                            $this->stats['unblocked_failed']++;
                            $message = isset($result['message']) ? $result['message'] : 'unknown';
                            $this->stats['api_errors'][] = "$ip: $message";
                            $this->output("✗ $message\n");
                        }
                        
                        usleep(API_DELAY_MS * 1000);
                    } else {
                        // Для non-IP типів просто видаляємо
                        $this->output("  Removing: $identifier (TTL: {$ttlDisplay})\n");
                        $this->redis->del($key);
                    }
                }
            }
            
        } while ($iterator > 0);
        
        if ($foundInThisPattern === 0) {
            $this->output("  No keys found\n");
        } else {
            $this->output("  Processed: $foundInThisPattern keys\n");
        }
    }
    
    private function getIdentifier($blockData) {
        if (isset($blockData['ip'])) {
            return $blockData['ip'];
        } elseif (isset($blockData['user_hash'])) {
            return substr($blockData['user_hash'], 0, 16) . '...';
        } elseif (isset($blockData['cookie_hash'])) {
            return 'cookie:' . substr($blockData['cookie_hash'], 0, 12);
        }
        return 'unknown';
    }
    
    /**
     * 2. ОЧИСТКА СТАРЫХ TRACKING ЗАПИСЕЙ
     */
    private function cleanupTracking() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("2. CLEANING OLD TRACKING RECORDS\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
        
        $patterns = array(
            REDIS_PREFIX . 'tracking:ip:*',
            REDIS_PREFIX . 'tracking:requests:*',
            REDIS_PREFIX . 'user_hash:tracking:*'
        );
        
        $currentTime = time();
        $cleaned = 0;
        
        foreach ($patterns as $pattern) {
            $this->output("\n→ Pattern: " . basename($pattern) . "\n");
            $iterator = null;
            
            do {
                $keys = $this->redis->scan($iterator, $pattern, CLEANUP_BATCH_SIZE);
                
                if ($keys === false) {
                    break;
                }
                
                foreach ($keys as $key) {
                    $ttl = $this->redis->ttl($key);
                    
                    if ($ttl === -2) {
                        continue;
                    }
                    
                    if ($ttl === -1) {
                        $data = $this->redis->get($key);
                        
                        if ($data && isset($data['last_seen'])) {
                            if ($data['last_seen'] < ($currentTime - TRACKING_TTL)) {
                                $this->redis->del($key);
                                $cleaned++;
                            }
                        } elseif ($data && isset($data['first_seen'])) {
                            if ($data['first_seen'] < ($currentTime - TRACKING_TTL)) {
                                $this->redis->del($key);
                                $cleaned++;
                            }
                        } else {
                            $this->redis->del($key);
                            $cleaned++;
                        }
                    }
                }
                
            } while ($iterator > 0);
        }
        
        $this->stats['tracking_cleaned'] = $cleaned;
        $this->output("  Cleaned: $cleaned records\n");
    }
    
    /**
     * 3. ОЧИСТКА RDNS КЕША
     */
    private function cleanupRDNSCache() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("3. CLEANING RDNS CACHE\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
        
        $patterns = array(
            REDIS_PREFIX . 'rdns:cache:*',
            REDIS_PREFIX . 'rdns:ratelimit:*'
        );
        
        $cleaned = 0;
        $currentTime = time();
        
        foreach ($patterns as $pattern) {
            $iterator = null;
            
            do {
                $keys = $this->redis->scan($iterator, $pattern, CLEANUP_BATCH_SIZE);
                
                if ($keys === false) {
                    break;
                }
                
                foreach ($keys as $key) {
                    $ttl = $this->redis->ttl($key);
                    
                    if ($ttl === -2) {
                        continue;
                    }
                    
                    if ($ttl === -1) {
                        $this->redis->del($key);
                        $cleaned++;
                    }
                }
                
            } while ($iterator > 0);
        }
        
        $this->stats['rdns_cleaned'] = $cleaned;
        $this->output("  Cleaned: $cleaned entries\n");
    }
    
    /**
     * 4. ОЧИСТКА МЕДЛЕННЫХ БОТОВ
     */
    private function cleanupSlowBots() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("4. CLEANING SLOW BOTS\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
        
        $pattern = REDIS_PREFIX . 'tracking:ip:*';
        $iterator = null;
        $cleaned = 0;
        $currentTime = time();
        $thresholdTime = $currentTime - (SLOW_BOT_THRESHOLD_HOURS * 3600);
        
        do {
            $keys = $this->redis->scan($iterator, $pattern, CLEANUP_BATCH_SIZE);
            
            if ($keys === false) {
                break;
            }
            
            foreach ($keys as $key) {
                $data = $this->redis->get($key);
                
                if (!$data) {
                    continue;
                }
                
                $firstSeen = $data['first_seen'] ?? null;
                $lastSeen = $data['last_seen'] ?? null;
                $requestCount = $data['request_count'] ?? 0;
                
                if (!$firstSeen || !$lastSeen) {
                    continue;
                }
                
                if ($lastSeen < $thresholdTime && $requestCount < SLOW_BOT_MIN_REQUESTS) {
                    $this->redis->del($key);
                    $cleaned++;
                }
            }
            
        } while ($iterator > 0);
        
        $this->stats['slow_bots_cleaned'] = $cleaned;
        $this->output("  Cleaned: $cleaned slow bot records\n");
    }
    
    /**
     * 5. ОЧИСТКА СТАРЫХ ЛОГОВ
     */
    private function cleanupLogs() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("5. CLEANING OLD LOGS\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
        
        $pattern = REDIS_PREFIX . 'logs:*';
        $iterator = null;
        $cleaned = 0;
        $currentTime = time();
        
        do {
            $keys = $this->redis->scan($iterator, $pattern, CLEANUP_BATCH_SIZE);
            
            if ($keys === false) {
                break;
            }
            
            foreach ($keys as $key) {
                $ttl = $this->redis->ttl($key);
                
                if ($ttl === -2) {
                    continue;
                }
                
                if ($ttl === -1 || $ttl > LOGS_TTL) {
                    $this->redis->expire($key, LOGS_TTL);
                }
            }
            
        } while ($iterator > 0);
        
        $this->stats['logs_cleaned'] = $cleaned;
        $this->output("  Processed log entries\n");
    }
    
    /**
     * 6. ОЧИСТКА RATE LIMIT КЛЮЧЕЙ
     */
    private function cleanupRateLimitKeys() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("6. CLEANING RATE LIMIT KEYS\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
        
        $patterns = array(
            REDIS_PREFIX . 'tracking:rl:*',
            REDIS_PREFIX . 'tracking:burst:*'
        );
        
        $cleaned = 0;
        
        foreach ($patterns as $pattern) {
            $iterator = null;
            
            do {
                $keys = $this->redis->scan($iterator, $pattern, CLEANUP_BATCH_SIZE);
                
                if ($keys === false) {
                    break;
                }
                
                foreach ($keys as $key) {
                    $ttl = $this->redis->ttl($key);
                    
                    if ($ttl === -2) {
                        continue;
                    }
                    
                    if ($ttl === -1) {
                        $this->redis->del($key);
                        $cleaned++;
                    }
                }
                
            } while ($iterator > 0);
        }
        
        $this->stats['rate_limit_cleaned'] = $cleaned;
        $this->stats['burst_cleaned'] = $cleaned;
        $this->output("  Cleaned: $cleaned keys\n");
    }
    
    /**
     * 7. ОЧИСТКА EXTENDED TRACKING
     */
    private function cleanupExtendedTracking() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("7. CLEANING EXTENDED TRACKING\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
        
        $pattern = REDIS_PREFIX . 'tracking:extended:*';
        $iterator = null;
        $cleaned = 0;
        $currentTime = time();
        
        do {
            $keys = $this->redis->scan($iterator, $pattern, CLEANUP_BATCH_SIZE);
            
            if ($keys === false) {
                break;
            }
            
            foreach ($keys as $key) {
                $ttl = $this->redis->ttl($key);
                
                if ($ttl === -2) {
                    continue;
                }
                
                if ($ttl === -1) {
                    $data = $this->redis->get($key);
                    
                    if ($data && isset($data['last_seen'])) {
                        if ($data['last_seen'] < ($currentTime - EXTENDED_TRACKING_TTL)) {
                            $this->redis->del($key);
                            $cleaned++;
                        }
                    } else {
                        $this->redis->del($key);
                        $cleaned++;
                    }
                }
            }
            
        } while ($iterator > 0);
        
        $this->stats['extended_tracking_cleaned'] = $cleaned;
        $this->output("  Cleaned: $cleaned records\n");
    }
    
    /**
     * 8. ОЧИСТКА WHITELIST И BLOCK HISTORY
     */
    private function cleanupMiscKeys() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("8. CLEANING WHITELIST & BLOCK HISTORY\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
        
        $patterns = array(
            REDIS_PREFIX . 'rdns:whitelist:*',
            REDIS_PREFIX . 'blocked:history:*',
            REDIS_PREFIX . 'blocked:api_call:*'
        );
        
        $totalCleaned = 0;
        
        foreach ($patterns as $pattern) {
            $iterator = null;
            $cleaned = 0;
            
            do {
                $keys = $this->redis->scan($iterator, $pattern, CLEANUP_BATCH_SIZE);
                
                if ($keys === false) {
                    break;
                }
                
                foreach ($keys as $key) {
                    $ttl = $this->redis->ttl($key);
                    
                    if ($ttl === -2) {
                        continue;
                    }
                    
                    if ($ttl === -1) {
                        $this->redis->del($key);
                        $cleaned++;
                    }
                }
                
            } while ($iterator > 0);
            
            $totalCleaned += $cleaned;
        }
        
        $this->stats['whitelist_cleaned'] = $totalCleaned;
        $this->stats['block_history_cleaned'] = $totalCleaned;
        $this->stats['api_call_records_cleaned'] = $totalCleaned;
        $this->output("  Cleaned: $totalCleaned keys\n");
    }
    
    /**
     * 9. ОЧИСТКА VIOLATIONS (v1.4)
     */
    private function cleanupViolations() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("9. CLEANING VIOLATIONS\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
        
        $pattern = REDIS_PREFIX . 'tracking:violations:*';
        $iterator = null;
        $cleaned = 0;
        
        do {
            $keys = $this->redis->scan($iterator, $pattern, CLEANUP_BATCH_SIZE);
            
            if ($keys === false) {
                break;
            }
            
            foreach ($keys as $key) {
                $ttl = $this->redis->ttl($key);
                
                if ($ttl === -2) {
                    continue;
                }
                
                if ($ttl === -1 || $ttl > VIOLATIONS_TTL) {
                    $this->redis->expire($key, VIOLATIONS_TTL);
                    $cleaned++;
                }
            }
            
        } while ($iterator > 0);
        
        $this->stats['violations_cleaned'] = $cleaned;
        $this->output("  Cleaned: $cleaned violations\n");
    }
    
    /**
     * 10. ОЧИСТКА GLOBAL RATE LIMIT (v1.4)
     */
    private function cleanupGlobalRateLimit() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("10. CLEANING GLOBAL RATE LIMIT\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
        
        $pattern = REDIS_PREFIX . 'global:grl:*';
        $iterator = null;
        $cleaned = 0;
        
        do {
            $keys = $this->redis->scan($iterator, $pattern, CLEANUP_BATCH_SIZE);
            
            if ($keys === false) {
                break;
            }
            
            foreach ($keys as $key) {
                $ttl = $this->redis->ttl($key);
                
                if ($ttl === -2) {
                    continue;
                }
                
                if ($ttl === -1) {
                    $this->redis->del($key);
                    $cleaned++;
                }
            }
            
        } while ($iterator > 0);
        
        $this->stats['global_rate_limit_cleaned'] = $cleaned;
        $this->output("  Cleaned: $cleaned keys\n");
    }
    
    /**
     * 11. ОБНОВЛЕНИЕ ГЛОБАЛЬНЫХ МЕТРИК
     */
    private function updateGlobalMetrics() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("11. UPDATING GLOBAL METRICS\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
        
        $metrics = array(
            'tracked_ips' => 0,
            'blocked_ips' => 0,
            'blocked_hashes' => 0,
            'blocked_cookies' => 0,
            'rate_limit_keys' => 0,
            'burst_keys' => 0,
            'extended_tracking' => 0,
            'whitelist_entries' => 0
        );
        
        // Підрахунок різних типів ключів
        $patterns = array(
            'tracked_ips' => REDIS_PREFIX . 'tracking:ip:*',
            'blocked_ips' => REDIS_PREFIX . 'blocked:ip:*',
            'blocked_hashes' => REDIS_PREFIX . 'user_hash:blocked:*',
            'blocked_cookies' => REDIS_PREFIX . 'cookie:blocked:*',
            'rate_limit_keys' => REDIS_PREFIX . 'tracking:rl:*',
            'burst_keys' => REDIS_PREFIX . 'tracking:burst:*',
            'extended_tracking' => REDIS_PREFIX . 'tracking:extended:*',
            'whitelist_entries' => REDIS_PREFIX . 'rdns:whitelist:*'
        );
        
        foreach ($patterns as $key => $pattern) {
            $iterator = null;
            $count = 0;
            
            do {
                $keys = $this->redis->scan($iterator, $pattern, 1000);
                
                if ($keys === false) {
                    break;
                }
                
                $count += count($keys);
                
            } while ($iterator > 0);
            
            $metrics[$key] = $count;
        }
        
        $metricsKey = REDIS_PREFIX . 'global:metrics';
        $this->redis->set($metricsKey, $metrics);
        $this->redis->expire($metricsKey, 3600);
        
        $this->stats['global_metrics_updated'] = 1;
        
        $this->output("Updated metrics:\n");
        $this->output("  Tracked IPs: {$metrics['tracked_ips']}\n");
        $this->output("  Blocked IPs: {$metrics['blocked_ips']}\n");
        $this->output("  Blocked Hashes: {$metrics['blocked_hashes']}\n");
        $this->output("  Blocked Cookies: {$metrics['blocked_cookies']}\n");
        $this->output("  Rate Limit Keys: {$metrics['rate_limit_keys']}\n");
        $this->output("  Burst Keys: {$metrics['burst_keys']}\n");
        $this->output("  Extended Tracking: {$metrics['extended_tracking']}\n");
        $this->output("  Whitelist Entries: {$metrics['whitelist_entries']}\n");
    }
    
    /**
     * 12. ПРОВЕРКА И АГРЕССИВНАЯ ОЧИСТКА ПРИ ПРЕВЫШЕНИИ ЛИМИТОВ
     */
    private function checkAndCleanupIfNeeded() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("12. CHECKING THRESHOLDS\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
        
        $metrics = $this->redis->get(REDIS_PREFIX . 'global:metrics');
        
        if (!$metrics) {
            $this->output("No metrics available, skipping threshold check\n");
            return;
        }
        
        $trackedCount = isset($metrics['tracked_ips']) ? $metrics['tracked_ips'] : 0;
        
        $this->output("Current tracked IPs: $trackedCount / " . CLEANUP_THRESHOLD . "\n");
        
        if ($trackedCount > CLEANUP_THRESHOLD) {
            $this->output("⚠ THRESHOLD EXCEEDED! Running aggressive cleanup...\n");
            $this->performAggressiveCleanup();
        } else {
            $this->output("✓ Within limits\n");
        }
    }
    
    /**
     * АГРЕССИВНАЯ ОЧИСТКА
     */
    private function performAggressiveCleanup() {
        $cleaned = 0;
        $currentTime = time();
        
        $pattern = REDIS_PREFIX . 'tracking:ip:*';
        $iterator = null;
        $threshold = $currentTime - 3600;
        
        do {
            $keys = $this->redis->scan($iterator, $pattern, CLEANUP_BATCH_SIZE);
            
            if ($keys === false) {
                break;
            }
            
            foreach ($keys as $key) {
                $data = $this->redis->get($key);
                
                if ($data && isset($data['last_seen'])) {
                    if ($data['last_seen'] < $threshold) {
                        $this->redis->del($key);
                        $cleaned++;
                    }
                } elseif ($data && isset($data['first_seen'])) {
                    if ($data['first_seen'] < $threshold) {
                        $this->redis->del($key);
                        $cleaned++;
                    }
                }
            }
            
        } while ($iterator > 0 && $cleaned < CLEANUP_BATCH_SIZE * 5);
        
        $this->output("  Aggressively cleaned: $cleaned records\n");
    }
    
    /**
     * Вывод итоговой статистики
     */
    private function printStats() {
        $duration = microtime(true) - $this->startTime;
        
        $this->output("\n");
        $this->output("╔════════════════════════════════════════════════════════════════╗\n");
        $this->output("║           CLEANUP STATISTICS (v1.5 - FIXED)                    ║\n");
        $this->output("╚════════════════════════════════════════════════════════════════╝\n\n");
        
        $this->output("BLOCKS:\n");
        $this->output("  Checked blocks:           {$this->stats['checked']}\n");
        $this->output("  Expired blocks:           {$this->stats['expired']}\n");
        $this->output("  Successfully unblocked:   {$this->stats['unblocked_success']}\n");
        $this->output("    ├─ Was api_blocked=true:  {$this->stats['unblocked_was_api_blocked']}\n");
        $this->output("    ├─ Was api_blocked=false: {$this->stats['unblocked_not_api_blocked']} ⭐ FIXED!\n");
        $this->output("    ├─ Had api_error:         {$this->stats['unblocked_had_api_error']}\n");
        $this->output("    └─ No api_blocked field:  {$this->stats['unblocked_no_api_field']}\n");
        $this->output("  Failed to unblock:        {$this->stats['unblocked_failed']}\n\n");
        
        $this->output("TRACKING & CACHE:\n");
        $this->output("  Tracking cleaned:         {$this->stats['tracking_cleaned']}\n");
        $this->output("  rDNS cache cleaned:       {$this->stats['rdns_cleaned']}\n");
        $this->output("  Slow bots cleaned:        {$this->stats['slow_bots_cleaned']}\n");
        $this->output("  Logs cleaned:             {$this->stats['logs_cleaned']}\n\n");
        
        $this->output("RATE LIMIT & BURST:\n");
        $this->output("  Rate limit keys cleaned:  {$this->stats['rate_limit_cleaned']}\n");
        $this->output("  Burst keys cleaned:       {$this->stats['burst_cleaned']}\n");
        $this->output("  Extended tracking cleaned:{$this->stats['extended_tracking_cleaned']}\n");
        $this->output("  Whitelist cleaned:        {$this->stats['whitelist_cleaned']}\n");
        $this->output("  Block history cleaned:    {$this->stats['block_history_cleaned']}\n");
        $this->output("  API call records cleaned: {$this->stats['api_call_records_cleaned']}\n\n");
        
        $this->output("NEW IN v1.4:\n");
        $this->output("  Violations cleaned:       {$this->stats['violations_cleaned']}\n");
        $this->output("  Global rate limit cleaned:{$this->stats['global_rate_limit_cleaned']}\n\n");
        
        $this->output("METRICS:\n");
        $this->output("  Global metrics updated:   " . ($this->stats['global_metrics_updated'] ? 'Yes' : 'No') . "\n\n");
        
        $this->output("PERFORMANCE:\n");
        $this->output("  Total duration:           " . number_format($duration, 2) . "s\n");
        $this->output("  Average per operation:    " . number_format($duration / 12, 3) . "s\n\n");
        
        if (!empty($this->stats['api_errors'])) {
            $this->output("API ERRORS:\n");
            foreach ($this->stats['api_errors'] as $error) {
                $this->output("  - $error\n");
            }
            $this->output("\n");
        }
        
        $this->output("════════════════════════════════════════════════════════════════\n");
        $this->output("\n⭐ v1.5 CHANGES:\n");
        $this->output("  - Fixed: API unblock now called for ALL IPs\n");
        $this->output("  - Fixed: api_blocked=false IPs are now unblocked properly\n");
        $this->output("  - Added: New counter for api_blocked=false unblocks\n");
        $this->output("  - Simplified: Removed wasApiAttempted complex logic\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
    }
    
    public function getStats() {
        return $this->stats;
    }
}

// ============================================================================
// ГЛАВНАЯ ФУНКЦИЯ
// ============================================================================

try {
    $startTime = microtime(true);
    
    echo "╔══════════════════════════════════════════════════════════════╗\n";
    echo "║    ADVANCED CLEANUP v1.5 - CRITICAL FIX (API for all IPs)   ║\n";
    echo "║    Совместим с inline_check.php v2.5.0+                     ║\n";
    echo "╚══════════════════════════════════════════════════════════════╝\n";
    echo "Started: " . date('Y-m-d H:i:s') . "\n";
    echo "Mode: " . ($isCLI ? "CLI" : "WEB") . "\n";
    
    echo "\nSettings:\n";
    echo "  Redis: " . REDIS_HOST . ":" . REDIS_PORT . "\n";
    echo "  API: " . (API_ENABLED ? API_URL : 'Disabled') . "\n";
    echo "  API User-Agent: " . API_USER_AGENT . "\n";
    echo "  TTL threshold: " . TTL_THRESHOLD . " seconds\n";
    echo "  Cleanup threshold: " . CLEANUP_THRESHOLD . " IPs\n";
    
    // Запуск полной очистки
    $cleanup = new AdvancedCleanup($isWeb);
    $cleanup->runFullCleanup();
    
    // Итого
    $duration = microtime(true) - $startTime;
    echo "\n✓ All cleanup operations completed successfully!\n";
    echo "Total duration: " . number_format($duration, 2) . " seconds\n";
    echo "Finished: " . date('Y-m-d H:i:s') . "\n";
    
    if ($isWeb) {
        echo "\n";
        echo "═══════════════════════════════════════════════════════════════\n";
        echo "РЕКОМЕНДАЦИИ ПО НАСТРОЙКЕ CRON:\n";
        echo "═══════════════════════════════════════════════════════════════\n";
        echo "\n# Запускать каждые 3 минуты (рекомендовано)\n";
        echo "*/3 * * * * php " . __FILE__ . " >> /var/log/cleanup.log 2>&1\n";
        echo "═══════════════════════════════════════════════════════════════\n";
    }
    
    exit(0);
    
} catch (Exception $e) {
    echo "\n✗ FATAL ERROR: " . $e->getMessage() . "\n";
    echo $e->getTraceAsString() . "\n";
    exit(1);
}
?>
