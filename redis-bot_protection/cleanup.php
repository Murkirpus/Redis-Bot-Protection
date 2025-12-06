<?php

// ============================================================================
// УЛУЧШЕННЫЙ CLEANUP - ПЕРЕНЕСЕНЫ ТЯЖЕЛЫЕ ОПЕРАЦИИ ИЗ inline_check.php
// ============================================================================
// Этот скрипт теперь выполняет ВСЮ тяжелую работу по очистке и обслуживанию Redis,
// освобождая inline_check.php для быстрой обработки запросов
//
// ВЕРСИЯ: 1.4 (СОВМЕСТИМА С inline_check.php v2.5.0)
// ДАТА: 2025-12-01
// ИЗМЕНЕНИЯ:
//   v1.4 - Совместимость с inline_check.php v2.5.0
//     - Исправлен паттерн rate limit ключей (tracking:rl:* вместо tracking:rl:1m:*)
//     - Добавлена очистка violations (tracking:violations:*)
//     - Обновлены TTL константы (TRACKING_TTL: 5400, SLOW_BOT_THRESHOLD: 2 часа)
//     - Добавлен подсчёт violations в метриках
//     - Добавлена очистка global rate limit (global:grl:*)
//     - Обновлена статистика с разбивкой по типам
//   v1.3 - Совместимость с новой структурой ключей inline_check.php
//     - Добавлена очистка rate limit ключей (tracking:rl:*)
//     - Добавлена очистка extended tracking (tracking:extended:*)
//     - Добавлена очистка whitelist поисковиков (rdns:whitelist:*)
//     - Добавлена очистка block history (blocked:history:*)
//     - Добавлена очистка API call записей (blocked:api_call:*)
//     - Обновлены метрики для новых типов ключей
//   v1.2 - User-Agent вынесен в настройки
//     - Добавлена константа API_USER_AGENT (было захардкожено 'uptimerobot')
//     - Теперь можно легко изменить User-Agent в настройках
//   v1.1 - Комбинированный подход для разблокировки IP через API
//     - Теперь API вызывается для ВСЕХ IP, где была попытка блокировки через API
//     - Исправлена проблема пропуска разблокировки при api_blocked = false
//     - Добавлена проверка на api_error и старые записи без поля api_blocked
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
define('API_URL', 'https://domain.com/redis-bot_protection/API/iptables.php');
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
        'unblocked_had_api_error' => 0,
        'unblocked_no_api_field' => 0,
        'api_errors' => array(),
        'tracking_cleaned' => 0,
        'rdns_cleaned' => 0,
        'slow_bots_cleaned' => 0,
        'logs_cleaned' => 0,
        'global_metrics_updated' => 0,
        // v1.3
        'rate_limit_cleaned' => 0,
        'extended_tracking_cleaned' => 0,
        'whitelist_cleaned' => 0,
        'block_history_cleaned' => 0,
        'api_call_records_cleaned' => 0,
        // НОВЫЕ v1.4
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
            CURLOPT_USERAGENT => API_USER_AGENT,
            CURLOPT_SSL_VERIFYPEER => true,
        ));
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);
        
        if ($error) {
            return array('status' => 'error', 'message' => $error);
        }
        
        if ($httpCode !== 200) {
            return array('status' => 'error', 'message' => "HTTP $httpCode");
        }
        
        $result = @json_decode($response, true);
        if ($result && isset($result['status'])) {
            return $result;
        }
        
        return array('status' => 'success', 'message' => 'Unblocked');
    }
    
    /**
     * ГЛАВНЫЙ МЕТОД - Запускает все операции очистки
     */
    public function runFullCleanup() {
        $this->output("\n╔════════════════════════════════════════════════════════════════╗\n");
        $this->output("║           FULL CLEANUP - ALL OPERATIONS (v1.4)                 ║\n");
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
        
        // 6. Очистка rate limit ключей (ОБНОВЛЕНО v1.4)
        $this->cleanupRateLimitKeys();
        
        // 7. Очистка extended tracking
        $this->cleanupExtendedTracking();
        
        // 8. Очистка whitelist и block history
        $this->cleanupMiscKeys();
        
        // 9. НОВОЕ v1.4: Очистка violations
        $this->cleanupViolations();
        
        // 10. НОВОЕ v1.4: Очистка global rate limit
        $this->cleanupGlobalRateLimit();
        
        // 11. Обновление глобальных метрик
        $this->updateGlobalMetrics();
        
        // 12. Проверка и очистка при превышении лимитов
        $this->checkAndCleanupIfNeeded();
        
        $this->printStats();
    }
    
    /**
     * 1. ОЧИСТКА БЛОКИРОВОК С ИСТЕКШИМ TTL
     */
    private function cleanupExpiredBlocks() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("1. CLEANING EXPIRED BLOCKS\n");
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
     * Очистка блокировок по паттерну
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
                    $wasApiBlocked = isset($blockData['api_blocked']) && $blockData['api_blocked'];
                    
                    // Комбинированный подход: проверяем была ли попытка API блокировки
                    $wasApiAttempted = ($wasApiBlocked || 
                                       (isset($blockData['api_error']) && !empty($blockData['api_error'])) ||
                                       !isset($blockData['api_blocked']));
                    
                    // Сбор статистики
                    if ($wasApiBlocked) {
                        $apiScenario = 'api_blocked';
                    } elseif (isset($blockData['api_error']) && !empty($blockData['api_error'])) {
                        $apiScenario = 'api_error';
                    } elseif (!isset($blockData['api_blocked'])) {
                        $apiScenario = 'no_field';
                    } else {
                        $apiScenario = 'unknown';
                    }
                    
                    if ($useAPI && $wasApiAttempted && isset($blockData['ip'])) {
                        $ip = $blockData['ip'];
                        $this->output("  Unblocking IP: $ip (TTL: {$ttlDisplay})... ");
                        
                        $result = $this->unblockViaAPI($ip);
                        
                        if ($result['status'] === 'success' || $result['status'] === 'not_blocked') {
                            $this->stats['unblocked_success']++;
                            
                            if ($apiScenario === 'api_blocked') {
                                $this->stats['unblocked_was_api_blocked']++;
                            } elseif ($apiScenario === 'api_error') {
                                $this->stats['unblocked_had_api_error']++;
                            } elseif ($apiScenario === 'no_field') {
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
                        if ($data && isset($data['first_seen'])) {
                            $age = $currentTime - $data['first_seen'];
                            if ($age > TRACKING_TTL) {
                                $this->redis->del($key);
                                $cleaned++;
                            }
                        } else {
                            $this->redis->del($key);
                            $cleaned++;
                        }
                    } elseif ($ttl < 60) {
                        $this->redis->del($key);
                        $cleaned++;
                    }
                }
                
            } while ($iterator > 0);
        }
        
        $this->stats['tracking_cleaned'] = $cleaned;
        $this->output("\n✓ Cleaned tracking records: $cleaned\n");
    }
    
    /**
     * 3. ОЧИСТКА rDNS КЕША
     */
    private function cleanupRDNSCache() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("3. CLEANING rDNS CACHE\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
        
        $pattern = REDIS_PREFIX . 'rdns:cache:*';
        $cleaned = 0;
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
                
                if ($ttl === -1 || $ttl < 60) {
                    $this->redis->del($key);
                    $cleaned++;
                }
            }
            
        } while ($iterator > 0);
        
        $this->stats['rdns_cleaned'] = $cleaned;
        $this->output("✓ Cleaned rDNS cache entries: $cleaned\n");
    }
    
    /**
     * 4. ОЧИСТКА МЕДЛЕННЫХ БОТОВ (ОБНОВЛЕНО v1.4)
     */
    private function cleanupSlowBots() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("4. CLEANING SLOW BOTS DATA (v2.5 thresholds)\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
        
        $pattern = REDIS_PREFIX . 'tracking:ip:*';
        $cleaned = 0;
        $currentTime = time();
        $thresholdTime = $currentTime - (SLOW_BOT_THRESHOLD_HOURS * 3600);
        $iterator = null;
        
        do {
            $keys = $this->redis->scan($iterator, $pattern, CLEANUP_BATCH_SIZE);
            
            if ($keys === false) {
                break;
            }
            
            foreach ($keys as $key) {
                $data = $this->redis->get($key);
                
                if (!$data || !isset($data['first_seen'])) {
                    continue;
                }
                
                $sessionAge = $currentTime - $data['first_seen'];
                $hoursSinceStart = $sessionAge / 3600;
                
                // v2.5: 2 часа вместо 4, 10 запросов вместо 15
                if ($hoursSinceStart > SLOW_BOT_THRESHOLD_HOURS) {
                    $requestCount = isset($data['requests']) ? $data['requests'] : 
                                   (isset($data['request_count']) ? $data['request_count'] : 0);
                    
                    if ($requestCount < SLOW_BOT_MIN_REQUESTS) {
                        $this->redis->del($key);
                        $cleaned++;
                    }
                }
            }
            
        } while ($iterator > 0);
        
        $this->stats['slow_bots_cleaned'] = $cleaned;
        $this->output("✓ Cleaned slow bots data: $cleaned\n");
    }
    
    /**
     * 5. ОЧИСТКА СТАРЫХ ЛОГОВ
     */
    private function cleanupLogs() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("5. CLEANING OLD LOGS\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
        
        $pattern = REDIS_PREFIX . 'log:*';
        $cleaned = 0;
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
                
                if ($ttl === -1 || $ttl < 3600) {
                    $this->redis->del($key);
                    $cleaned++;
                }
            }
            
        } while ($iterator > 0);
        
        $this->stats['logs_cleaned'] = $cleaned;
        $this->output("✓ Cleaned log entries: $cleaned\n");
    }
    
    /**
     * 6. ОЧИСТКА RATE LIMIT КЛЮЧЕЙ (ОБНОВЛЕНО v1.4)
     * v2.3+: Используется tracking:rl:<md5_hash> вместо tracking:rl:1m:*
     */
    private function cleanupRateLimitKeys() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("6. CLEANING RATE LIMIT KEYS (v2.3+ format)\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
        
        $patterns = array(
            // v2.3+ формат (один ключ на IP)
            REDIS_PREFIX . 'tracking:rl:*',
            // Burst detection
            REDIS_PREFIX . 'tracking:burst:*'
        );
        
        $cleaned = 0;
        $burstCleaned = 0;
        
        foreach ($patterns as $pattern) {
            $patternName = str_replace(REDIS_PREFIX, '', $pattern);
            $this->output("\n→ Pattern: $patternName\n");
            $iterator = null;
            $patternCleaned = 0;
            
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
                    
                    // Rate limit ключи имеют TTL 1 час, чистим если почти истекли
                    if ($ttl === -1 || $ttl < 30) {
                        $this->redis->del($key);
                        $patternCleaned++;
                        
                        if (strpos($pattern, 'burst') !== false) {
                            $burstCleaned++;
                        } else {
                            $cleaned++;
                        }
                    }
                }
                
            } while ($iterator > 0);
            
            $this->output("  Cleaned: $patternCleaned\n");
        }
        
        $this->stats['rate_limit_cleaned'] = $cleaned;
        $this->stats['burst_cleaned'] = $burstCleaned;
        $this->output("\n✓ Total rate limit keys cleaned: $cleaned, burst: $burstCleaned\n");
    }
    
    /**
     * 7. ОЧИСТКА EXTENDED TRACKING
     */
    private function cleanupExtendedTracking() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("7. CLEANING EXTENDED TRACKING\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
        
        $pattern = REDIS_PREFIX . 'tracking:extended:*';
        $cleaned = 0;
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
                
                // v2.5: Extended tracking TTL = 6 часов, чистим если < 5 минут
                if ($ttl === -1 || $ttl < 300) {
                    $this->redis->del($key);
                    $cleaned++;
                }
            }
            
        } while ($iterator > 0);
        
        $this->stats['extended_tracking_cleaned'] = $cleaned;
        $this->output("✓ Cleaned extended tracking entries: $cleaned\n");
    }
    
    /**
     * 8. ОЧИСТКА РАЗНЫХ КЛЮЧЕЙ
     */
    private function cleanupMiscKeys() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("8. CLEANING MISC KEYS\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
        
        // Whitelist поисковиков
        $this->output("\n→ Search engine whitelist\n");
        $pattern = REDIS_PREFIX . 'rdns:whitelist:*';
        $iterator = null;
        $whitelistCleaned = 0;
        
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
                
                if ($ttl === -1 || $ttl < 60) {
                    $this->redis->del($key);
                    $whitelistCleaned++;
                }
            }
            
        } while ($iterator > 0);
        
        $this->stats['whitelist_cleaned'] = $whitelistCleaned;
        $this->output("  Cleaned: $whitelistCleaned\n");
        
        // Block history
        $this->output("\n→ Block history\n");
        $pattern = REDIS_PREFIX . 'blocked:history:*';
        $iterator = null;
        $historyCleaned = 0;
        
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
                
                if ($ttl === -1 || $ttl < 300) {
                    $this->redis->del($key);
                    $historyCleaned++;
                }
            }
            
        } while ($iterator > 0);
        
        $this->stats['block_history_cleaned'] = $historyCleaned;
        $this->output("  Cleaned: $historyCleaned\n");
        
        // API call records
        $this->output("\n→ API call records\n");
        $pattern = REDIS_PREFIX . 'blocked:api_call:*';
        $iterator = null;
        $apiCallCleaned = 0;
        
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
                
                if ($ttl === -1 || $ttl < 30) {
                    $this->redis->del($key);
                    $apiCallCleaned++;
                }
            }
            
        } while ($iterator > 0);
        
        $this->stats['api_call_records_cleaned'] = $apiCallCleaned;
        $this->output("  Cleaned: $apiCallCleaned\n");
        
        $this->output("\n✓ Total misc keys cleaned: " . ($whitelistCleaned + $historyCleaned + $apiCallCleaned) . "\n");
    }
    
    /**
     * 9. ОЧИСТКА VIOLATIONS (НОВОЕ v1.4)
     * Удаляет истекшие записи нарушений
     */
    private function cleanupViolations() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("9. CLEANING VIOLATIONS (NEW in v1.4)\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
        
        $pattern = REDIS_PREFIX . 'tracking:violations:*';
        $cleaned = 0;
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
                
                // Violations имеют TTL 1 час, чистим если < 1 минуты
                if ($ttl === -1 || $ttl < 60) {
                    $this->redis->del($key);
                    $cleaned++;
                }
            }
            
        } while ($iterator > 0);
        
        $this->stats['violations_cleaned'] = $cleaned;
        $this->output("✓ Cleaned violations entries: $cleaned\n");
    }
    
    /**
     * 10. ОЧИСТКА GLOBAL RATE LIMIT (НОВОЕ v1.4)
     * Удаляет старые глобальные rate limit записи
     */
    private function cleanupGlobalRateLimit() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("10. CLEANING GLOBAL RATE LIMIT (NEW in v1.4)\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
        
        $pattern = REDIS_PREFIX . 'global:grl:*';
        $cleaned = 0;
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
                
                // Global rate limit имеет TTL 5 секунд, чистим всё без TTL
                if ($ttl === -1 || $ttl < 2) {
                    $this->redis->del($key);
                    $cleaned++;
                }
            }
            
        } while ($iterator > 0);
        
        $this->stats['global_rate_limit_cleaned'] = $cleaned;
        $this->output("✓ Cleaned global rate limit entries: $cleaned\n");
    }
    
    /**
     * 11. ОБНОВЛЕНИЕ ГЛОБАЛЬНЫХ МЕТРИК (ОБНОВЛЕНО v1.4)
     */
    private function updateGlobalMetrics() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("11. UPDATING GLOBAL METRICS\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
        
        $metrics = array(
            'tracked_ips' => 0,
            'blocked_ips' => 0,
            'blocked_hashes' => 0,
            'rdns_cache_size' => 0,
            'rate_limit_keys' => 0,
            'extended_tracking' => 0,
            'whitelist_entries' => 0,
            'violations_count' => 0,  // НОВОЕ v1.4
            'burst_keys' => 0,        // НОВОЕ v1.4
            'last_cleanup' => time()
        );
        
        // Подсчет tracking IPs
        $pattern = REDIS_PREFIX . 'tracking:ip:*';
        $iterator = null;
        do {
            $keys = $this->redis->scan($iterator, $pattern, 1000);
            if ($keys !== false) {
                $metrics['tracked_ips'] += count($keys);
            }
        } while ($iterator > 0);
        
        // Подсчет blocked IPs
        $pattern = REDIS_PREFIX . 'blocked:ip:*';
        $iterator = null;
        do {
            $keys = $this->redis->scan($iterator, $pattern, 1000);
            if ($keys !== false) {
                $metrics['blocked_ips'] += count($keys);
            }
        } while ($iterator > 0);
        
        // Подсчет blocked hashes
        $pattern = REDIS_PREFIX . 'user_hash:blocked:*';
        $iterator = null;
        do {
            $keys = $this->redis->scan($iterator, $pattern, 1000);
            if ($keys !== false) {
                $metrics['blocked_hashes'] += count($keys);
            }
        } while ($iterator > 0);
        
        // Подсчет rDNS cache
        $pattern = REDIS_PREFIX . 'rdns:cache:*';
        $iterator = null;
        do {
            $keys = $this->redis->scan($iterator, $pattern, 1000);
            if ($keys !== false) {
                $metrics['rdns_cache_size'] += count($keys);
            }
        } while ($iterator > 0);
        
        // Подсчет rate limit ключей (v2.3+ формат)
        $pattern = REDIS_PREFIX . 'tracking:rl:*';
        $iterator = null;
        do {
            $keys = $this->redis->scan($iterator, $pattern, 1000);
            if ($keys !== false) {
                $metrics['rate_limit_keys'] += count($keys);
            }
        } while ($iterator > 0);
        
        // НОВОЕ v1.4: Подсчет violations
        $pattern = REDIS_PREFIX . 'tracking:violations:*';
        $iterator = null;
        do {
            $keys = $this->redis->scan($iterator, $pattern, 1000);
            if ($keys !== false) {
                $metrics['violations_count'] += count($keys);
            }
        } while ($iterator > 0);
        
        // НОВОЕ v1.4: Подсчет burst keys
        $pattern = REDIS_PREFIX . 'tracking:burst:*';
        $iterator = null;
        do {
            $keys = $this->redis->scan($iterator, $pattern, 1000);
            if ($keys !== false) {
                $metrics['burst_keys'] += count($keys);
            }
        } while ($iterator > 0);
        
        // Подсчет extended tracking
        $pattern = REDIS_PREFIX . 'tracking:extended:*';
        $iterator = null;
        do {
            $keys = $this->redis->scan($iterator, $pattern, 1000);
            if ($keys !== false) {
                $metrics['extended_tracking'] += count($keys);
            }
        } while ($iterator > 0);
        
        // Подсчет whitelist
        $pattern = REDIS_PREFIX . 'rdns:whitelist:*';
        $iterator = null;
        do {
            $keys = $this->redis->scan($iterator, $pattern, 1000);
            if ($keys !== false) {
                $metrics['whitelist_entries'] += count($keys);
            }
        } while ($iterator > 0);
        
        // Сохраняем метрики
        $this->redis->set(REDIS_PREFIX . 'global:metrics', $metrics);
        $this->redis->expire(REDIS_PREFIX . 'global:metrics', 86400);
        
        $this->stats['global_metrics_updated'] = 1;
        
        $this->output("✓ Metrics updated:\n");
        $this->output("  Tracked IPs: {$metrics['tracked_ips']}\n");
        $this->output("  Blocked IPs: {$metrics['blocked_ips']}\n");
        $this->output("  Blocked Hashes: {$metrics['blocked_hashes']}\n");
        $this->output("  rDNS Cache: {$metrics['rdns_cache_size']}\n");
        $this->output("  Rate Limit Keys: {$metrics['rate_limit_keys']}\n");
        $this->output("  Violations: {$metrics['violations_count']}\n");
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
        
        // Очистка tracking записей старше 1 часа
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
                    // Fallback на first_seen если нет last_seen
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
        $this->output("║                    CLEANUP STATISTICS (v1.4)                   ║\n");
        $this->output("╚════════════════════════════════════════════════════════════════╝\n\n");
        
        $this->output("BLOCKS:\n");
        $this->output("  Checked blocks:           {$this->stats['checked']}\n");
        $this->output("  Expired blocks:           {$this->stats['expired']}\n");
        $this->output("  Successfully unblocked:   {$this->stats['unblocked_success']}\n");
        $this->output("    └─ Was api_blocked:     {$this->stats['unblocked_was_api_blocked']}\n");
        $this->output("    └─ Had api_error:       {$this->stats['unblocked_had_api_error']}\n");
        $this->output("    └─ No api_blocked field: {$this->stats['unblocked_no_api_field']}\n");
        $this->output("  Failed to unblock:        {$this->stats['unblocked_failed']}\n\n");
        
        $this->output("TRACKING & CACHE:\n");
        $this->output("  Tracking cleaned:         {$this->stats['tracking_cleaned']}\n");
        $this->output("  rDNS cache cleaned:       {$this->stats['rdns_cleaned']}\n");
        $this->output("  Slow bots cleaned:        {$this->stats['slow_bots_cleaned']}\n");
        $this->output("  Logs cleaned:             {$this->stats['logs_cleaned']}\n\n");
        
        $this->output("RATE LIMIT & BURST (v1.3+):\n");
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
    echo "║       ADVANCED CLEANUP v1.4 - Full Redis Maintenance        ║\n";
    echo "║  Совместим с inline_check.php v2.5.0 (защита от ботнетов)   ║\n";
    echo "╚══════════════════════════════════════════════════════════════╝\n";
    echo "Started: " . date('Y-m-d H:i:s') . "\n";
    echo "Mode: " . ($isCLI ? "CLI" : "WEB") . "\n";
    
    echo "\nSettings:\n";
    echo "  Redis: " . REDIS_HOST . ":" . REDIS_PORT . "\n";
    echo "  API: " . (API_ENABLED ? API_URL : 'Disabled') . "\n";
    echo "  API User-Agent: " . API_USER_AGENT . "\n";
    echo "  TTL threshold: " . TTL_THRESHOLD . " seconds\n";
    echo "  Cleanup threshold: " . CLEANUP_THRESHOLD . " IPs\n";
    echo "  Batch size: " . CLEANUP_BATCH_SIZE . "\n";
    echo "  Slow bot threshold: " . SLOW_BOT_THRESHOLD_HOURS . " hours / " . SLOW_BOT_MIN_REQUESTS . " requests\n";
    
    // Запуск полной очистки
    $cleanup = new AdvancedCleanup($isWeb);
    $cleanup->runFullCleanup();
    
    // Итого
    $duration = microtime(true) - $startTime;
    echo "\n✓ All cleanup operations completed successfully!\n";
    echo "Total duration: " . number_format($duration, 2) . " seconds\n";
    echo "Finished: " . date('Y-m-d H:i:s') . "\n";
    
    // Рекомендации по cron
    if ($isWeb) {
        echo "\n";
        echo "═══════════════════════════════════════════════════════════════\n";
        echo "РЕКОМЕНДАЦИИ ПО НАСТРОЙКЕ CRON:\n";
        echo "═══════════════════════════════════════════════════════════════\n";
        echo "\n# Запускать каждые 5 минут (основная очистка)\n";
        echo "*/5 * * * * php " . __FILE__ . " >> /var/log/cleanup.log 2>&1\n";
        echo "\n# Альтернатива: каждые 10 минут для меньшей нагрузки\n";
        echo "*/10 * * * * php " . __FILE__ . " >> /var/log/cleanup.log 2>&1\n";
        echo "\n# Для крупных сайтов: каждую минуту\n";
        echo "* * * * * php " . __FILE__ . " >> /var/log/cleanup.log 2>&1\n";
        echo "═══════════════════════════════════════════════════════════════\n";
    }
    
    exit(0);
    
} catch (Exception $e) {
    echo "\n✗ FATAL ERROR: " . $e->getMessage() . "\n";
    echo $e->getTraceAsString() . "\n";
    exit(1);
}
?>
