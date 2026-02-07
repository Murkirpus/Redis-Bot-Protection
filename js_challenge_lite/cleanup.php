<?php
/**
 * ============================================================================
 * MurKir Security - Advanced Cleanup Script v1.3
 * ============================================================================
 * Сумісний з inline_check_lite.php v3.8.13+ (per-site Redis ізоляція)
 * 
 * НОВЕ v1.3:
 * 🔥 Per-site ізоляція: автоматичне виявлення всіх site_id в Redis
 * 🔥 Очистка ключів усіх сайтів (bot_protection:{site_id}:*)
 * 🔥 Зворотня сумісність: очистка legacy ключів (bot_protection:* без site_id)
 * 🔥 Покращена статистика: показує кількість виявлених сайтів
 * 🔥 Новий крок: міграція legacy ключів (видалення старих після переходу)
 * 
 * НОВЕ v1.2:
 * 🔥 Виправлено: Додано api=1 параметр для API запитів (IPv6 не працювало!)
 * 🔥 Виправлено: IPv6 тепер коректно розблоковуються через POST
 * 🔥 Додано: Підтримка GET/POST методів для API (налаштування API_METHOD)
 * 
 * НОВЕ v1.1:
 * 🔥 Додано паттерн ua_rotation_blocked (старий формат)
 * 🔥 Режим --force для примусової очистки ВСІХ блокувань
 * 🔥 Очистка total та log лічильників в force режимі
 * 
 * ВИКОРИСТАННЯ FORCE MODE:
 *   CLI:  php cleanup.php --force
 *   WEB:  cleanup.php?force=1
 *   Також можна встановити FORCE_CLEANUP = true в конфігурації
 * 
 * Функції:
 *   1. Очистка блокировок з TTL що закінчується (+ API розблокування)
 *   2. Очистка UA tracking
 *   3. Очистка rDNS кешу
 *   4. Очистка no-cookie attempts
 *   5. Очистка whitelist кешу
 *   6. Очистка rate limit даних
 *   7. Очистка JS Challenge статистики
 *   8. Очистка search engine visits
 *   9. Оновлення глобальних метрик
 *  10. Перевірка порогів та агресивна очистка
 *  11. Міграція: очистка legacy ключів (без site_id)
 * 
 * Використання:
 *   CLI:  php cleanup.php
 *   WEB:  https://site.com/cleanup.php?key=YOUR_SECRET_KEY
 *   CRON: Run every 5 minutes - see example at the end of script
 * 
 * ============================================================================
 */

// ============================================================================
// НАЛАШТУВАННЯ - ЗМІНІТЬ НА СВОЇ!
// ============================================================================

// Redis налаштування
define('REDIS_HOST', '127.0.0.1');
define('REDIS_PORT', 6379);
define('REDIS_PASSWORD', null);       // або ваш пароль
define('REDIS_DATABASE', 1);          // MurKir Security використовує DB 1
define('REDIS_BASE_PREFIX', 'bot_protection:'); // Базовий префікс (без site_id)

// API налаштування для iptables (має збігатися з inline_check_lite.php)
define('API_ENABLED', true);
define('API_URL', 'https://blog.dj-x.info/redis-bot_protection/API/iptables.php');  // ЗМІНІТЬ!
define('API_KEY', 'Asd12345');                        // ЗМІНІТЬ!
define('API_METHOD', 'POST');                          // v1.2: 'GET' або 'POST' (POST рекомендовано для IPv6!)
define('API_TIMEOUT', 5);
define('API_USER_AGENT', 'MurKir-Cleanup/1.3');

// Налаштування очистки
define('TTL_THRESHOLD', 300);         // Розблокувати якщо TTL < 5 хвилин
define('BATCH_SIZE', 100);            // Обробляти по 100 ключів за раз
define('API_DELAY_MS', 100);          // Затримка між API запитами (мс)

// TTL для різних типів даних
define('UA_TRACKING_TTL', 3600);      // UA tracking - 1 година
define('RDNS_CACHE_TTL', 86400);      // rDNS кеш - 24 години
define('WHITELIST_CACHE_TTL', 3600);  // Whitelist кеш негативний - 1 година
define('NO_COOKIE_TTL', 3600);        // No-cookie attempts - 1 година
define('JSC_STATS_TTL', 604800);      // JS Challenge статистика - 7 днів

// Пороги для агресивної очистки
define('CLEANUP_THRESHOLD', 10000);   // Поріг кількості ключів
define('MAX_CLEANUP_TIME_MS', 500);   // Максимальний час на очистку (мс)

// v1.1: Режим примусової очистки (видаляє ВСІ блокування незалежно від TTL)
define('FORCE_CLEANUP', false);       // За замовчуванням вимкнено

// v1.3: Видаляти legacy ключі (без site_id) під час очистки
define('CLEANUP_LEGACY_KEYS', true);  // Рекомендовано true після оновлення

// Захист веб-доступу (опціонально - розкоментуй якщо потрібен захист)
// define('WEB_ACCESS_KEY', 'YOUR_SECRET_KEY');

// ============================================================================
// ВИЗНАЧЕННЯ РЕЖИМУ ЗАПУСКУ
// ============================================================================

$isCLI = (php_sapi_name() === 'cli');
$isWeb = !$isCLI;

// Перевірка ключа для веб-доступу (тільки якщо WEB_ACCESS_KEY визначено)
if ($isWeb && defined('WEB_ACCESS_KEY')) {
    $providedKey = isset($_GET['key']) ? $_GET['key'] : '';
    if ($providedKey !== WEB_ACCESS_KEY) {
        http_response_code(403);
        die("Access denied. Provide correct key parameter.");
    }
}

if ($isWeb) {
    header('Content-Type: text/plain; charset=utf-8');
    @ini_set('output_buffering', 'off');
    @ini_set('implicit_flush', 'on');
    if (ob_get_level()) {
        ob_end_flush();
    }
}

// v1.1: Перевірка режиму примусової очистки
$forceCleanup = FORCE_CLEANUP;

if ($isCLI) {
    global $argv;
    if (isset($argv) && in_array('--force', $argv)) {
        $forceCleanup = true;
    }
} else {
    if (isset($_GET['force']) && $_GET['force'] == '1') {
        $forceCleanup = true;
    }
}

// ============================================================================
// КЛАС ОЧИСТКИ
// ============================================================================

class MurKirCleanup {
    private $redis;
    private $isWeb;
    private $startTime;
    
    // v1.3: Масив всіх виявлених префіксів (per-site + legacy)
    private $sitePrefixes = array();  // Per-site: ['bot_protection:a1b2c3d4:', ...]
    private $legacyPrefix = '';       // Legacy: 'bot_protection:'
    
    private $stats = array(
        'blocks_checked' => 0, 'blocks_expired' => 0, 'blocks_unblocked' => 0,
        'blocks_api_success' => 0, 'blocks_api_failed' => 0, 'api_errors' => array(),
        'ua_tracking_checked' => 0, 'ua_tracking_cleaned' => 0,
        'rdns_checked' => 0, 'rdns_cleaned' => 0,
        'no_cookie_checked' => 0, 'no_cookie_cleaned' => 0,
        'whitelist_checked' => 0, 'whitelist_cleaned' => 0,
        'rate_limit_checked' => 0, 'rate_limit_cleaned' => 0,
        'jsc_stats_checked' => 0, 'jsc_stats_cleaned' => 0,
        'se_visits_checked' => 0, 'se_visits_cleaned' => 0,
        'legacy_checked' => 0, 'legacy_cleaned' => 0,
        'metrics_updated' => false, 'sites_found' => 0,
    );
    
    private $forceCleanup = false;
    
    public function __construct($isWeb = false, $forceCleanup = false) {
        $this->isWeb = $isWeb;
        $this->forceCleanup = $forceCleanup;
        $this->startTime = microtime(true);
        $this->legacyPrefix = REDIS_BASE_PREFIX;
        $this->connectRedis();
        $this->discoverSitePrefixes();
    }
    
    private function output($message) {
        echo $message;
        if ($this->isWeb) flush();
    }
    
    private function connectRedis() {
        try {
            $this->redis = new Redis();
            if (!$this->redis->connect(REDIS_HOST, REDIS_PORT, 2)) {
                throw new Exception("Cannot connect to Redis");
            }
            if (REDIS_PASSWORD) $this->redis->auth(REDIS_PASSWORD);
            $this->redis->select(REDIS_DATABASE);
            $this->redis->setOption(Redis::OPT_SERIALIZER, Redis::SERIALIZER_PHP);
            $this->output("✓ Connected to Redis (DB " . REDIS_DATABASE . ")\n");
        } catch (Exception $e) {
            $this->output("✗ Redis connection failed: " . $e->getMessage() . "\n");
            throw $e;
        }
    }
    
    /**
     * v1.3: Виявлення всіх site_id префіксів в Redis
     * Шукаємо ключі виду bot_protection:{8_hex_chars}:*
     */
    private function discoverSitePrefixes() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("DISCOVERING SITE PREFIXES\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
        
        $siteIds = array();
        $iterator = null;
        
        do {
            $keys = $this->redis->scan($iterator, REDIS_BASE_PREFIX . '*', 500);
            if ($keys === false) break;
            
            foreach ($keys as $key) {
                $afterBase = substr($key, strlen(REDIS_BASE_PREFIX));
                // Per-site ключ: {8 hex chars}:{rest}
                if (preg_match('/^([a-f0-9]{8}):/', $afterBase, $m)) {
                    $siteIds[$m[1]] = true;
                }
            }
        } while ($iterator > 0);
        
        $this->sitePrefixes = array();
        foreach (array_keys($siteIds) as $siteId) {
            $this->sitePrefixes[] = REDIS_BASE_PREFIX . $siteId . ':';
        }
        
        $this->stats['sites_found'] = count($this->sitePrefixes);
        
        $this->output("  Found " . count($this->sitePrefixes) . " site prefix(es):\n");
        foreach ($this->sitePrefixes as $prefix) {
            $this->output("    → $prefix\n");
        }
        if (empty($this->sitePrefixes)) {
            $this->output("  ⚠ No per-site prefixes found. Only legacy keys will be processed.\n");
        }
    }
    
    /**
     * v1.3: Повертає масив SCAN-паттернів по всіх сайтах + legacy
     */
    private function getAllPatterns($suffix, $includeLegacy = true) {
        $patterns = array();
        foreach ($this->sitePrefixes as $prefix) {
            $patterns[] = $prefix . $suffix;
        }
        if ($includeLegacy) {
            $patterns[] = $this->legacyPrefix . $suffix;
        }
        return $patterns;
    }
    
    /**
     * v1.3: Витягнути IP з ключа (per-site або legacy формат)
     */
    private function extractIPFromKey($key, $ipKeyPart) {
        // Per-site: bot_protection:{site_id}:{ipKeyPart}{IP}
        foreach ($this->sitePrefixes as $prefix) {
            $fullPrefix = $prefix . $ipKeyPart;
            if (strpos($key, $fullPrefix) === 0) {
                return substr($key, strlen($fullPrefix));
            }
        }
        // Legacy: bot_protection:{ipKeyPart}{IP}
        $legacyFull = $this->legacyPrefix . $ipKeyPart;
        if (strpos($key, $legacyFull) === 0) {
            return substr($key, strlen($legacyFull));
        }
        return null;
    }
    
    /**
     * Виклик API для розблокування IP
     */
    private function unblockViaAPI($ip) {
        if (!API_ENABLED) {
            return array('status' => 'disabled', 'message' => 'API disabled');
        }
        
        $params = array(
            'action' => 'unblock', 'ip' => $ip,
            'api' => 1, 'api_key' => API_KEY
        );
        
        $method = defined('API_METHOD') ? strtoupper(API_METHOD) : 'POST';
        $ch = curl_init();
        
        $curlOptions = array(
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => API_TIMEOUT,
            CURLOPT_CONNECTTIMEOUT => API_TIMEOUT,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_USERAGENT => API_USER_AGENT,
            CURLOPT_HTTPHEADER => array('Accept: application/json', 'Cache-Control: no-cache'),
        );
        
        if ($method === 'POST') {
            $curlOptions[CURLOPT_URL] = API_URL;
            $curlOptions[CURLOPT_POST] = true;
            $curlOptions[CURLOPT_POSTFIELDS] = http_build_query($params);
        } else {
            $curlOptions[CURLOPT_URL] = API_URL . '?' . http_build_query($params);
        }
        
        curl_setopt_array($ch, $curlOptions);
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);
        
        if ($curlError) return array('status' => 'error', 'message' => "CURL: $curlError");
        if ($httpCode !== 200) return array('status' => 'error', 'message' => "HTTP $httpCode");
        
        $data = json_decode($response, true);
        if (!$data) {
            return array('status' => 'error', 'message' => "Invalid JSON. Response: " . substr($response, 0, 100) . "...");
        }
        if (isset($data['status'])) {
            if ($data['status'] === 'success' || $data['status'] === 'not_blocked') {
                return array('status' => 'success', 'message' => 'Unblocked');
            }
            return array('status' => 'error', 'message' => isset($data['message']) ? $data['message'] : 'Unknown error');
        }
        return array('status' => 'success', 'message' => 'OK');
    }
    
    // ========================================================================
    // ГОЛОВНИЙ МЕТОД
    // ========================================================================
    
    public function runFullCleanup() {
        $this->output("\n╔════════════════════════════════════════════════════════════════╗\n");
        $this->output("║        MurKir Security - Full Cleanup v1.3                     ║\n");
        $this->output("║        Per-site Redis ізоляція                                  ║\n");
        $this->output("╚════════════════════════════════════════════════════════════════╝\n\n");
        
        $this->cleanupExpiredBlocks();      // 1
        $this->cleanupUATracking();         // 2
        $this->cleanupRDNSCache();          // 3
        $this->cleanupNoCookieAttempts();   // 4
        $this->cleanupWhitelistCache();     // 5
        $this->cleanupRateLimitData();      // 6
        $this->cleanupJSCStats();           // 7
        $this->cleanupSearchEngineVisits(); // 8
        $this->updateGlobalMetrics();       // 9
        $this->checkThresholds();           // 10
        
        if (CLEANUP_LEGACY_KEYS) {
            $this->cleanupLegacyKeys();     // 11
        }
        
        $this->printStats();
    }
    
    // ========================================================================
    // 1. ОЧИСТКА БЛОКИРОВОК
    // ========================================================================
    
    private function cleanupExpiredBlocks() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("1. CLEANING EXPIRED BLOCKS\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
        
        $blockConfigs = array(
            array(
                'suffix' => 'ua_blocked:*',
                'description' => 'UA Blocks (new format)',
                'api_unblock' => true, 'ip_from_key' => true,
                'ip_key_part' => 'ua_blocked:',
            ),
            array(
                'suffix' => 'ua_rotation_blocked:*',
                'description' => 'UA Rotation Blocks (old format)',
                'api_unblock' => true, 'ip_from_key' => true,
                'ip_key_part' => 'ua_rotation_blocked:',
            ),
            array(
                'suffix' => 'blocked:hammer:*',
                'description' => 'Hammer Attack Blocks',
                'api_unblock' => true, 'ip_from_key' => true,
                'ip_key_part' => 'blocked:hammer:',
            ),
            array(
                'suffix' => 'blocked:no_cookie:*',
                'description' => 'No-Cookie Attack Blocks',
                'api_unblock' => true, 'ip_from_key' => true,
                'ip_key_part' => 'blocked:no_cookie:',
            ),
            array(
                'suffix' => 'blocked:*',
                'description' => 'Rate Limit Blocks',
                'api_unblock' => true, 'ip_from_key' => false,
                'exclude' => array('no_cookie', 'hammer'),
            ),
        );
        
        foreach ($blockConfigs as $config) {
            $this->output("\n→ {$config['description']}\n");
            $patterns = $this->getAllPatterns($config['suffix'], true);
            foreach ($patterns as $pattern) {
                $this->cleanupBlockPattern($pattern, $config);
            }
        }
    }
    
    private function cleanupBlockPattern($pattern, $config) {
        $useAPI = $config['api_unblock'];
        $ipFromKey = isset($config['ip_from_key']) ? $config['ip_from_key'] : false;
        $ipKeyPart = isset($config['ip_key_part']) ? $config['ip_key_part'] : '';
        $exclude = isset($config['exclude']) ? $config['exclude'] : array();
        
        $iterator = null;
        $found = 0;
        
        do {
            $keys = $this->redis->scan($iterator, $pattern, BATCH_SIZE);
            if ($keys === false) break;
            
            foreach ($keys as $key) {
                $skip = false;
                foreach ($exclude as $exc) {
                    if (strpos($key, $exc) !== false) { $skip = true; break; }
                }
                if ($skip) continue;
                
                $this->stats['blocks_checked']++;
                $found++;
                
                $ttl = $this->redis->ttl($key);
                if ($ttl === -2) continue;
                
                $shouldCleanup = false;
                if ($this->forceCleanup) {
                    $shouldCleanup = true;
                } elseif ($ttl === -1) {
                    $this->output("  ⚠ Key without TTL: " . basename($key) . "\n");
                    $shouldCleanup = true;
                } elseif ($ttl <= TTL_THRESHOLD) {
                    $shouldCleanup = true;
                }
                
                if ($shouldCleanup) {
                    $this->stats['blocks_expired']++;
                    $ip = null;
                    
                    if ($ipFromKey && $ipKeyPart) {
                        $ip = $this->extractIPFromKey($key, $ipKeyPart);
                    } elseif (!$ipFromKey) {
                        $data = $this->redis->get($key);
                        if (is_array($data) && isset($data['ip'])) $ip = $data['ip'];
                    }
                    
                    $ttlDisplay = ($ttl === -1) ? "NO TTL" : "{$ttl}s";
                    
                    if ($useAPI && $ip && filter_var($ip, FILTER_VALIDATE_IP)) {
                        $this->output("  Unblocking IP: $ip (TTL: {$ttlDisplay})... ");
                        $result = $this->unblockViaAPI($ip);
                        if ($result['status'] === 'success' || $result['status'] === 'disabled') {
                            $this->stats['blocks_api_success']++;
                            $this->output("✓\n");
                        } else {
                            $this->stats['blocks_api_failed']++;
                            $this->stats['api_errors'][] = "$ip: " . $result['message'];
                            $this->output("✗ " . $result['message'] . "\n");
                        }
                        usleep(API_DELAY_MS * 1000);
                    } else {
                        $this->output("  Removing: " . basename($key) . " (TTL: {$ttlDisplay})\n");
                    }
                    
                    $this->redis->del($key);
                    $this->stats['blocks_unblocked']++;
                }
            }
        } while ($iterator > 0);
        
        if ($found > 0) {
            $this->output("  Checked: $found keys\n");
        }
    }
    
    // ========================================================================
    // 2. ОЧИСТКА UA TRACKING
    // ========================================================================
    
    private function cleanupUATracking() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("2. CLEANING UA TRACKING\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
        
        $patterns = $this->getAllPatterns('ua:*', true);
        $cleaned = 0;
        
        foreach ($patterns as $pattern) {
            $iterator = null;
            do {
                $keys = $this->redis->scan($iterator, $pattern, BATCH_SIZE);
                if ($keys === false) break;
                foreach ($keys as $key) {
                    $this->stats['ua_tracking_checked']++;
                    $ttl = $this->redis->ttl($key);
                    if ($ttl === -2) continue;
                    if ($ttl === -1) { $this->redis->del($key); $cleaned++; }
                }
            } while ($iterator > 0);
        }
        
        $this->stats['ua_tracking_cleaned'] = $cleaned;
        $this->output("  Cleaned: $cleaned keys\n");
    }
    
    // ========================================================================
    // 3. ОЧИСТКА rDNS КЕШУ
    // ========================================================================
    
    private function cleanupRDNSCache() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("3. CLEANING rDNS CACHE\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
        
        $suffixes = array('rdns_verified:*', 'rdns_check_count:*', 'rdns:cache:*');
        $cleaned = 0;
        
        foreach ($suffixes as $suffix) {
            $patterns = $this->getAllPatterns($suffix, true);
            foreach ($patterns as $pattern) {
                $iterator = null;
                do {
                    $keys = $this->redis->scan($iterator, $pattern, BATCH_SIZE);
                    if ($keys === false) break;
                    foreach ($keys as $key) {
                        $this->stats['rdns_checked']++;
                        $ttl = $this->redis->ttl($key);
                        if ($ttl === -2) continue;
                        if ($ttl === -1) { $this->redis->expire($key, RDNS_CACHE_TTL); $cleaned++; }
                    }
                } while ($iterator > 0);
            }
        }
        
        $this->stats['rdns_cleaned'] = $cleaned;
        $this->output("  Fixed TTL for: $cleaned keys\n");
    }
    
    // ========================================================================
    // 4. ОЧИСТКА NO-COOKIE ATTEMPTS
    // ========================================================================
    
    private function cleanupNoCookieAttempts() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("4. CLEANING NO-COOKIE ATTEMPTS\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
        
        $patterns = $this->getAllPatterns('no_cookie_attempts:*', true);
        $cleaned = 0;
        
        foreach ($patterns as $pattern) {
            $iterator = null;
            do {
                $keys = $this->redis->scan($iterator, $pattern, BATCH_SIZE);
                if ($keys === false) break;
                foreach ($keys as $key) {
                    $this->stats['no_cookie_checked']++;
                    $ttl = $this->redis->ttl($key);
                    if ($ttl === -2) continue;
                    if ($ttl === -1) { $this->redis->del($key); $cleaned++; }
                }
            } while ($iterator > 0);
        }
        
        $this->stats['no_cookie_cleaned'] = $cleaned;
        $this->output("  Cleaned: $cleaned keys\n");
    }
    
    // ========================================================================
    // 5. ОЧИСТКА WHITELIST КЕШУ (shared між сайтами)
    // ========================================================================
    
    private function cleanupWhitelistCache() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("5. CLEANING WHITELIST CACHE\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
        
        $pattern = $this->legacyPrefix . 'ip_whitelist:*';
        $iterator = null;
        $cleaned = 0;
        
        do {
            $keys = $this->redis->scan($iterator, $pattern, BATCH_SIZE);
            if ($keys === false) break;
            foreach ($keys as $key) {
                $this->stats['whitelist_checked']++;
                $ttl = $this->redis->ttl($key);
                if ($ttl === -2) continue;
                if ($ttl === -1) {
                    $value = $this->redis->get($key);
                    if ($value === '0' || $value === 0) { $this->redis->del($key); $cleaned++; }
                }
            }
        } while ($iterator > 0);
        
        $this->stats['whitelist_cleaned'] = $cleaned;
        $this->output("  Cleaned negative cache: $cleaned keys\n");
    }
    
    // ========================================================================
    // 6. ОЧИСТКА RATE LIMIT ДАНИХ
    // ========================================================================
    
    private function cleanupRateLimitData() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("6. CLEANING RATE LIMIT DATA\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
        
        // Новий формат rate:* + старий формат rate_limit:*
        $patterns = $this->getAllPatterns('rate:*', true);
        $patterns = array_merge($patterns, $this->getAllPatterns('rate_limit:*', true));
        $cleaned = 0;
        
        foreach ($patterns as $pattern) {
            $iterator = null;
            do {
                $keys = $this->redis->scan($iterator, $pattern, BATCH_SIZE);
                if ($keys === false) break;
                foreach ($keys as $key) {
                    $this->stats['rate_limit_checked']++;
                    $ttl = $this->redis->ttl($key);
                    if ($ttl === -2) continue;
                    if ($ttl === -1) { $this->redis->del($key); $cleaned++; }
                }
            } while ($iterator > 0);
        }
        
        $this->stats['rate_limit_cleaned'] = $cleaned;
        $this->output("  Cleaned: $cleaned keys\n");
    }
    
    // ========================================================================
    // 7. ОЧИСТКА JS CHALLENGE СТАТИСТИКИ
    // ========================================================================
    
    private function cleanupJSCStats() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("7. CLEANING OLD JSC STATS\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
        
        $threshold = date('Y-m-d', strtotime('-7 days'));
        $suffixes = array('jsc_stats:daily:*', 'jsc_stats:hourly:*');
        
        if ($this->forceCleanup) {
            $suffixes[] = 'jsc_stats:total:*';
            $suffixes[] = 'jsc_stats:log:*';
            $this->output("  ⚠ FORCE MODE: очищаємо також total та log\n");
        }
        
        // Також очищаємо jsc_auto:pending та jsc_auto:requests та jsc_auto:no_cookie
        $suffixes[] = 'jsc_auto:pending:*';
        $suffixes[] = 'jsc_auto:requests:*';
        $suffixes[] = 'jsc_auto:no_cookie:*';
        
        $cleaned = 0;
        
        foreach ($suffixes as $suffix) {
            $patterns = $this->getAllPatterns($suffix, true);
            foreach ($patterns as $pattern) {
                $iterator = null;
                do {
                    $keys = $this->redis->scan($iterator, $pattern, BATCH_SIZE);
                    if ($keys === false) break;
                    foreach ($keys as $key) {
                        $this->stats['jsc_stats_checked']++;
                        
                        if ($this->forceCleanup) {
                            $this->redis->del($key); $cleaned++; continue;
                        }
                        
                        // Для pending/requests/no_cookie - видаляємо якщо без TTL
                        if (strpos($key, 'jsc_auto:') !== false) {
                            $ttl = $this->redis->ttl($key);
                            if ($ttl === -1) { $this->redis->del($key); $cleaned++; }
                            continue;
                        }
                        
                        // Для статистики - видаляємо старі за датою
                        if (preg_match('/(\d{4}-\d{2}-\d{2})/', $key, $matches)) {
                            if ($matches[1] < $threshold) { $this->redis->del($key); $cleaned++; }
                        }
                    }
                } while ($iterator > 0);
            }
        }
        
        $this->stats['jsc_stats_cleaned'] = $cleaned;
        $this->output("  Cleaned: $cleaned keys\n");
    }
    
    // ========================================================================
    // 8. ОЧИСТКА SEARCH ENGINE VISITS (shared)
    // ========================================================================
    
    private function cleanupSearchEngineVisits() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("8. CLEANING OLD SEARCH ENGINE VISITS\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
        
        $threshold = date('Y-m-d', strtotime('-30 days'));
        
        $patterns = array(
            $this->legacyPrefix . 'search_engine_visits:daily:*',
            $this->legacyPrefix . 'search_engine_visits:host:*',
            $this->legacyPrefix . 'search_stats:today:*',
            $this->legacyPrefix . 'search_stats:hosts:*',
        );
        
        $cleaned = 0;
        
        foreach ($patterns as $pattern) {
            $iterator = null;
            do {
                $keys = $this->redis->scan($iterator, $pattern, BATCH_SIZE);
                if ($keys === false) break;
                foreach ($keys as $key) {
                    $this->stats['se_visits_checked']++;
                    if (preg_match('/(\d{4}-\d{2}-\d{2})/', $key, $matches)) {
                        if ($matches[1] < $threshold) { $this->redis->del($key); $cleaned++; }
                    }
                }
            } while ($iterator > 0);
        }
        
        $this->stats['se_visits_cleaned'] = $cleaned;
        $this->output("  Cleaned visits older than $threshold: $cleaned keys\n");
    }
    
    // ========================================================================
    // 9. ОНОВЛЕННЯ ГЛОБАЛЬНИХ МЕТРИК
    // ========================================================================
    
    private function updateGlobalMetrics() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("9. UPDATING GLOBAL METRICS\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
        
        $metrics = array(
            'ua_blocked' => 0, 'hammer_blocked' => 0,
            'no_cookie_blocked' => 0, 'rate_limit_blocked' => 0,
            'whitelist_cached' => 0,
            'sites_count' => count($this->sitePrefixes),
            'last_cleanup' => date('Y-m-d H:i:s'),
        );
        
        foreach ($this->getAllPatterns('ua_blocked:*', true) as $p) {
            $k = $this->redis->keys($p);
            $metrics['ua_blocked'] += $k ? count($k) : 0;
        }
        foreach ($this->getAllPatterns('blocked:hammer:*', true) as $p) {
            $k = $this->redis->keys($p);
            $metrics['hammer_blocked'] += $k ? count($k) : 0;
        }
        foreach ($this->getAllPatterns('blocked:no_cookie:*', true) as $p) {
            $k = $this->redis->keys($p);
            $metrics['no_cookie_blocked'] += $k ? count($k) : 0;
        }
        $totalBlocked = 0;
        foreach ($this->getAllPatterns('blocked:*', true) as $p) {
            $k = $this->redis->keys($p);
            $totalBlocked += $k ? count($k) : 0;
        }
        $metrics['rate_limit_blocked'] = max(0, $totalBlocked - $metrics['no_cookie_blocked'] - $metrics['hammer_blocked']);
        
        $k = $this->redis->keys($this->legacyPrefix . 'ip_whitelist:*');
        $metrics['whitelist_cached'] = $k ? count($k) : 0;
        
        $this->redis->set($this->legacyPrefix . 'global:cleanup_metrics', $metrics);
        $this->stats['metrics_updated'] = true;
        
        $this->output("  Sites found:           {$metrics['sites_count']}\n");
        $this->output("  UA Blocked IPs:        {$metrics['ua_blocked']}\n");
        $this->output("  Hammer Blocked IPs:    {$metrics['hammer_blocked']}\n");
        $this->output("  No-Cookie Blocked IPs: {$metrics['no_cookie_blocked']}\n");
        $this->output("  Rate Limit Blocked:    {$metrics['rate_limit_blocked']}\n");
        $this->output("  Whitelist Cached:      {$metrics['whitelist_cached']}\n");
    }
    
    // ========================================================================
    // 10. ПЕРЕВІРКА ПОРОГІВ
    // ========================================================================
    
    private function checkThresholds() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("10. CHECKING THRESHOLDS\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
        
        $allKeys = $this->redis->keys($this->legacyPrefix . '*');
        $totalKeys = $allKeys ? count($allKeys) : 0;
        
        $this->output("  Total keys: $totalKeys / " . CLEANUP_THRESHOLD . "\n");
        
        if ($totalKeys > CLEANUP_THRESHOLD) {
            $this->output("  ⚠ THRESHOLD EXCEEDED! Running aggressive cleanup...\n");
            $this->performAggressiveCleanup();
        } else {
            $this->output("  ✓ Within limits\n");
        }
    }
    
    private function performAggressiveCleanup() {
        $cleaned = 0;
        $startTime = microtime(true);
        $suffixes = array('ua:*', 'rate:*', 'rate_limit:*', 'no_cookie_attempts:*');
        
        foreach ($suffixes as $suffix) {
            $patterns = $this->getAllPatterns($suffix, true);
            foreach ($patterns as $pattern) {
                $iterator = null;
                do {
                    if ((microtime(true) - $startTime) * 1000 > MAX_CLEANUP_TIME_MS) {
                        $this->output("  Time limit reached\n");
                        break 3;
                    }
                    $keys = $this->redis->scan($iterator, $pattern, BATCH_SIZE);
                    if ($keys === false) break;
                    foreach ($keys as $key) {
                        $ttl = $this->redis->ttl($key);
                        if ($ttl === -1) { $this->redis->del($key); $cleaned++; }
                    }
                } while ($iterator > 0);
            }
        }
        
        $this->output("  Aggressively cleaned: $cleaned keys\n");
    }
    
    // ========================================================================
    // 11. v1.3: МІГРАЦІЯ LEGACY КЛЮЧІВ
    // ========================================================================
    
    /**
     * Видаляє старі ключі формату bot_protection:{type}:{data}
     * які не мають site_id (залишилися від попередньої версії).
     * Пропускає shared ключі (ip_whitelist, search_stats, search_log, global).
     */
    private function cleanupLegacyKeys() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("11. CLEANING LEGACY KEYS (no site_id)\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
        
        // Shared ключі - НЕ видаляємо
        $sharedPrefixes = array(
            'ip_whitelist:', 'search_stats:', 'search_log', 'global:',
        );
        
        // Per-site ключі які мають видалятися якщо legacy (без site_id)
        $legacySuffixes = array(
            'blocked:', 'ua_blocked:', 'ua_rotation_blocked:',
            'ua:', 'rate:', 'rate_limit:',
            'no_cookie_attempts:', 'hammer:',
            'jsc_auto:', 'jsc_stats:',
            'hammer_stats:', 'hammer_blocks:',
        );
        
        $iterator = null;
        $cleaned = 0;
        $checked = 0;
        
        do {
            $keys = $this->redis->scan($iterator, $this->legacyPrefix . '*', BATCH_SIZE);
            if ($keys === false) break;
            
            foreach ($keys as $key) {
                $afterBase = substr($key, strlen($this->legacyPrefix));
                
                // Пропускаємо per-site ключі (8 hex + :)
                if (preg_match('/^[a-f0-9]{8}:/', $afterBase)) continue;
                
                // Пропускаємо shared ключі
                $isShared = false;
                foreach ($sharedPrefixes as $sp) {
                    if (strpos($afterBase, $sp) === 0) { $isShared = true; break; }
                }
                if ($isShared) continue;
                
                // Перевіряємо чи це legacy per-site ключ
                $isLegacy = false;
                foreach ($legacySuffixes as $ls) {
                    if (strpos($afterBase, $ls) === 0) { $isLegacy = true; break; }
                }
                
                if ($isLegacy) {
                    $checked++;
                    $this->stats['legacy_checked']++;
                    
                    if ($this->forceCleanup) {
                        $this->redis->del($key);
                        $cleaned++;
                    } else {
                        $ttl = $this->redis->ttl($key);
                        if ($ttl === -1 || ($ttl > 0 && $ttl <= TTL_THRESHOLD)) {
                            $this->redis->del($key);
                            $cleaned++;
                        }
                    }
                }
            }
        } while ($iterator > 0);
        
        $this->stats['legacy_cleaned'] = $cleaned;
        $this->output("  Legacy keys checked: $checked\n");
        $this->output("  Legacy keys cleaned: $cleaned\n");
        
        if ($checked > 0 && !$this->forceCleanup) {
            $this->output("  💡 Tip: use --force to remove all remaining legacy keys\n");
        }
    }
    
    // ========================================================================
    // ВИВІД СТАТИСТИКИ
    // ========================================================================
    
    private function printStats() {
        $duration = microtime(true) - $this->startTime;
        
        $this->output("\n");
        $this->output("╔════════════════════════════════════════════════════════════════╗\n");
        $this->output("║              CLEANUP STATISTICS                                ║\n");
        $this->output("╚════════════════════════════════════════════════════════════════╝\n\n");
        
        $this->output("SITES:\n");
        $this->output("  Found:                {$this->stats['sites_found']}\n\n");
        
        $this->output("BLOCKS:\n");
        $this->output("  Checked:              {$this->stats['blocks_checked']}\n");
        $this->output("  Expired:              {$this->stats['blocks_expired']}\n");
        $this->output("  Unblocked:            {$this->stats['blocks_unblocked']}\n");
        $this->output("  API Success:          {$this->stats['blocks_api_success']}\n");
        $this->output("  API Failed:           {$this->stats['blocks_api_failed']}\n\n");
        
        $this->output("TRACKING & CACHE:\n");
        $this->output("  UA Tracking cleaned:  {$this->stats['ua_tracking_cleaned']}\n");
        $this->output("  rDNS fixed:           {$this->stats['rdns_cleaned']}\n");
        $this->output("  No-Cookie cleaned:    {$this->stats['no_cookie_cleaned']}\n");
        $this->output("  Whitelist cleaned:    {$this->stats['whitelist_cleaned']}\n");
        $this->output("  Rate Limit cleaned:   {$this->stats['rate_limit_cleaned']}\n\n");
        
        $this->output("STATS:\n");
        $this->output("  JSC Stats cleaned:    {$this->stats['jsc_stats_cleaned']}\n");
        $this->output("  SE Visits cleaned:    {$this->stats['se_visits_cleaned']}\n\n");
        
        $this->output("LEGACY:\n");
        $this->output("  Legacy checked:       {$this->stats['legacy_checked']}\n");
        $this->output("  Legacy cleaned:       {$this->stats['legacy_cleaned']}\n\n");
        
        $this->output("METRICS:\n");
        $this->output("  Updated:              " . ($this->stats['metrics_updated'] ? 'Yes' : 'No') . "\n\n");
        
        $this->output("PERFORMANCE:\n");
        $this->output("  Duration:             " . number_format($duration, 2) . "s\n\n");
        
        if (!empty($this->stats['api_errors'])) {
            $this->output("API ERRORS:\n");
            foreach (array_slice($this->stats['api_errors'], 0, 10) as $error) {
                $this->output("  - $error\n");
            }
            if (count($this->stats['api_errors']) > 10) {
                $this->output("  ... and " . (count($this->stats['api_errors']) - 10) . " more\n");
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
// ГОЛОВНА ФУНКЦІЯ
// ============================================================================

try {
    $startTime = microtime(true);
    
    echo "╔══════════════════════════════════════════════════════════════╗\n";
    echo "║    MurKir Security - Advanced Cleanup v1.3                   ║\n";
    echo "║    Сумісний з inline_check_lite.php v3.8.13+                 ║\n";
    echo "║    Per-site Redis ізоляція                                   ║\n";
    echo "╚══════════════════════════════════════════════════════════════╝\n";
    echo "Started: " . date('Y-m-d H:i:s') . "\n";
    echo "Mode: " . ($isCLI ? "CLI" : "WEB") . "\n";
    
    if ($forceCleanup) {
        echo "⚠️  FORCE MODE: Видаляються ВСІ блокування незалежно від TTL!\n";
    }
    
    echo "\nSettings:\n";
    echo "  Redis: " . REDIS_HOST . ":" . REDIS_PORT . " (DB " . REDIS_DATABASE . ")\n";
    echo "  API: " . (API_ENABLED ? API_URL : 'Disabled') . "\n";
    echo "  API Method: " . (defined('API_METHOD') ? API_METHOD : 'POST') . "\n";
    echo "  TTL threshold: " . TTL_THRESHOLD . " seconds\n";
    echo "  Cleanup threshold: " . CLEANUP_THRESHOLD . " keys\n";
    echo "  Force cleanup: " . ($forceCleanup ? "YES" : "NO") . "\n";
    echo "  Cleanup legacy: " . (CLEANUP_LEGACY_KEYS ? "YES" : "NO") . "\n\n";
    
    $cleanup = new MurKirCleanup($isWeb, $forceCleanup);
    $cleanup->runFullCleanup();
    
    $duration = microtime(true) - $startTime;
    echo "\n✓ All cleanup operations completed!\n";
    echo "Total duration: " . number_format($duration, 2) . " seconds\n";
    echo "Finished: " . date('Y-m-d H:i:s') . "\n";
    
    if ($isWeb) {
        echo "\n";
        echo "═══════════════════════════════════════════════════════════════\n";
        echo "РЕКОМЕНДАЦІЇ ПО НАЛАШТУВАННЮ CRON:\n";
        echo "═══════════════════════════════════════════════════════════════\n";
        echo "\n# Запускати кожні 5 хвилин\n";
        echo "*/5 * * * * php " . __FILE__ . " >> /var/log/murkir_cleanup.log 2>&1\n";
        echo "\n# Перша очистка після оновлення (видалити старі legacy ключі):\n";
        echo "# php " . __FILE__ . " --force\n";
        echo "═══════════════════════════════════════════════════════════════\n";
    }
    
    exit(0);
    
} catch (Exception $e) {
    echo "\n✗ FATAL ERROR: " . $e->getMessage() . "\n";
    echo $e->getTraceAsString() . "\n";
    exit(1);
}
