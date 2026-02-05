<?php
/**
 * ============================================================================
 * MurKir Security - Advanced Cleanup Script v1.2
 * ============================================================================
 * Сумісний з inline_check_lite.php v3.8.12+
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
 *   8. Оновлення глобальних метрик
 *   9. Перевірка порогів та агресивна очистка
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
define('REDIS_PREFIX', 'bot_protection:');

// API налаштування для iptables (має збігатися з inline_check_lite.php)
define('API_ENABLED', true);
define('API_URL', 'https://blog.dj-x.info/redis-bot_protection/API/iptables.php');  // ЗМІНІТЬ!
define('API_KEY', 'Asd12345');                        // ЗМІНІТЬ!
define('API_METHOD', 'POST');                          // v1.2: 'GET' або 'POST' (POST рекомендовано для IPv6!)
define('API_TIMEOUT', 5);
define('API_USER_AGENT', 'MurKir-Cleanup/1.2');

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
// Можна встановити через CLI: php cleanup.php --force
// Або через WEB: cleanup.php?key=XXX&force=1
define('FORCE_CLEANUP', false);       // За замовчуванням вимкнено

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
    // CLI: php cleanup.php --force
    global $argv;
    if (isset($argv) && in_array('--force', $argv)) {
        $forceCleanup = true;
    }
} else {
    // WEB: cleanup.php?force=1
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
    
    private $stats = array(
        // Блокування
        'blocks_checked' => 0,
        'blocks_expired' => 0,
        'blocks_unblocked' => 0,
        'blocks_api_success' => 0,
        'blocks_api_failed' => 0,
        'api_errors' => array(),
        
        // UA tracking
        'ua_tracking_checked' => 0,
        'ua_tracking_cleaned' => 0,
        
        // rDNS
        'rdns_checked' => 0,
        'rdns_cleaned' => 0,
        
        // No-cookie
        'no_cookie_checked' => 0,
        'no_cookie_cleaned' => 0,
        
        // Whitelist cache
        'whitelist_checked' => 0,
        'whitelist_cleaned' => 0,
        
        // Rate limit
        'rate_limit_checked' => 0,
        'rate_limit_cleaned' => 0,
        
        // JS Challenge stats
        'jsc_stats_checked' => 0,
        'jsc_stats_cleaned' => 0,
        
        // Search engine visits
        'se_visits_checked' => 0,
        'se_visits_cleaned' => 0,
        
        // Метрики
        'metrics_updated' => false,
    );
    
    // v1.1: Режим примусової очистки
    private $forceCleanup = false;
    
    public function __construct($isWeb = false, $forceCleanup = false) {
        $this->isWeb = $isWeb;
        $this->forceCleanup = $forceCleanup;
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
            $this->redis->setOption(Redis::OPT_SERIALIZER, Redis::SERIALIZER_PHP);
            
            $this->output("✓ Connected to Redis (DB " . REDIS_DATABASE . ")\n");
            
        } catch (Exception $e) {
            $this->output("✗ Redis connection failed: " . $e->getMessage() . "\n");
            throw $e;
        }
    }
    
    /**
     * Виклик API для розблокування IP
     * v1.2: Виправлено - додано api=1, підтримка GET/POST, коректна робота з IPv6
     */
    private function unblockViaAPI($ip) {
        if (!API_ENABLED) {
            return array('status' => 'disabled', 'message' => 'API disabled');
        }
        
        // v1.2: Додано api=1 - ОБОВ'ЯЗКОВО для отримання JSON відповіді!
        $params = array(
            'action' => 'unblock',
            'ip' => $ip,
            'api' => 1,              // <-- Це було відсутнє! Без цього API повертає HTML
            'api_key' => API_KEY
        );
        
        // v1.2: Визначаємо метод запиту
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
            CURLOPT_HTTPHEADER => array(
                'Accept: application/json',
                'Cache-Control: no-cache'
            )
        );
        
        if ($method === 'POST') {
            // POST запит - параметри в тілі (безпечніше для IPv6!)
            $curlOptions[CURLOPT_URL] = API_URL;
            $curlOptions[CURLOPT_POST] = true;
            $curlOptions[CURLOPT_POSTFIELDS] = http_build_query($params);
        } else {
            // GET запит - параметри в URL
            $curlOptions[CURLOPT_URL] = API_URL . '?' . http_build_query($params);
        }
        
        curl_setopt_array($ch, $curlOptions);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);
        
        if ($curlError) {
            return array('status' => 'error', 'message' => "CURL: $curlError");
        }
        
        if ($httpCode !== 200) {
            return array('status' => 'error', 'message' => "HTTP $httpCode");
        }
        
        $data = json_decode($response, true);
        
        if (!$data) {
            // v1.2: Покращене повідомлення про помилку
            $preview = substr($response, 0, 100);
            return array('status' => 'error', 'message' => "Invalid JSON. Response: $preview...");
        }
        
        if (isset($data['status'])) {
            if ($data['status'] === 'success' || $data['status'] === 'not_blocked') {
                return array('status' => 'success', 'message' => 'Unblocked');
            }
            return array('status' => 'error', 'message' => isset($data['message']) ? $data['message'] : 'Unknown error');
        }
        
        return array('status' => 'success', 'message' => 'OK');
    }
    
    /**
     * ГОЛОВНИЙ МЕТОД - Запускає всі операції очистки
     */
    public function runFullCleanup() {
        $this->output("\n╔════════════════════════════════════════════════════════════════╗\n");
        $this->output("║        MurKir Security - Full Cleanup v1.0                     ║\n");
        $this->output("║        Сумісний з inline_check_lite.php v3.8.2+                ║\n");
        $this->output("╚════════════════════════════════════════════════════════════════╝\n\n");
        
        // 1. Очистка блокировок
        $this->cleanupExpiredBlocks();
        
        // 2. Очистка UA tracking
        $this->cleanupUATracking();
        
        // 3. Очистка rDNS кешу
        $this->cleanupRDNSCache();
        
        // 4. Очистка no-cookie attempts
        $this->cleanupNoCookieAttempts();
        
        // 5. Очистка whitelist кешу
        $this->cleanupWhitelistCache();
        
        // 6. Очистка rate limit даних
        $this->cleanupRateLimitData();
        
        // 7. Очистка JS Challenge статистики (стара)
        $this->cleanupJSCStats();
        
        // 8. Очистка search engine visits (стара)
        $this->cleanupSearchEngineVisits();
        
        // 9. Оновлення глобальних метрик
        $this->updateGlobalMetrics();
        
        // 10. Перевірка порогів
        $this->checkThresholds();
        
        // Статистика
        $this->printStats();
    }
    
    /**
     * 1. ОЧИСТКА БЛОКИРОВОК З ИСТІКАЮЧИМ TTL
     */
    private function cleanupExpiredBlocks() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("1. CLEANING EXPIRED BLOCKS\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
        
        $blockPatterns = array(
            // UA rotation blocks (обидва формати!)
            array(
                'pattern' => REDIS_PREFIX . 'ua_blocked:*',
                'description' => 'UA Blocks (new format)',
                'api_unblock' => true,
                'ip_from_key' => true,
                'ip_key_prefix' => 'ua_blocked:'  // v1.2: Префікс до IP в ключі
            ),
            // v1.1: Старий формат UA rotation blocks
            array(
                'pattern' => REDIS_PREFIX . 'ua_rotation_blocked:*',
                'description' => 'UA Rotation Blocks (old format)',
                'api_unblock' => true,
                'ip_from_key' => true,
                'ip_key_prefix' => 'ua_rotation_blocked:'
            ),
            // No-cookie blocks
            array(
                'pattern' => REDIS_PREFIX . 'blocked:no_cookie:*',
                'description' => 'No-Cookie Attack Blocks',
                'api_unblock' => true,
                'ip_from_key' => true,
                'ip_key_prefix' => 'blocked:no_cookie:'  // v1.2: Два рівні до IP!
            ),
            // Rate limit blocks (IP в даних)
            array(
                'pattern' => REDIS_PREFIX . 'blocked:*',
                'description' => 'Rate Limit Blocks',
                'api_unblock' => true,
                'ip_from_key' => false,
                'exclude' => array('no_cookie')  // Вже обробили вище
            ),
        );
        
        foreach ($blockPatterns as $config) {
            $this->output("\n→ {$config['description']}\n");
            $this->cleanupBlockPattern($config);
        }
    }
    
    /**
     * Очистка блокировок по паттерну
     */
    private function cleanupBlockPattern($config) {
        $pattern = $config['pattern'];
        $useAPI = $config['api_unblock'];
        $ipFromKey = isset($config['ip_from_key']) ? $config['ip_from_key'] : false;
        $ipKeyPrefix = isset($config['ip_key_prefix']) ? $config['ip_key_prefix'] : '';  // v1.2
        $exclude = isset($config['exclude']) ? $config['exclude'] : array();
        
        $iterator = null;
        $found = 0;
        
        do {
            $keys = $this->redis->scan($iterator, $pattern, BATCH_SIZE);
            
            if ($keys === false) {
                break;
            }
            
            foreach ($keys as $key) {
                // Перевірка виключень
                $skip = false;
                foreach ($exclude as $exc) {
                    if (strpos($key, $exc) !== false) {
                        $skip = true;
                        break;
                    }
                }
                if ($skip) continue;
                
                $this->stats['blocks_checked']++;
                $found++;
                
                $ttl = $this->redis->ttl($key);
                
                // Пропускаємо неіснуючі
                if ($ttl === -2) {
                    continue;
                }
                
                // Перевіряємо чи потрібно очищати
                $shouldCleanup = false;
                
                // v1.1: Примусова очистка - видаляємо ВСЕ
                if ($this->forceCleanup) {
                    $shouldCleanup = true;
                } elseif ($ttl === -1) {
                    // Ключ без TTL - підозрілий
                    $this->output("  ⚠ Key without TTL: " . basename($key) . "\n");
                    $shouldCleanup = true;
                } elseif ($ttl <= TTL_THRESHOLD) {
                    // TTL закінчується
                    $shouldCleanup = true;
                }
                
                if ($shouldCleanup) {
                    $this->stats['blocks_expired']++;
                    
                    // Отримуємо IP
                    $ip = null;
                    
                    if ($ipFromKey && $ipKeyPrefix) {
                        // v1.2: Виправлено для IPv6!
                        // Ключ: bot_protection:ua_blocked:1.2.3.4
                        // Або:  bot_protection:ua_blocked:2a03:3f40:2:e:0:4:0:2
                        // Або:  bot_protection:blocked:no_cookie:2a03:3f40:2:e:0:4:0:2
                        // Використовуємо ip_key_prefix для точного визначення де починається IP
                        
                        $fullPrefix = REDIS_PREFIX . $ipKeyPrefix;  // bot_protection:ua_blocked:
                        if (strpos($key, $fullPrefix) === 0) {
                            $ip = substr($key, strlen($fullPrefix));  // Все після префіксу = IP
                        }
                    } elseif ($ipFromKey) {
                        // Fallback: старий метод (для сумісності)
                        $prefixLen = strlen(REDIS_PREFIX);
                        $withoutPrefix = substr($key, $prefixLen);
                        $firstColon = strpos($withoutPrefix, ':');
                        if ($firstColon !== false) {
                            $ip = substr($withoutPrefix, $firstColon + 1);
                        }
                    } else {
                        // IP в даних
                        $data = $this->redis->get($key);
                        if (is_array($data) && isset($data['ip'])) {
                            $ip = $data['ip'];
                        }
                    }
                    
                    $ttlDisplay = ($ttl === -1) ? "NO TTL" : "{$ttl}s";
                    
                    // Якщо є IP і потрібно API
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
                    
                    // Видаляємо ключ
                    $this->redis->del($key);
                    $this->stats['blocks_unblocked']++;
                }
            }
            
        } while ($iterator > 0);
        
        if ($found === 0) {
            $this->output("  No keys found\n");
        } else {
            $this->output("  Checked: $found keys\n");
        }
    }
    
    /**
     * 2. ОЧИСТКА UA TRACKING
     */
    private function cleanupUATracking() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("2. CLEANING UA TRACKING\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
        
        $pattern = REDIS_PREFIX . 'ua:*';
        $iterator = null;
        $cleaned = 0;
        
        do {
            $keys = $this->redis->scan($iterator, $pattern, BATCH_SIZE);
            
            if ($keys === false) {
                break;
            }
            
            foreach ($keys as $key) {
                $this->stats['ua_tracking_checked']++;
                
                $ttl = $this->redis->ttl($key);
                
                if ($ttl === -2) continue;
                
                // Видаляємо ключі без TTL або зі старими даними
                if ($ttl === -1) {
                    $this->redis->del($key);
                    $cleaned++;
                }
            }
            
        } while ($iterator > 0);
        
        $this->stats['ua_tracking_cleaned'] = $cleaned;
        $this->output("  Cleaned: $cleaned keys\n");
    }
    
    /**
     * 3. ОЧИСТКА rDNS КЕШУ
     */
    private function cleanupRDNSCache() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("3. CLEANING rDNS CACHE\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
        
        $patterns = array(
            REDIS_PREFIX . 'rdns_verified:*',
            REDIS_PREFIX . 'rdns_check_count:*',
        );
        
        $cleaned = 0;
        
        foreach ($patterns as $pattern) {
            $iterator = null;
            
            do {
                $keys = $this->redis->scan($iterator, $pattern, BATCH_SIZE);
                
                if ($keys === false) {
                    break;
                }
                
                foreach ($keys as $key) {
                    $this->stats['rdns_checked']++;
                    
                    $ttl = $this->redis->ttl($key);
                    
                    if ($ttl === -2) continue;
                    
                    if ($ttl === -1) {
                        // Встановлюємо TTL якщо немає
                        $this->redis->expire($key, RDNS_CACHE_TTL);
                        $cleaned++;
                    }
                }
                
            } while ($iterator > 0);
        }
        
        $this->stats['rdns_cleaned'] = $cleaned;
        $this->output("  Fixed TTL for: $cleaned keys\n");
    }
    
    /**
     * 4. ОЧИСТКА NO-COOKIE ATTEMPTS
     */
    private function cleanupNoCookieAttempts() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("4. CLEANING NO-COOKIE ATTEMPTS\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
        
        $pattern = REDIS_PREFIX . 'no_cookie_attempts:*';
        $iterator = null;
        $cleaned = 0;
        
        do {
            $keys = $this->redis->scan($iterator, $pattern, BATCH_SIZE);
            
            if ($keys === false) {
                break;
            }
            
            foreach ($keys as $key) {
                $this->stats['no_cookie_checked']++;
                
                $ttl = $this->redis->ttl($key);
                
                if ($ttl === -2) continue;
                
                if ($ttl === -1) {
                    $this->redis->del($key);
                    $cleaned++;
                }
            }
            
        } while ($iterator > 0);
        
        $this->stats['no_cookie_cleaned'] = $cleaned;
        $this->output("  Cleaned: $cleaned keys\n");
    }
    
    /**
     * 5. ОЧИСТКА WHITELIST КЕШУ
     */
    private function cleanupWhitelistCache() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("5. CLEANING WHITELIST CACHE\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
        
        $pattern = REDIS_PREFIX . 'ip_whitelist:*';
        $iterator = null;
        $cleaned = 0;
        
        do {
            $keys = $this->redis->scan($iterator, $pattern, BATCH_SIZE);
            
            if ($keys === false) {
                break;
            }
            
            foreach ($keys as $key) {
                $this->stats['whitelist_checked']++;
                
                $ttl = $this->redis->ttl($key);
                
                if ($ttl === -2) continue;
                
                // Видаляємо негативні кеші (value = '0') що старші за поріг
                if ($ttl === -1) {
                    $value = $this->redis->get($key);
                    if ($value === '0' || $value === 0) {
                        $this->redis->del($key);
                        $cleaned++;
                    }
                }
            }
            
        } while ($iterator > 0);
        
        $this->stats['whitelist_cleaned'] = $cleaned;
        $this->output("  Cleaned negative cache: $cleaned keys\n");
    }
    
    /**
     * 6. ОЧИСТКА RATE LIMIT ДАНИХ
     */
    private function cleanupRateLimitData() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("6. CLEANING RATE LIMIT DATA\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
        
        $pattern = REDIS_PREFIX . 'rate_limit:*';
        $iterator = null;
        $cleaned = 0;
        
        do {
            $keys = $this->redis->scan($iterator, $pattern, BATCH_SIZE);
            
            if ($keys === false) {
                break;
            }
            
            foreach ($keys as $key) {
                $this->stats['rate_limit_checked']++;
                
                $ttl = $this->redis->ttl($key);
                
                if ($ttl === -2) continue;
                
                if ($ttl === -1) {
                    $this->redis->del($key);
                    $cleaned++;
                }
            }
            
        } while ($iterator > 0);
        
        $this->stats['rate_limit_cleaned'] = $cleaned;
        $this->output("  Cleaned: $cleaned keys\n");
    }
    
    /**
     * 7. ОЧИСТКА СТАРОЇ JS CHALLENGE СТАТИСТИКИ
     */
    private function cleanupJSCStats() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("7. CLEANING OLD JSC STATS\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
        
        $currentDate = date('Y-m-d');
        $threshold = date('Y-m-d', strtotime('-7 days'));
        
        $patterns = array(
            REDIS_PREFIX . 'jsc_stats:daily:*',
            REDIS_PREFIX . 'jsc_stats:hourly:*',
        );
        
        // v1.1: В режимі force також очищаємо total лічильники
        if ($this->forceCleanup) {
            $patterns[] = REDIS_PREFIX . 'jsc_stats:total:*';
            $patterns[] = REDIS_PREFIX . 'jsc_stats:log:*';
            $this->output("  ⚠ FORCE MODE: очищаємо також total та log\n");
        }
        
        $cleaned = 0;
        
        foreach ($patterns as $pattern) {
            $iterator = null;
            
            do {
                $keys = $this->redis->scan($iterator, $pattern, BATCH_SIZE);
                
                if ($keys === false) {
                    break;
                }
                
                foreach ($keys as $key) {
                    $this->stats['jsc_stats_checked']++;
                    
                    // v1.1: В режимі force видаляємо все
                    if ($this->forceCleanup) {
                        $this->redis->del($key);
                        $cleaned++;
                        continue;
                    }
                    
                    // Витягуємо дату з ключа
                    if (preg_match('/(\d{4}-\d{2}-\d{2})/', $key, $matches)) {
                        $keyDate = $matches[1];
                        
                        if ($keyDate < $threshold) {
                            $this->redis->del($key);
                            $cleaned++;
                        }
                    }
                }
                
            } while ($iterator > 0);
        }
        
        $this->stats['jsc_stats_cleaned'] = $cleaned;
        $this->output("  Cleaned stats older than $threshold: $cleaned keys\n");
    }
    
    /**
     * 8. ОЧИСТКА СТАРИХ SEARCH ENGINE VISITS
     */
    private function cleanupSearchEngineVisits() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("8. CLEANING OLD SEARCH ENGINE VISITS\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
        
        $threshold = date('Y-m-d', strtotime('-30 days'));
        
        $patterns = array(
            REDIS_PREFIX . 'search_engine_visits:daily:*',
            REDIS_PREFIX . 'search_engine_visits:host:*',
        );
        
        $cleaned = 0;
        
        foreach ($patterns as $pattern) {
            $iterator = null;
            
            do {
                $keys = $this->redis->scan($iterator, $pattern, BATCH_SIZE);
                
                if ($keys === false) {
                    break;
                }
                
                foreach ($keys as $key) {
                    $this->stats['se_visits_checked']++;
                    
                    if (preg_match('/(\d{4}-\d{2}-\d{2})/', $key, $matches)) {
                        $keyDate = $matches[1];
                        
                        if ($keyDate < $threshold) {
                            $this->redis->del($key);
                            $cleaned++;
                        }
                    }
                }
                
            } while ($iterator > 0);
        }
        
        $this->stats['se_visits_cleaned'] = $cleaned;
        $this->output("  Cleaned visits older than $threshold: $cleaned keys\n");
    }
    
    /**
     * 9. ОНОВЛЕННЯ ГЛОБАЛЬНИХ МЕТРИК
     */
    private function updateGlobalMetrics() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("9. UPDATING GLOBAL METRICS\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
        
        $metrics = array(
            'ua_blocked' => 0,
            'no_cookie_blocked' => 0,
            'rate_limit_blocked' => 0,
            'whitelist_cached' => 0,
            'last_cleanup' => date('Y-m-d H:i:s'),
        );
        
        // Підрахунок ua_blocked
        $keys = $this->redis->keys(REDIS_PREFIX . 'ua_blocked:*');
        $metrics['ua_blocked'] = $keys ? count($keys) : 0;
        
        // Підрахунок no_cookie blocked
        $keys = $this->redis->keys(REDIS_PREFIX . 'blocked:no_cookie:*');
        $metrics['no_cookie_blocked'] = $keys ? count($keys) : 0;
        
        // Підрахунок rate_limit blocked
        $keys = $this->redis->keys(REDIS_PREFIX . 'blocked:*');
        $metrics['rate_limit_blocked'] = $keys ? count($keys) - $metrics['no_cookie_blocked'] : 0;
        
        // Підрахунок whitelist cached
        $keys = $this->redis->keys(REDIS_PREFIX . 'ip_whitelist:*');
        $metrics['whitelist_cached'] = $keys ? count($keys) : 0;
        
        // Зберігаємо метрики
        $this->redis->set(REDIS_PREFIX . 'global:cleanup_metrics', $metrics);
        
        $this->stats['metrics_updated'] = true;
        
        $this->output("  UA Blocked IPs:        {$metrics['ua_blocked']}\n");
        $this->output("  No-Cookie Blocked IPs: {$metrics['no_cookie_blocked']}\n");
        $this->output("  Rate Limit Blocked:    {$metrics['rate_limit_blocked']}\n");
        $this->output("  Whitelist Cached:      {$metrics['whitelist_cached']}\n");
    }
    
    /**
     * 10. ПЕРЕВІРКА ПОРОГІВ ТА АГРЕСИВНА ОЧИСТКА
     */
    private function checkThresholds() {
        $this->output("\n════════════════════════════════════════════════════════════════\n");
        $this->output("10. CHECKING THRESHOLDS\n");
        $this->output("════════════════════════════════════════════════════════════════\n");
        
        // Підрахунок всіх ключів bot_protection
        $allKeys = $this->redis->keys(REDIS_PREFIX . '*');
        $totalKeys = $allKeys ? count($allKeys) : 0;
        
        $this->output("  Total keys: $totalKeys / " . CLEANUP_THRESHOLD . "\n");
        
        if ($totalKeys > CLEANUP_THRESHOLD) {
            $this->output("  ⚠ THRESHOLD EXCEEDED! Running aggressive cleanup...\n");
            $this->performAggressiveCleanup();
        } else {
            $this->output("  ✓ Within limits\n");
        }
    }
    
    /**
     * АГРЕСИВНА ОЧИСТКА
     */
    private function performAggressiveCleanup() {
        $cleaned = 0;
        $startTime = microtime(true);
        
        // Видаляємо всі ключі без TTL
        $patterns = array(
            REDIS_PREFIX . 'ua:*',
            REDIS_PREFIX . 'rate_limit:*',
            REDIS_PREFIX . 'no_cookie_attempts:*',
        );
        
        foreach ($patterns as $pattern) {
            $iterator = null;
            
            do {
                // Перевіряємо час
                if ((microtime(true) - $startTime) * 1000 > MAX_CLEANUP_TIME_MS) {
                    $this->output("  Time limit reached\n");
                    break 2;
                }
                
                $keys = $this->redis->scan($iterator, $pattern, BATCH_SIZE);
                
                if ($keys === false) {
                    break;
                }
                
                foreach ($keys as $key) {
                    $ttl = $this->redis->ttl($key);
                    
                    if ($ttl === -1) {
                        $this->redis->del($key);
                        $cleaned++;
                    }
                }
                
            } while ($iterator > 0);
        }
        
        $this->output("  Aggressively cleaned: $cleaned keys\n");
    }
    
    /**
     * ВИВІД СТАТИСТИКИ
     */
    private function printStats() {
        $duration = microtime(true) - $this->startTime;
        
        $this->output("\n");
        $this->output("╔════════════════════════════════════════════════════════════════╗\n");
        $this->output("║              CLEANUP STATISTICS                                ║\n");
        $this->output("╚════════════════════════════════════════════════════════════════╝\n\n");
        
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
    echo "║    MurKir Security - Advanced Cleanup v1.2                   ║\n";
    echo "║    Сумісний з inline_check_lite.php v3.8.12+                 ║\n";
    echo "╚══════════════════════════════════════════════════════════════╝\n";
    echo "Started: " . date('Y-m-d H:i:s') . "\n";
    echo "Mode: " . ($isCLI ? "CLI" : "WEB") . "\n";
    
    // v1.1: Показуємо режим очистки
    if ($forceCleanup) {
        echo "⚠️  FORCE MODE: Видаляються ВСІ блокування незалежно від TTL!\n";
    }
    
    echo "\nSettings:\n";
    echo "  Redis: " . REDIS_HOST . ":" . REDIS_PORT . " (DB " . REDIS_DATABASE . ")\n";
    echo "  API: " . (API_ENABLED ? API_URL : 'Disabled') . "\n";
    echo "  API Method: " . (defined('API_METHOD') ? API_METHOD : 'POST') . "\n";
    echo "  TTL threshold: " . TTL_THRESHOLD . " seconds\n";
    echo "  Cleanup threshold: " . CLEANUP_THRESHOLD . " keys\n";
    echo "  Force cleanup: " . ($forceCleanup ? "YES" : "NO") . "\n\n";
    
    // Запуск очистки
    $cleanup = new MurKirCleanup($isWeb, $forceCleanup);
    $cleanup->runFullCleanup();
    
    // Результат
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
        echo "═══════════════════════════════════════════════════════════════\n";
    }
    
    exit(0);
    
} catch (Exception $e) {
    echo "\n✗ FATAL ERROR: " . $e->getMessage() . "\n";
    echo $e->getTraceAsString() . "\n";
    exit(1);
}
