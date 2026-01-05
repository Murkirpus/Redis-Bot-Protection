<?php
/**
 * ============================================================================
 * СПРОЩЕНА ВЕРСІЯ - Redis Bot Protection (User Tracking + Rate Limit + Burst)
 * ============================================================================
 * 
 * ВЕРСІЯ 3.3.1 - IPv6 CIDR FIX (2026-01-05)
 * 
 * ВИПРАВЛЕННЯ v3.3.1:
 * ✅ Виправлено помилку "Invalid IPv4 CIDR mask" для IPv6 діапазонів
 * ✅ Функція ipInRange() тепер коректно обробляє різні типи IP та CIDR
 * ✅ IPv4 користувачі більше не перевіряються проти IPv6 діапазонів
 * 
 * НОВЕ v3.3.0:
 * ✅ UA Rotation Detection - блокує ботів що часто міняють User-Agent!
 * ✅ Трекінг унікальних UA на одному IP
 * ✅ Захист від User-Agent rotation (класична тактика ботів)
 * ✅ Ліміти: 10 унікальних UA за 5 хв, 20 за годину
 * ✅ Окреме блокування на 2 години (жорсткіше за звичайний rate limit)
 * ✅ Не впливає на легітимні офіси з багатьма користувачами
 * 
 * ЯК ПРАЦЮЄ UA ROTATION:
 * - Трекаємо унікальні User-Agent на кожному IP
 * - Офіс з 50 людьми = 50 різних UA протягом дня = OK ✅
 * - Бот з 50 різних UA за 5 хвилин = ПІДОЗРІЛО ❌
 * - Блокування на 2 години + API iptables
 * 
 * КРИТИЧНІ ВИПРАВЛЕННЯ v3.2.1:
 * ✅ Виправлено Rate Limit - тепер працює коректно!
 * ✅ array_values після array_filter - правильна серіалізація в Redis
 * ✅ Стабільний User ID - browser hash замість random
 * ✅ Перевірка типів даних при десеріалізації з Redis
 * ✅ Детальне debug логування для Rate Limit перевірок
 * 
 * НОВЕ v3.2.0:
 * ✅ Блокування по користувачу (browser hash + cookie), а не по IP!
 * ✅ Cookie для ідентифікації користувачів
 * ✅ Browser fingerprint (User-Agent, Accept headers)
 * ✅ Cookie multiplier - збільшені ліміти для користувачів з cookie
 * ✅ Один IP може мати багато користувачів (не блокує весь офіс)
 * 
 * ЩО ВКЛЮЧЕНО:
 * ✅ UA Rotation Detection (НОВЕ!)
 * ✅ User tracking (browser hash + cookie)
 * ✅ Rate Limit з cookie multiplier
 * ✅ Burst Detection
 * ✅ rDNS верифікація
 * ✅ API блокування через iptables
 * ✅ 502 помилка для порушників
 * ✅ Whitelist IP для пошукових систем
 * 
 * ВИКОРИСТАННЯ:
 * require_once 'inline_check_lite.php';
 * // Захист запускається автоматично!
 * 
 * НАЛАШТУВАННЯ UA ROTATION:
 * $protection->updateUARotationSettings([
 *     'enabled' => true,
 *     'max_unique_ua_per_5min' => 10,  // Макс 10 різних UA за 5 хв
 *     'max_unique_ua_per_hour' => 20,  // Макс 20 різних UA за годину
 * ]);
 * 
 * ============================================================================
 */

class SimpleBotProtection {
    private $redis;
    private $redisHost = '127.0.0.1';
    private $redisPort = 6379;
    private $redisPassword = null; // Встановіть пароль якщо потрібно
    private $redisDB = 1;
    private $redisPrefix = 'bot_protection:';
    private $rdnsPrefix = 'rdns:';
    
    // Налаштування debug
    private $debugMode = false;  // Встановіть true для детального логування
    
    // Налаштування Rate Limit
    private $rateLimitSettings = array(
        'max_requests_per_minute' => 60,    // Максимум запитів за хвилину
        'max_requests_per_5min' => 200,     // Максимум запитів за 5 хвилин
        'max_requests_per_hour' => 500,     // Максимум запитів за годину
        'burst_threshold' => 20,             // Поріг для burst (запитів за 10 сек)
        'block_duration' => 3600,            // Час блокування (1 година)
        'cookie_multiplier' => 1.25,          // Множник лімітів для користувачів з cookie
        'track_by_user' => true,             // Трекати по користувачу (hash+cookie), а не по IP
    );
    
    // Налаштування UA Rotation Detection (захист від ботів що міняють User-Agent)
    private $uaRotationSettings = array(
        'enabled' => true,                   // Увімкнути захист від UA rotation
        'max_unique_ua_per_5min' => 10,      // Макс унікальних UA за 5 хв з одного IP
        'max_unique_ua_per_hour' => 20,      // Макс унікальних UA за годину з одного IP
        'window_5min' => 300,                // Вікно перевірки 5 хвилин
        'window_hour' => 3600,               // Вікно перевірки 1 година
        'block_duration' => 7200,            // Блокування на 2 години (жорсткіше)
    );
    
    // Налаштування Cookie
    private $cookieSettings = array(
        'name' => 'bot_protection_uid',      // Ім'я cookie
        'lifetime' => 2592000,               // 30 днів (86400 * 30)
        'path' => '/',
        'secure' => false,                   // Встановіть true для HTTPS
        'httponly' => true,
        'samesite' => 'Lax',
    );
    
    // Налаштування rDNS
    private $rdnsSettings = array(
        'max_rdns_per_minute' => 60,        // Максимум rDNS перевірок за хвилину
        'rdns_cache_ttl' => 1800,           // Кеш на 30 хвилин
        'rdns_negative_cache_ttl' => 300,   // Кеш негативних результатів 5 хвилин
        'rdns_on_limit_action' => 'skip',   // 'skip' або 'block' при перевищенні
    );
    
    // Налаштування API для блокування через iptables
    private $apiSettings = array(
        'enabled' => false,                 // Увімкнути/вимкнути API блокування
        'url' => 'https://mysite.com/redis-bot_protection/API/iptables.php',
        'api_key' => '123456',   // API ключ
        'timeout' => 5,                     // Таймаут запиту (секунди)
        'block_on_redis' => true,           // Блокувати в Redis (локально)
        'block_on_api' => true,             // Блокувати через API (iptables)
        'auto_unblock' => true,             // Автоматично розблокувати через API
        'retry_on_failure' => 2,            // Кількість спроб при помилці
        'log_api_errors' => true,           // Логувати помилки API
        'user_agent' => 'BotProtection/3.0',
        'verify_ssl' => true,               // Перевіряти SSL сертифікат
    );
    
    // Пошукові системи з User-Agent паттернами та rDNS доменами
    private $searchEngines = array(
        'googlebot' => array(
            'user_agent_patterns' => array('googlebot', 'google'),
            'rdns_patterns' => array('.googlebot.com', '.google.com'),
            'ip_ranges' => array(
                '66.249.64.0/19', '66.249.88.0/22', '66.249.92.0/24',
                '2001:4860:4801::/48', '2001:4860:4802::/48',
            )
        ),
        'yandexbot' => array(
            'user_agent_patterns' => array('yandex'),
            'rdns_patterns' => array('.yandex.ru', '.yandex.net', '.yandex.com'),
            'ip_ranges' => array(
                '5.255.253.0/24', '5.255.255.0/24', '37.9.64.0/18',
                '77.88.0.0/18', '95.108.128.0/17', '100.43.80.0/22',
                '2a02:6b8::/32',
            )
        ),
        'bingbot' => array(
            'user_agent_patterns' => array('bingbot', 'msnbot'),
            'rdns_patterns' => array('.search.msn.com'),
            'ip_ranges' => array(
                '40.77.167.0/24', '157.55.39.0/24', '207.46.13.0/24',
                '2620:1ec:c11::/48',
            )
        ),
        'duckduckbot' => array(
            'user_agent_patterns' => array('duckduckbot'),
            'rdns_patterns' => array('.duckduckgo.com'),
            'ip_ranges' => array(
                '20.191.45.0/24', '40.88.21.0/24', '52.142.0.0/16',
            )
        ),
        'baiduspider' => array(
            'user_agent_patterns' => array('baiduspider'),
            'rdns_patterns' => array('.baidu.com', '.baidu.jp'),
            'ip_ranges' => array(
                '123.125.71.0/24', '220.181.108.0/24', '180.76.0.0/16',
            )
        ),
        'facebookbot' => array(
            'user_agent_patterns' => array('facebookexternalhit', 'facebookcatalog'),
            'rdns_patterns' => array('.facebook.com', '.fbsv.net'),
            'skip_forward_verification' => true,
            'ip_ranges' => array(
                '31.13.24.0/21', '31.13.64.0/18', '66.220.144.0/20',
                '69.63.176.0/20', '173.252.64.0/18', '2a03:2880::/32',
            )
        ),
    );
    
    public function __construct() {
        $this->connectRedis();
    }
    
    /**
     * Підключення до Redis
     */
    private function connectRedis() {
        try {
            $this->redis = new Redis();
            $this->redis->connect($this->redisHost, $this->redisPort, 1);
            
            if ($this->redisPassword) {
                $this->redis->auth($this->redisPassword);
            }
            
            $this->redis->select($this->redisDB);
            $this->redis->setOption(Redis::OPT_SERIALIZER, Redis::SERIALIZER_PHP);
            
        } catch (Exception $e) {
            error_log("Redis connection failed: " . $e->getMessage());
            $this->redis = null;
        }
    }
    
    /**
     * Головний метод захисту
     */
    public function protect() {
        try {
            if (!$this->redis) {
                error_log("BOT PROTECTION: Redis not available, protection disabled");
                return; // Якщо Redis недоступний - пропускаємо
            }
            
            $ip = $this->getClientIP();
            $userAgent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
            
            // Debug logging (тільки якщо debugMode = true)
            if ($this->debugMode) {
                error_log("BOT PROTECTION: Checking IP=$ip, UA=" . substr($userAgent, 0, 50));
            }
            
            // Перевірка IP Whitelist (швидка перевірка)
            if ($this->isSearchEngineByIP($ip, $userAgent)) {
                if ($this->debugMode) {
                    error_log("BOT PROTECTION: IP whitelisted, allowing request");
                }
                return; // Пошукові системи пропускаємо
            }
            
            // rDNS верифікація (якщо не пройшов IP whitelist)
            if ($this->verifySearchEngineRDNS($ip, $userAgent)) {
                if ($this->debugMode) {
                    error_log("BOT PROTECTION: rDNS verified, allowing request");
                }
                return; // Верифікований пошуковий бот
            }
            
            // Перевірка UA Rotation (боти що часто міняють User-Agent)
            if ($this->checkUserAgentRotation($ip)) {
                error_log("BOT PROTECTION: UA rotation detected, blocking IP=$ip");
                $this->show502Error();
            }
            
            // Перевірка Rate Limit і Burst
            if ($this->checkRateLimit($ip)) {
                error_log("BOT PROTECTION: Rate limit exceeded, blocking IP=$ip");
                $this->show502Error();
            }
            
            if ($this->debugMode) {
                error_log("BOT PROTECTION: Request allowed for IP=$ip");
            }
            
        } catch (Exception $e) {
            error_log("BOT PROTECTION ERROR: " . $e->getMessage() . " at line " . $e->getLine());
            // При помилці - пропускаємо запит (fail-open для безпеки)
            return;
        }
    }
    
    /**
     * Перевірка чи IP належить пошуковій системі (IP Whitelist)
     */
    private function isSearchEngineByIP($ip, $userAgent = '') {
        // Спочатку визначаємо пошуковик по User-Agent
        $detectedEngine = null;
        $engineConfig = null;
        
        if (!empty($userAgent)) {
            foreach ($this->searchEngines as $engine => $config) {
                foreach ($config['user_agent_patterns'] as $pattern) {
                    if (stripos($userAgent, $pattern) !== false) {
                        $detectedEngine = $engine;
                        $engineConfig = $config;
                        break 2;
                    }
                }
            }
        }
        
        // Якщо знайшли пошуковик по UA, перевіряємо його IP ranges
        if ($detectedEngine && $engineConfig && !empty($engineConfig['ip_ranges'])) {
            foreach ($engineConfig['ip_ranges'] as $cidr) {
                if ($this->ipInRange($ip, $cidr)) {
                    error_log("Search engine verified by IP: $detectedEngine ($ip)");
                    return true;
                }
            }
        }
        
        // Fallback: перевіряємо всі IP ranges (якщо UA не співпав або відсутній)
        foreach ($this->searchEngines as $engine => $config) {
            if (!empty($config['ip_ranges'])) {
                foreach ($config['ip_ranges'] as $cidr) {
                    if ($this->ipInRange($ip, $cidr)) {
                        error_log("Search engine verified by IP (fallback): $engine ($ip)");
                        return true;
                    }
                }
            }
        }
        
        return false;
    }
    
    /**
     * rDNS верифікація пошукових ботів
     */
    private function verifySearchEngineRDNS($ip, $userAgent = '') {
        // Визначаємо пошуковик по User-Agent
        $engineConfig = null;
        
        if (!empty($userAgent)) {
            foreach ($this->searchEngines as $engine => $config) {
                foreach ($config['user_agent_patterns'] as $pattern) {
                    if (stripos($userAgent, $pattern) !== false) {
                        $engineConfig = $config;
                        break 2;
                    }
                }
            }
        }
        
        // Якщо не знайшли конфіг - пропускаємо rDNS
        if (!$engineConfig || empty($engineConfig['rdns_patterns'])) {
            return false;
        }
        
        return $this->performRDNSVerification($ip, $engineConfig);
    }
    
    /**
     * Виконання rDNS верифікації
     */
    private function performRDNSVerification($ip, $engineConfig) {
        try {
            $cacheKey = $this->redisPrefix . $this->rdnsPrefix . 'cache:' . hash('md5', $ip);
            
            // Перевірка кешу
            $cached = $this->redis->get($cacheKey);
            if ($cached !== false) {
                return $cached === '1';
            }
            
            // Перевірка rate limit для rDNS
            if (!$this->checkRDNSRateLimit()) {
                if ($this->rdnsSettings['rdns_on_limit_action'] === 'block') {
                    error_log("rDNS rate limit exceeded, blocking IP: $ip");
                    return false;
                }
                // 'skip' - пропускаємо перевірку
                error_log("rDNS rate limit exceeded, skipping verification for: $ip");
                return false;
            }
            
            $verified = false;
            $allowedPatterns = $engineConfig['rdns_patterns'];
            $skipForward = isset($engineConfig['skip_forward_verification']) ? $engineConfig['skip_forward_verification'] : false;
            
            // Reverse DNS lookup
            $hostname = $this->getHostnameWithTimeout($ip, 2);
            
            if ($hostname && $hostname !== $ip) {
                // Перевірка hostname по паттернах
                $hostnameMatches = false;
                foreach ($allowedPatterns as $pattern) {
                    if ($this->matchesDomainPattern($hostname, $pattern)) {
                        $hostnameMatches = true;
                        break;
                    }
                }
                
                if ($hostnameMatches) {
                    if ($skipForward) {
                        // Пропускаємо forward lookup (для Facebook тощо)
                        $verified = true;
                        error_log("rDNS verified (forward skip): $ip -> $hostname");
                    } else {
                        // Forward lookup для перевірки
                        $forwardIPs = $this->getIPsWithTimeout($hostname, 2);
                        if ($forwardIPs && in_array($ip, $forwardIPs)) {
                            $verified = true;
                            error_log("rDNS verified: $ip -> $hostname");
                        }
                    }
                }
            }
            
            // Кешування результату
            $cacheTTL = $verified ? 
                $this->rdnsSettings['rdns_cache_ttl'] : 
                $this->rdnsSettings['rdns_negative_cache_ttl'];
            
            $this->redis->setex($cacheKey, $cacheTTL, $verified ? '1' : '0');
            
            return $verified;
            
        } catch (Exception $e) {
            error_log("Error in rDNS verification: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Перевірка rate limit для rDNS
     */
    private function checkRDNSRateLimit() {
        try {
            $currentMinute = floor(time() / 60);
            $rateLimitKey = $this->redisPrefix . $this->rdnsPrefix . 'ratelimit:' . $currentMinute;
            
            $currentCount = $this->redis->get($rateLimitKey);
            
            if ($currentCount === false) {
                $this->redis->setex($rateLimitKey, 120, 1);
                return true;
            }
            
            $currentCount = (int)$currentCount;
            
            if ($currentCount >= $this->rdnsSettings['max_rdns_per_minute']) {
                return false;
            }
            
            $this->redis->incr($rateLimitKey);
            return true;
            
        } catch (Exception $e) {
            error_log("Error in checkRDNSRateLimit: " . $e->getMessage());
            return true; // При помилці дозволяємо
        }
    }
    
    /**
     * Отримання hostname з timeout
     */
    private function getHostnameWithTimeout($ip, $timeoutSec = 2) {
        $originalTimeout = ini_get('default_socket_timeout');
        ini_set('default_socket_timeout', $timeoutSec);
        
        try {
            $hostname = @gethostbyaddr($ip);
            ini_set('default_socket_timeout', $originalTimeout);
            return ($hostname !== $ip) ? $hostname : false;
        } catch (Exception $e) {
            ini_set('default_socket_timeout', $originalTimeout);
            return false;
        }
    }
    
    /**
     * Отримання IP адрес з hostname (forward lookup)
     */
    private function getIPsWithTimeout($hostname, $timeoutSec = 2) {
        $originalTimeout = ini_get('default_socket_timeout');
        ini_set('default_socket_timeout', $timeoutSec);
        
        $allIPs = array();
        
        try {
            // IPv4
            $ipv4List = @gethostbynamel($hostname);
            if ($ipv4List) {
                $allIPs = array_merge($allIPs, $ipv4List);
            }
            
            // IPv6
            if (function_exists('dns_get_record')) {
                $records = @dns_get_record($hostname, DNS_AAAA);
                if ($records) {
                    foreach ($records as $record) {
                        if (isset($record['ipv6'])) {
                            $allIPs[] = $record['ipv6'];
                        }
                    }
                }
            }
            
            ini_set('default_socket_timeout', $originalTimeout);
            return array_unique($allIPs);
            
        } catch (Exception $e) {
            ini_set('default_socket_timeout', $originalTimeout);
            return array();
        }
    }
    
    /**
     * Перевірка чи hostname відповідає паттерну
     */
    private function matchesDomainPattern($hostname, $pattern) {
        $hostname = strtolower(trim($hostname));
        $pattern = strtolower(trim($pattern));
        
        if ($hostname === $pattern) {
            return true;
        }
        
        // Паттерн починається з крапки (.googlebot.com)
        if (strpos($pattern, '.') === 0) {
            return substr($hostname, -strlen($pattern)) === $pattern;
        }
        
        // Додаємо крапку до паттерну
        $fullPattern = '.' . $pattern;
        return substr($hostname, -strlen($fullPattern)) === $fullPattern;
    }
    
    /**
     * Генерація хешу браузера (fingerprint)
     */
    private function generateBrowserHash() {
        $userAgent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
        $acceptLanguage = isset($_SERVER['HTTP_ACCEPT_LANGUAGE']) ? $_SERVER['HTTP_ACCEPT_LANGUAGE'] : '';
        $acceptEncoding = isset($_SERVER['HTTP_ACCEPT_ENCODING']) ? $_SERVER['HTTP_ACCEPT_ENCODING'] : '';
        $accept = isset($_SERVER['HTTP_ACCEPT']) ? $_SERVER['HTTP_ACCEPT'] : '';
        
        // Створюємо стабільний відбиток браузера
        $fingerprint = implode('|', array(
            $userAgent,
            $acceptLanguage,
            $acceptEncoding,
            $accept
        ));
        
        return hash('sha256', $fingerprint);
    }
    
    /**
     * Отримання Cookie користувача
     */
    private function getUserCookie() {
        return isset($_COOKIE[$this->cookieSettings['name']]) ? $_COOKIE[$this->cookieSettings['name']] : null;
    }
    
    /**
     * Встановлення Cookie користувача
     */
    private function setUserCookie($value) {
        $options = array(
            'expires' => time() + $this->cookieSettings['lifetime'],
            'path' => $this->cookieSettings['path'],
            'secure' => $this->cookieSettings['secure'],
            'httponly' => $this->cookieSettings['httponly'],
            'samesite' => $this->cookieSettings['samesite']
        );
        
        setcookie($this->cookieSettings['name'], $value, $options);
    }
    
    /**
     * Генерація унікального ідентифікатора користувача
     */
    private function generateUserIdentifier() {
        $ip = $this->getClientIP();
        $browserHash = $this->generateBrowserHash();
        $cookie = $this->getUserCookie();
        
        if ($this->rateLimitSettings['track_by_user']) {
            // Трекаємо по користувачу (браузер + cookie)
            if ($cookie) {
                // Є cookie - використовуємо його
                if ($this->debugMode) {
                    error_log("USER ID: Using cookie: " . substr($cookie, 0, 16));
                }
                return 'user:' . $cookie;
            } else {
                // Немає cookie - використовуємо browser hash як стабільний ID
                // Це забезпечує що поки cookie не встановиться, ID залишається сталим
                $userId = 'user:' . substr($browserHash, 0, 32);
                
                // Спробуємо встановити cookie для майбутніх запитів
                // Використовуємо browser hash + timestamp щоб зробити унікальним
                $newCookie = substr($browserHash, 0, 16) . '_' . dechex(time());
                $this->setUserCookie($newCookie);
                
                if ($this->debugMode) {
                    error_log("USER ID: No cookie, using browser hash: " . substr($userId, 0, 30) . ", setting cookie: " . substr($newCookie, 0, 20));
                }
                
                return $userId;
            }
        } else {
            // Старий режим - трекаємо тільки по IP
            return 'ip:' . $ip;
        }
    }
    
    /**
     * Перевірка чи користувач має валідний cookie
     */
    private function hasValidCookie() {
        return $this->getUserCookie() !== null;
    }
    
    /**
     * Отримання інформації про користувача для логування
     */
    private function getUserInfo() {
        $cookie = $this->getUserCookie();
        return array(
            'ip' => $this->getClientIP(),
            'browser_hash' => substr($this->generateBrowserHash(), 0, 8),
            'has_cookie' => $this->hasValidCookie(),
            'cookie_id' => $cookie ? substr($cookie, 0, 8) : null,
            'user_id' => $this->generateUserIdentifier()
        );
    }
    
    /**
     * Перевірка UA Rotation (боти що часто міняють User-Agent)
     * @return bool true якщо виявлено підозрілу ротацію UA
     */
    private function checkUserAgentRotation($ip) {
        if (!$this->uaRotationSettings['enabled']) {
            return false;
        }
        
        $now = time();
        $userAgent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : 'unknown';
        $uaHash = hash('md5', $userAgent);
        
        // Ключі для Redis
        $key5min = $this->redisPrefix . 'ua_rotation_5min:' . $ip;
        $keyHour = $this->redisPrefix . 'ua_rotation_hour:' . $ip;
        $blockKey = $this->redisPrefix . 'ua_rotation_blocked:' . $ip;
        
        // Перевірка чи IP вже заблокований за UA rotation
        if ($this->redis->exists($blockKey)) {
            if ($this->debugMode) {
                error_log("UA ROTATION: IP already blocked: $ip");
            }
            return true;
        }
        
        // Отримання даних про UA за 5 хвилин
        $data5min = $this->redis->get($key5min);
        $uniqueUA5min = $data5min && is_array($data5min) ? $data5min : array();
        
        // Отримання даних про UA за годину
        $dataHour = $this->redis->get($keyHour);
        $uniqueUAHour = $dataHour && is_array($dataHour) ? $dataHour : array();
        
        // Очищення старих записів (структура: [uaHash => timestamp])
        $window5min = $this->uaRotationSettings['window_5min'];
        $windowHour = $this->uaRotationSettings['window_hour'];
        
        $filtered5min = array();
        foreach ($uniqueUA5min as $hash => $t) {
            if (($now - $t) < $window5min) {
                $filtered5min[$hash] = $t;
            }
        }
        $uniqueUA5min = $filtered5min;
        
        $filteredHour = array();
        foreach ($uniqueUAHour as $hash => $t) {
            if (($now - $t) < $windowHour) {
                $filteredHour[$hash] = $t;
            }
        }
        $uniqueUAHour = $filteredHour;
        
        // Додавання поточного UA
        $uniqueUA5min[$uaHash] = $now;
        $uniqueUAHour[$uaHash] = $now;
        
        $count5min = count($uniqueUA5min);
        $countHour = count($uniqueUAHour);
        
        // Debug logging
        if ($this->debugMode) {
            error_log(sprintf(
                "UA ROTATION CHECK: IP=%s, unique_ua_5min=%d/%d, unique_ua_hour=%d/%d, current_ua=%s",
                $ip,
                $count5min,
                $this->uaRotationSettings['max_unique_ua_per_5min'],
                $countHour,
                $this->uaRotationSettings['max_unique_ua_per_hour'],
                substr($userAgent, 0, 50)
            ));
        }
        
        // Збереження даних
        $this->redis->setex($key5min, $this->uaRotationSettings['window_5min'], $uniqueUA5min);
        $this->redis->setex($keyHour, $this->uaRotationSettings['window_hour'], $uniqueUAHour);
        
        // Перевірка лімітів
        $violations = array();
        
        if ($count5min > $this->uaRotationSettings['max_unique_ua_per_5min']) {
            $violations[] = '5min';
        }
        
        if ($countHour > $this->uaRotationSettings['max_unique_ua_per_hour']) {
            $violations[] = 'hour';
        }
        
        // Якщо є порушення - блокуємо
        if (!empty($violations)) {
            $this->blockIPForUARotation($ip, $violations, $count5min, $countHour);
            return true;
        }
        
        return false;
    }
    
    /**
     * Блокування IP за UA Rotation
     */
    private function blockIPForUARotation($ip, $violations, $count5min, $countHour) {
        $blockKey = $this->redisPrefix . 'ua_rotation_blocked:' . $ip;
        
        $blockData = array(
            'time' => time(),
            'ip' => $ip,
            'violations' => $violations,
            'unique_ua_5min' => $count5min,
            'unique_ua_hour' => $countHour,
            'reason' => 'ua_rotation'
        );
        
        // Блокування в Redis
        $this->redis->setex(
            $blockKey,
            $this->uaRotationSettings['block_duration'],
            $blockData
        );
        
        error_log(sprintf(
            "UA ROTATION BLOCK: IP=%s, unique_ua_5min=%d, unique_ua_hour=%d, violations=%s",
            $ip,
            $count5min,
            $countHour,
            implode(',', $violations)
        ));
        
        // Також блокуємо через API якщо увімкнено
        if ($this->apiSettings['enabled'] && $this->apiSettings['block_on_api']) {
            $apiResult = $this->callBlockingAPI($ip, 'block');
            if ($apiResult['status'] === 'success') {
                error_log("API BLOCK SUCCESS (UA ROTATION): IP=$ip");
            }
        }
    }
    
    /**
     * Отримати IP клієнта
     */
    private function getClientIP() {
        $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '0.0.0.0';
        
        // Перевірка проксі headers
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            $ip = $_SERVER['HTTP_CF_CONNECTING_IP']; // Cloudflare
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            $ip = trim($ips[0]);
        } elseif (!empty($_SERVER['HTTP_X_REAL_IP'])) {
            $ip = $_SERVER['HTTP_X_REAL_IP'];
        }
        
        return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '0.0.0.0';
    }
    
    /**
     * Нормалізація IPv6 адреси
     */
    private function normalizeIPv6($ip) {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return inet_ntop(inet_pton($ip));
        }
        return $ip;
    }
    
    /**
     * Перевірка чи IP в CIDR діапазоні
     * ВИПРАВЛЕНО v3.3.1: Перевірка типу CIDR перед перевіркою маски
     */
    private function ipInRange($ip, $cidr) {
        if (strpos($cidr, '/') === false) {
            return $ip === $cidr;
        }
        
        list($subnet, $mask) = explode('/', $cidr);
        $mask = (int)$mask;
        
        // ВИПРАВЛЕННЯ: Визначаємо типи IP та CIDR
        $ipIsV6 = (strpos($ip, ':') !== false);
        $cidrIsV6 = (strpos($subnet, ':') !== false);
        
        // Якщо типи різні — IP не може бути в цьому діапазоні
        // (IPv4 користувач не може бути в IPv6 діапазоні і навпаки)
        if ($ipIsV6 !== $cidrIsV6) {
            return false;
        }
        
        // IPv6
        if ($ipIsV6) {
            // Валідація маски для IPv6 (0-128)
            if ($mask < 0 || $mask > 128) {
                error_log("Invalid IPv6 CIDR mask: $cidr");
                return false;
            }
            return $this->ipv6InRange($ip, $subnet, $mask);
        }
        
        // IPv4
        // Валідація маски для IPv4 (0-32)
        if ($mask < 0 || $mask > 32) {
            error_log("Invalid IPv4 CIDR mask: $cidr (IP: $ip)");
            return false;
        }
        
        $ip_long = ip2long($ip);
        $subnet_long = ip2long($subnet);
        
        // Перевірка валідності IP адрес
        if ($ip_long === false || $subnet_long === false) {
            return false;
        }
        
        $mask_long = -1 << (32 - $mask);
        
        return ($ip_long & $mask_long) === ($subnet_long & $mask_long);
    }
    
    /**
     * Перевірка IPv6 в діапазоні
     */
    private function ipv6InRange($ip, $subnet, $mask) {
        $ip_bin = inet_pton($ip);
        $subnet_bin = inet_pton($subnet);
        
        if ($ip_bin === false || $subnet_bin === false) {
            return false;
        }
        
        $mask = (int)$mask;
        
        // Валідація маски (0-128 для IPv6)
        if ($mask < 0 || $mask > 128) {
            error_log("Invalid IPv6 mask in ipv6InRange: $mask");
            return false;
        }
        
        $full_bytes = floor($mask / 8);
        $remaining_bits = $mask % 8;
        
        for ($i = 0; $i < $full_bytes; $i++) {
            if ($ip_bin[$i] !== $subnet_bin[$i]) {
                return false;
            }
        }
        
        if ($remaining_bits > 0) {
            $mask_byte = (0xFF << (8 - $remaining_bits)) & 0xFF;
            if ((ord($ip_bin[$full_bytes]) & $mask_byte) !== (ord($subnet_bin[$full_bytes]) & $mask_byte)) {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Перевірка Rate Limit
     * @return bool true якщо потрібно блокувати
     */
    private function checkRateLimit($ip) {
        $now = time();
        $userId = $this->generateUserIdentifier();
        $hasCookie = $this->hasValidCookie();
        
        // Ключі для Redis
        $key = $this->redisPrefix . 'rate:' . hash('md5', $userId);
        $blockKey = $this->redisPrefix . 'blocked:' . hash('md5', $userId);
        
        // Перевірка чи користувач вже заблокований
        if ($this->redis->exists($blockKey)) {
            return true;
        }
        
        // Отримання даних про запити
        $data = $this->redis->get($key);
        
        // Ініціалізація структури даних
        $defaultRequests = array(
            'minute' => array(),
            '5min' => array(),
            'hour' => array(),
            'last_10sec' => array()
        );
        
        // Перевірка що дані правильно десеріалізовані
        if ($data && is_array($data)) {
            $requests = $data;
            // Перевірка що всі ключі є масивами
            foreach (array('minute', '5min', 'hour', 'last_10sec') as $key_name) {
                if (!isset($requests[$key_name]) || !is_array($requests[$key_name])) {
                    $requests[$key_name] = array();
                }
            }
        } else {
            $requests = $defaultRequests;
        }
        
        // Очищення старих записів (array_values перенумеровує ключі)
        $filteredMinute = array();
        foreach ($requests['minute'] as $t) {
            if (($now - $t) < 60) {
                $filteredMinute[] = $t;
            }
        }
        $requests['minute'] = $filteredMinute;
        
        $filtered5min = array();
        foreach ($requests['5min'] as $t) {
            if (($now - $t) < 300) {
                $filtered5min[] = $t;
            }
        }
        $requests['5min'] = $filtered5min;
        
        $filteredHour = array();
        foreach ($requests['hour'] as $t) {
            if (($now - $t) < 3600) {
                $filteredHour[] = $t;
            }
        }
        $requests['hour'] = $filteredHour;
        
        $filtered10sec = array();
        foreach ($requests['last_10sec'] as $t) {
            if (($now - $t) < 10) {
                $filtered10sec[] = $t;
            }
        }
        $requests['last_10sec'] = $filtered10sec;
        
        // Додавання нового запиту
        $requests['minute'][] = $now;
        $requests['5min'][] = $now;
        $requests['hour'][] = $now;
        $requests['last_10sec'][] = $now;
        
        // Розрахунок лімітів з урахуванням cookie multiplier
        $multiplier = $hasCookie ? $this->rateLimitSettings['cookie_multiplier'] : 1.0;
        $limits = array(
            'minute' => (int)($this->rateLimitSettings['max_requests_per_minute'] * $multiplier),
            '5min' => (int)($this->rateLimitSettings['max_requests_per_5min'] * $multiplier),
            'hour' => (int)($this->rateLimitSettings['max_requests_per_hour'] * $multiplier),
            'burst' => (int)($this->rateLimitSettings['burst_threshold'] * $multiplier)
        );
        
        // Перевірка лімітів
        $violations = array();
        
        // Debug logging
        if ($this->debugMode) {
            error_log(sprintf(
                "RATE LIMIT CHECK: user_id=%s, cookie=%s, counts=[min:%d/%d, 5min:%d/%d, hour:%d/%d, burst:%d/%d]",
                substr($userId, 0, 30),
                $hasCookie ? 'YES' : 'NO',
                count($requests['minute']), $limits['minute'],
                count($requests['5min']), $limits['5min'],
                count($requests['hour']), $limits['hour'],
                count($requests['last_10sec']), $limits['burst']
            ));
        }
        
        if (count($requests['minute']) > $limits['minute']) {
            $violations[] = 'minute';
        }
        
        if (count($requests['5min']) > $limits['5min']) {
            $violations[] = '5min';
        }
        
        if (count($requests['hour']) > $limits['hour']) {
            $violations[] = 'hour';
        }
        
        // Burst Detection (занадто багато запитів за 10 секунд)
        if (count($requests['last_10sec']) > $limits['burst']) {
            $violations[] = 'burst';
        }
        
        // Збереження даних (PHP serializer автоматично серіалізує)
        $this->redis->setex($key, 3600, $requests);
        
        // Якщо є порушення - блокуємо
        if (!empty($violations)) {
            $this->blockUser($userId, $ip, $violations, $hasCookie, $limits);
            return true;
        }
        
        return false;
    }
    
    /**
     * Блокування користувача (замість IP)
     */
    private function blockUser($userId, $ip, $violations, $hasCookie, $limits) {
        $blockKey = $this->redisPrefix . 'blocked:' . hash('md5', $userId);
        $userInfo = $this->getUserInfo();
        
        $blockData = array(
            'time' => time(),
            'violations' => $violations,
            'user_id' => $userId,
            'ip' => $ip,
            'browser_hash' => $userInfo['browser_hash'],
            'cookie_id' => $userInfo['cookie_id'],
            'has_cookie' => $hasCookie,
            'limits' => $limits
        );
        
        // Блокування в Redis
        if ($this->apiSettings['block_on_redis']) {
            $this->redis->setex(
                $blockKey, 
                $this->rateLimitSettings['block_duration'], 
                $blockData
            );
        }
        
        error_log("RATE LIMIT BLOCK USER: " . 
                  "user_id=" . substr($userId, 0, 20) . 
                  ", ip=$ip" .
                  ", cookie=" . ($hasCookie ? 'YES' : 'NO') .
                  ", violations=" . implode(',', $violations));
        
        // Блокування через API (iptables) - тільки якщо немає cookie
        // Це означає що користувач з cookie може продовжити з іншого IP
        if (!$hasCookie && $this->apiSettings['enabled'] && $this->apiSettings['block_on_api']) {
            $apiResult = $this->callBlockingAPI($ip, 'block');
            if ($apiResult['status'] === 'success') {
                error_log("API BLOCK SUCCESS: IP=$ip (user without cookie)");
            } elseif ($apiResult['status'] !== 'already_blocked') {
                $msg = isset($apiResult['message']) ? $apiResult['message'] : 'unknown';
                error_log("API BLOCK FAILED: IP=$ip, reason=" . $msg);
            }
        }
    }
    
    /**
     * Блокування IP (старий метод для сумісності)
     */
    private function blockIP($ip, $violations) {
        $blockKey = $this->redisPrefix . 'blocked:' . $ip;
        $blockData = array(
            'time' => time(),
            'violations' => $violations,
            'ip' => $ip
        );
        
        // Блокування в Redis
        if ($this->apiSettings['block_on_redis']) {
            $this->redis->setex(
                $blockKey, 
                $this->rateLimitSettings['block_duration'], 
                $blockData
            );
        }
        
        error_log("RATE LIMIT BLOCK: IP=$ip, violations=" . implode(',', $violations));
        
        // Блокування через API (iptables)
        if ($this->apiSettings['enabled'] && $this->apiSettings['block_on_api']) {
            $apiResult = $this->callBlockingAPI($ip, 'block');
            if ($apiResult['status'] === 'success') {
                error_log("API BLOCK SUCCESS: IP=$ip");
            } elseif ($apiResult['status'] !== 'already_blocked') {
                $msg = isset($apiResult['message']) ? $apiResult['message'] : 'unknown';
                error_log("API BLOCK FAILED: IP=$ip, reason=" . $msg);
            }
        }
    }
    
    /**
     * Виклик API для блокування/розблокування IP
     */
    private function callBlockingAPI($ip, $action = 'block') {
        if (!$this->apiSettings['enabled']) {
            return array('status' => 'disabled', 'message' => 'API disabled');
        }
        
        if (!$this->apiSettings['block_on_api']) {
            return array('status' => 'skipped', 'message' => 'API blocking disabled');
        }
        
        $url = $this->apiSettings['url'] . 
               '?action=' . urlencode($action) . 
               '&ip=' . urlencode($ip) . 
               '&api=1' . 
               '&api_key=' . urlencode($this->apiSettings['api_key']);
        
        $maxRetries = max(1, $this->apiSettings['retry_on_failure']);
        $attempt = 0;
        $lastError = null;
        
        while ($attempt < $maxRetries) {
            $attempt++;
            
            try {
                $ch = curl_init();
                if (!$ch) {
                    throw new Exception("Failed to initialize cURL");
                }
                
                curl_setopt_array($ch, array(
                    CURLOPT_URL => $url,
                    CURLOPT_RETURNTRANSFER => true,
                    CURLOPT_TIMEOUT => $this->apiSettings['timeout'],
                    CURLOPT_CONNECTTIMEOUT => 3,
                    CURLOPT_FOLLOWLOCATION => false,
                    CURLOPT_SSL_VERIFYPEER => $this->apiSettings['verify_ssl'],
                    CURLOPT_SSL_VERIFYHOST => $this->apiSettings['verify_ssl'] ? 2 : 0,
                    CURLOPT_USERAGENT => $this->apiSettings['user_agent'],
                    CURLOPT_HTTPHEADER => array(
                        'Accept: application/json',
                        'Cache-Control: no-cache'
                    )
                ));
                
                $response = curl_exec($ch);
                $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                $curlError = curl_error($ch);
                $curlErrno = curl_errno($ch);
                curl_close($ch);
                
                if ($curlErrno !== 0) {
                    throw new Exception("cURL error #" . $curlErrno . ": " . $curlError);
                }
                
                if ($httpCode !== 200) {
                    throw new Exception("HTTP error code: " . $httpCode);
                }
                
                if (empty($response)) {
                    throw new Exception("Empty response from API");
                }
                
                $result = json_decode($response, true);
                if (!is_array($result)) {
                    throw new Exception("Invalid JSON response");
                }
                
                if (isset($result['status'])) {
                    if ($result['status'] === 'success') {
                        return array(
                            'status' => 'success',
                            'message' => isset($result['message']) ? $result['message'] : 'OK',
                            'attempt' => $attempt
                        );
                    } elseif ($result['status'] === 'error') {
                        $errorMsg = isset($result['message']) ? $result['message'] : 'Unknown error';
                        
                        // Перевірка чи вже заблоковано
                        if (stripos($errorMsg, 'already blocked') !== false || 
                            stripos($errorMsg, 'вже заблокован') !== false) {
                            return array('status' => 'already_blocked', 'message' => $errorMsg);
                        }
                        
                        // Перевірка чи не заблоковано
                        if (stripos($errorMsg, 'not blocked') !== false || 
                            stripos($errorMsg, 'не заблокирован') !== false) {
                            return array('status' => 'not_blocked', 'message' => $errorMsg);
                        }
                        
                        throw new Exception("API error: " . $errorMsg);
                    }
                }
                
                throw new Exception("Unknown API response format");
                
            } catch (Exception $e) {
                $lastError = $e->getMessage();
                
                if ($this->apiSettings['log_api_errors']) {
                    error_log("API " . $action . " ATTEMPT " . $attempt . "/" . $maxRetries . " FAILED: " . $ip . " | " . $lastError);
                }
                
                if ($attempt < $maxRetries) {
                    usleep(200000); // 200ms затримка між спробами
                }
            }
        }
        
        return array(
            'status' => 'error',
            'message' => $lastError ? $lastError : 'Unknown error',
            'attempts' => $maxRetries
        );
    }
    
    /**
     * Показ 502 помилки
     */
    private function show502Error() {
        if (headers_sent()) {
            return;
        }
        
        http_response_code(502);
        header('Content-Type: text/html; charset=utf-8');
        header('Cache-Control: no-cache, no-store, must-revalidate');
        header('Pragma: no-cache');
        header('Expires: 0');
        
        echo '<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>502 Bad Gateway</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #fff;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            padding: 20px;
        }
        .container {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 40px;
            max-width: 600px;
            text-align: center;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
        }
        h1 {
            font-size: 72px;
            margin: 0 0 20px 0;
            font-weight: 700;
        }
        h2 {
            font-size: 24px;
            margin: 0 0 30px 0;
            font-weight: 400;
            opacity: 0.9;
        }
        p {
            font-size: 16px;
            line-height: 1.6;
            opacity: 0.8;
        }
        .icon {
            font-size: 100px;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">⚠️</div>
        <h1>502</h1>
        <h2>Bad Gateway</h2>
        <p>Сервер тимчасово недоступний через технічні роботи або перевантаження.</p>
        <p>Будь ласка, спробуйте пізніше.</p>
    </div>
</body>
</html>';
        exit;
    }
    
    /**
     * Розблокування користувача по user ID
     */
    public function unblockUser($userId) {
        $blockKey = $this->redisPrefix . 'blocked:' . hash('md5', $userId);
        $deleted = false;
        
        // Розблокування в Redis
        if ($this->apiSettings['block_on_redis']) {
            $deleted = $this->redis->del($blockKey);
        }
        
        return $deleted;
    }
    
    /**
     * Розблокування IP (для адміністратора)
     */
    public function unblockIP($ip) {
        // Старий метод - розблокування по IP
        $blockKey = $this->redisPrefix . 'blocked:' . $ip;
        $blockKeyHash = $this->redisPrefix . 'blocked:' . hash('md5', 'ip:' . $ip);
        $uaRotationBlockKey = $this->redisPrefix . 'ua_rotation_blocked:' . $ip;
        $deleted = false;
        
        // Розблокування в Redis (всі типи блокувань)
        if ($this->apiSettings['block_on_redis']) {
            $deleted = $this->redis->del($blockKey);
            $this->redis->del($blockKeyHash);
            $this->redis->del($uaRotationBlockKey); // UA rotation block
        }
        
        // Розблокування через API
        if ($this->apiSettings['enabled'] && 
            $this->apiSettings['auto_unblock'] && 
            $this->apiSettings['block_on_api']) {
            
            $apiResult = $this->callBlockingAPI($ip, 'unblock');
            if ($apiResult['status'] === 'success') {
                error_log("API UNBLOCK SUCCESS: IP=$ip");
            } elseif ($apiResult['status'] !== 'not_blocked') {
                $msg = isset($apiResult['message']) ? $apiResult['message'] : 'unknown';
                error_log("API UNBLOCK FAILED: IP=$ip, reason=" . $msg);
            }
        }
        
        return $deleted;
    }
    
    /**
     * Скидання rate limit для користувача по user ID
     */
    public function resetUserRateLimit($userId) {
        $key = $this->redisPrefix . 'rate:' . hash('md5', $userId);
        return $this->redis->del($key);
    }
    
    /**
     * Скидання лічильників для IP
     */
    public function resetRateLimit($ip) {
        $key = $this->redisPrefix . 'rate:' . $ip;
        $keyHash = $this->redisPrefix . 'rate:' . hash('md5', 'ip:' . $ip);
        
        $this->redis->del($key);
        $this->redis->del($keyHash);
        
        return true;
    }
    
    /**
     * Отримання статистики
     */
    public function getStats() {
        $keys = $this->redis->keys($this->redisPrefix . '*');
        
        $stats = array(
            'total_tracked_ips' => 0,
            'blocked_ips' => 0,
            'ua_rotation_blocked' => 0,
            'rate_limit_keys' => 0,
            'ua_rotation_tracked' => 0,
            'rdns_cache_entries' => 0
        );
        
        if (!is_array($keys)) {
            return $stats;
        }
        
        foreach ($keys as $key) {
            if (strpos($key, ':ua_rotation_blocked:') !== false) {
                $stats['ua_rotation_blocked']++;
            } elseif (strpos($key, ':blocked:') !== false) {
                $stats['blocked_ips']++;
            } elseif (strpos($key, ':rate:') !== false) {
                $stats['rate_limit_keys']++;
                $stats['total_tracked_ips']++;
            } elseif (strpos($key, ':ua_rotation_5min:') !== false || strpos($key, ':ua_rotation_hour:') !== false) {
                $stats['ua_rotation_tracked']++;
            } elseif (strpos($key, $this->rdnsPrefix . 'cache:') !== false) {
                $stats['rdns_cache_entries']++;
            }
        }
        
        return $stats;
    }
    
    /**
     * Статистика rDNS
     */
    public function getRDNSStats() {
        $currentMinute = floor(time() / 60);
        $prevMinute = $currentMinute - 1;
        
        $currentKey = $this->redisPrefix . $this->rdnsPrefix . 'ratelimit:' . $currentMinute;
        $prevKey = $this->redisPrefix . $this->rdnsPrefix . 'ratelimit:' . $prevMinute;
        
        $currentCount = $this->redis->get($currentKey);
        $prevCount = $this->redis->get($prevKey);
        
        $cacheKeys = $this->redis->keys($this->redisPrefix . $this->rdnsPrefix . 'cache:*');
        
        return array(
            'current_minute_requests' => (int)($currentCount ? $currentCount : 0),
            'previous_minute_requests' => (int)($prevCount ? $prevCount : 0),
            'limit_per_minute' => $this->rdnsSettings['max_rdns_per_minute'],
            'cache_entries' => is_array($cacheKeys) ? count($cacheKeys) : 0,
            'limit_reached' => $currentCount >= $this->rdnsSettings['max_rdns_per_minute']
        );
    }
    
    /**
     * Статистика UA Rotation Detection
     */
    public function getUARotationStats() {
        $blockedKeys = $this->redis->keys($this->redisPrefix . 'ua_rotation_blocked:*');
        $tracked5minKeys = $this->redis->keys($this->redisPrefix . 'ua_rotation_5min:*');
        $trackedHourKeys = $this->redis->keys($this->redisPrefix . 'ua_rotation_hour:*');
        
        $stats = array(
            'enabled' => $this->uaRotationSettings['enabled'],
            'blocked_ips' => is_array($blockedKeys) ? count($blockedKeys) : 0,
            'tracked_ips_5min' => is_array($tracked5minKeys) ? count($tracked5minKeys) : 0,
            'tracked_ips_hour' => is_array($trackedHourKeys) ? count($trackedHourKeys) : 0,
            'max_unique_ua_5min' => $this->uaRotationSettings['max_unique_ua_per_5min'],
            'max_unique_ua_hour' => $this->uaRotationSettings['max_unique_ua_per_hour'],
            'block_duration' => $this->uaRotationSettings['block_duration']
        );
        
        return $stats;
    }
    
    /**
     * Отримання детальної інформації про UA rotation для IP
     */
    public function getUARotationInfo($ip) {
        $key5min = $this->redisPrefix . 'ua_rotation_5min:' . $ip;
        $keyHour = $this->redisPrefix . 'ua_rotation_hour:' . $ip;
        $blockKey = $this->redisPrefix . 'ua_rotation_blocked:' . $ip;
        
        $data5min = $this->redis->get($key5min);
        $dataHour = $this->redis->get($keyHour);
        $blockData = $this->redis->get($blockKey);
        
        return array(
            'ip' => $ip,
            'is_blocked' => $this->redis->exists($blockKey),
            'unique_ua_5min' => $data5min && is_array($data5min) ? count($data5min) : 0,
            'unique_ua_hour' => $dataHour && is_array($dataHour) ? count($dataHour) : 0,
            'block_info' => $blockData ? $blockData : null
        );
    }
    
    /**
     * Очищення rDNS кешу
     */
    public function clearRDNSCache() {
        $keys = $this->redis->keys($this->redisPrefix . $this->rdnsPrefix . 'cache:*');
        $deleted = 0;
        
        if (is_array($keys)) {
            foreach ($keys as $key) {
                $this->redis->del(str_replace($this->redisPrefix, '', $key));
                $deleted++;
            }
        }
        
        return $deleted;
    }
    
    /**
     * Інформація про заблокований IP
     */
    public function getBlockedIPInfo($ip) {
        $blockKey = $this->redisPrefix . 'blocked:' . $ip;
        $data = $this->redis->get($blockKey);
        
        return $data ? $data : null;
    }
    
    /**
     * Оновлення налаштувань Rate Limit
     */
    public function updateRateLimitSettings($settings) {
        $this->rateLimitSettings = array_merge($this->rateLimitSettings, $settings);
    }
    
    /**
     * Оновлення налаштувань rDNS
     */
    public function updateRDNSSettings($settings) {
        $this->rdnsSettings = array_merge($this->rdnsSettings, $settings);
    }
    
    /**
     * Оновлення налаштувань API
     */
    public function updateAPISettings($settings) {
        $this->apiSettings = array_merge($this->apiSettings, $settings);
    }
    
    /**
     * Оновлення налаштувань UA Rotation Detection
     */
    public function updateUARotationSettings($settings) {
        $this->uaRotationSettings = array_merge($this->uaRotationSettings, $settings);
    }
    
    /**
     * Отримання налаштувань API
     */
    public function getAPISettings() {
        return $this->apiSettings;
    }
    
    /**
     * Отримання списку заблокованих IP через API
     */
    public function getBlockedIPsFromAPI() {
        if (!$this->apiSettings['enabled']) {
            return array('status' => 'disabled', 'message' => 'API disabled');
        }
        
        $url = $this->apiSettings['url'] . 
               '?action=list&api=1&api_key=' . urlencode($this->apiSettings['api_key']);
        
        try {
            $ch = curl_init();
            curl_setopt_array($ch, array(
                CURLOPT_URL => $url,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => $this->apiSettings['timeout'],
                CURLOPT_SSL_VERIFYPEER => $this->apiSettings['verify_ssl'],
                CURLOPT_SSL_VERIFYHOST => $this->apiSettings['verify_ssl'] ? 2 : 0,
            ));
            
            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            
            if ($httpCode === 200 && !empty($response)) {
                $result = json_decode($response, true);
                return $result ? $result : array('status' => 'error', 'message' => 'Invalid JSON');
            }
            
            return array('status' => 'error', 'message' => 'HTTP ' . $httpCode);
            
        } catch (Exception $e) {
            return array('status' => 'error', 'message' => $e->getMessage());
        }
    }
    
    /**
     * Додавання IP діапазону до конкретної пошукової системи
     */
    public function addSearchEngineIP($engine, $cidr) {
        if (isset($this->searchEngines[$engine])) {
            $this->searchEngines[$engine]['ip_ranges'][] = $cidr;
        }
    }
    
    /**
     * Додавання нової пошукової системи
     */
    public function addSearchEngine($name, $config) {
        $this->searchEngines[$name] = $config;
    }
    
    /**
     * Увімкнути/вимкнути debug логування
     */
    public function setDebugMode($enabled) {
        $this->debugMode = (bool)$enabled;
    }
    
    /**
     * Перевірити чи увімкнено debug режим
     */
    public function isDebugMode() {
        return $this->debugMode;
    }
    
    /**
     * Отримати поточний user identifier
     */
    public function getCurrentUserId() {
        return $this->generateUserIdentifier();
    }
    
    /**
     * Отримати інформацію про поточного користувача
     */
    public function getCurrentUserInfo() {
        return $this->getUserInfo();
    }
    
    /**
     * Очищення старих записів (cleanup)
     */
    public function cleanup() {
        $keys = $this->redis->keys($this->redisPrefix . 'rate:*');
        $cleaned = 0;
        
        if (is_array($keys)) {
            foreach ($keys as $key) {
                $data = $this->redis->get($key);
                if (!$data) {
                    $this->redis->del($key);
                    $cleaned++;
                }
            }
        }
        
        return $cleaned;
    }
}

// ============================================================================
// АВТОМАТИЧНИЙ ЗАХИСТ
// ============================================================================

$protection = new SimpleBotProtection();
$protection->protect();

?>