<?php
// /var/www/your-site/bot_protection/redis_inline_check.php

class RedisBotProtectionNoSessions {
 private $redis;
 private $cookieName = 'visitor_verified';
 private $secretKey = 'your_secret_key_here_change_this12345!@#$';
 private $cookieLifetime = 86400 * 30; // 30 дней
 
 // Префиксы для Redis ключей (БЕЗ sessionPrefix)
 private $redisPrefix = 'bot_protection:';
 private $trackingPrefix = 'tracking:';
 private $blockPrefix = 'blocked:';
 private $cookiePrefix = 'cookie:';
 private $rdnsPrefix = 'rdns:';
 private $userHashPrefix = 'user_hash:';
 
 // ОПТИМИЗИРОВАННЫЕ TTL (в секундах) - БЕЗ сессий
 private $ttlSettings = [
     'tracking_ip' => 1800,          // 30 мин
     'cookie_blocked' => 7200,       // 2 часа
     'ip_blocked' => 86400,          // 24 часа
     'ip_blocked_repeat' => 259200,  // 3 дня
     'rdns_cache' => 900,            // 15 мин
     'logs' => 86400,                // 1 день
     'cleanup_interval' => 900,      // 15 мин
     'user_hash_blocked' => 172800,  // 2 дня
     'user_hash_tracking' => 1800,   // 30 мин
     'user_hash_stats' => 172800,    // 2 дня
 ];
 
 // РАСШИРЕННЫЙ список поисковиков с точными паттернами
 private $allowedSearchEngines = [
     'googlebot' => [
         'user_agent_patterns' => ['googlebot', 'google'],
         'rdns_patterns' => ['.googlebot.com', '.google.com']
     ],
     'bingbot' => [
         'user_agent_patterns' => ['bingbot', 'msnbot'],
         'rdns_patterns' => ['.search.msn.com']
     ],
     'yandexbot' => [
         'user_agent_patterns' => ['yandexbot', 'yandex'],
         'rdns_patterns' => ['.yandex.ru', '.yandex.net', '.yandex.com']
     ],
     'slurp' => [
         'user_agent_patterns' => ['slurp'],
         'rdns_patterns' => ['.crawl.yahoo.net']
     ],
     'duckduckbot' => [
         'user_agent_patterns' => ['duckduckbot'],
         'rdns_patterns' => ['.duckduckgo.com']
     ],
     'baiduspider' => [
         'user_agent_patterns' => ['baiduspider'],
         'rdns_patterns' => ['.baidu.com', '.baidu.jp']
     ],
     'facebookexternalhit' => [
         'user_agent_patterns' => ['facebookexternalhit'],
         'rdns_patterns' => ['.facebook.com']
     ],
     'twitterbot' => [
         'user_agent_patterns' => ['twitterbot'],
         'rdns_patterns' => ['.twitter.com']
     ],
     'linkedinbot' => [
         'user_agent_patterns' => ['linkedinbot'],
         'rdns_patterns' => ['.linkedin.com']
     ],
     'applebot' => [
         'user_agent_patterns' => ['applebot'],
         'rdns_patterns' => ['.applebot.apple.com']
     ],
     'amazonbot' => [
         'user_agent_patterns' => ['amazonbot'],
         'rdns_patterns' => ['.amazon.com']
     ],
     'petalbot' => [
         'user_agent_patterns' => ['petalbot'],
         'rdns_patterns' => ['.petalsearch.com']
     ],
     'sogou' => [
         'user_agent_patterns' => ['sogou'],
         'rdns_patterns' => ['.sogou.com']
     ]
 ];
 
 public function __construct($redisHost = '127.0.0.1', $redisPort = 6379, $redisPassword = null, $redisDatabase = 0) {
     $this->initRedis($redisHost, $redisPort, $redisPassword, $redisDatabase);
     $this->autoCleanup();
 }
 
 private function initRedis($host, $port, $password, $database) {
     try {
         $this->redis = new Redis();
         $this->redis->connect($host, $port);
         
         if ($password) {
             $this->redis->auth($password);
         }
         
         $this->redis->select($database);
         
         // Настройка Redis для оптимальной производительности
         $this->redis->setOption(Redis::OPT_SERIALIZER, Redis::SERIALIZER_JSON);
         $this->redis->setOption(Redis::OPT_PREFIX, $this->redisPrefix);
         
     } catch (Exception $e) {
         // ТОЛЬКО КРИТИЧЕСКИЕ ОШИБКИ
         error_log("CRITICAL: Redis connection failed - " . $e->getMessage());
         die('Service temporarily unavailable. Please try again later.');
     }
 }
 
 // АВТОМАТИЧЕСКАЯ очистка БЕЗ ЛОГИРОВАНИЯ
 private function autoCleanup() {
     $lastCleanupKey = 'last_cleanup';
     $lastCleanup = $this->redis->get($lastCleanupKey);
     
     if (!$lastCleanup || (time() - $lastCleanup) > $this->ttlSettings['cleanup_interval']) {
         $this->aggressiveCleanup();
         $this->redis->setex($lastCleanupKey, $this->ttlSettings['cleanup_interval'], time());
     }
 }
 
 // АГРЕССИВНАЯ очистка БЕЗ ЛОГИРОВАНИЯ
 private function aggressiveCleanup() {
     try {
         $cleaned = 0;
         $startTime = microtime(true);
         $maxExecutionTime = 0.05;
         
         $patterns = [
             $this->trackingPrefix . 'ip:*',
             $this->userHashPrefix . 'tracking:*',
             $this->rdnsPrefix . 'cache:*'
         ];
         
         foreach ($patterns as $pattern) {
             if ((microtime(true) - $startTime) > $maxExecutionTime) break;
             
             $keys = array_slice($this->redis->keys($pattern), 0, 25);
             foreach ($keys as $key) {
                 if ((microtime(true) - $startTime) > $maxExecutionTime) break;
                 
                 $ttl = $this->redis->ttl($key);
                 if ($ttl === -1 || ($ttl > 0 && $ttl < 450)) {
                     $this->redis->del($key);
                     $cleaned++;
                 }
             }
             
             if ($cleaned > 50) break;
         }
         
     } catch (Exception $e) {
         error_log("Cleanup error: " . $e->getMessage());
     }
 }
 
 /**
  * УЛУЧШЕННАЯ функция нормализации IPv6
  */
 private function normalizeIPv6($ip) {
     if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
         return $ip;
     }
     
     // Используем inet_pton/inet_ntop для правильной нормализации
     $binary = @inet_pton($ip);
     if ($binary === false) {
         return $ip;
     }
     
     $normalized = @inet_ntop($binary);
     return $normalized ?: $ip;
 }
 
 /**
  * НОВАЯ функция: улучшенная нормализация IP (IPv4 и IPv6)
  */
 private function normalizeIP($ip) {
     // Убираем пробелы
     $ip = trim($ip);
     
     if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
         return $ip; // IPv4 уже нормализован
     }
     
     if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
         return $this->normalizeIPv6($ip);
     }
     
     return $ip;
 }
 
 private function getIPFingerprint($ip) {
     $ip = $this->normalizeIPv6($ip);
     
     if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
         $parts = explode(':', $ip);
         if (count($parts) >= 4) {
             return implode(':', array_slice($parts, -4));
         }
         return substr($ip, -16);
     } else {
         $parts = explode('.', $ip);
         if (count($parts) >= 2) {
             return end($parts) . '.' . prev($parts);
         }
         return $ip;
     }
 }
 
 // БЕЗ ЛОГИРОВАНИЯ генерации хеша
 private function generateUserHash($ip = null) {
     $ip = $ip ?: $this->getRealIP();
     $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
     $acceptLanguage = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '';
     $acceptEncoding = $_SERVER['HTTP_ACCEPT_ENCODING'] ?? '';
     $accept = $_SERVER['HTTP_ACCEPT'] ?? '';
     
     $browserInfo = $this->getBrowserFingerprint($userAgent);
     
     $stableFingerprint = $userAgent . '|' . 
                         $acceptLanguage . '|' . 
                         $acceptEncoding . '|' . 
                         $accept . '|' .
                         $browserInfo['name'] . '|' .
                         $browserInfo['version'] . '|' .
                         $browserInfo['platform'] . '|' .
                         $this->secretKey;
     
     if ($this->isMobileDevice($userAgent)) {
         $ipPart = $this->getIPFingerprint($ip);
         $stableFingerprint .= '|mobile|' . $ipPart;
     } else {
         $stableFingerprint .= '|desktop|' . $ip;
     }
     
     return hash('sha256', $stableFingerprint);
 }
 
 private function getBrowserFingerprint($userAgent) {
     $browser = [
         'name' => 'unknown',
         'version' => 'unknown',
         'platform' => 'unknown'
     ];
     
     if (preg_match('/Chrome\/(\d+\.\d+)/', $userAgent, $matches)) {
         $browser['name'] = 'Chrome';
         $browser['version'] = $matches[1];
     } elseif (preg_match('/Firefox\/(\d+\.\d+)/', $userAgent, $matches)) {
         $browser['name'] = 'Firefox';
         $browser['version'] = $matches[1];
     } elseif (preg_match('/Safari\/(\d+\.\d+)/', $userAgent, $matches)) {
         if (strpos($userAgent, 'Chrome') === false) {
             $browser['name'] = 'Safari';
             $browser['version'] = $matches[1];
         }
     } elseif (preg_match('/Edge\/(\d+\.\d+)/', $userAgent, $matches)) {
         $browser['name'] = 'Edge';
         $browser['version'] = $matches[1];
     } elseif (preg_match('/Edg\/(\d+\.\d+)/', $userAgent, $matches)) {
         $browser['name'] = 'EdgeChromium';
         $browser['version'] = $matches[1];
     }
     
     if (strpos($userAgent, 'Windows NT') !== false) {
         if (preg_match('/Windows NT (\d+\.\d+)/', $userAgent, $matches)) {
             $browser['platform'] = 'Windows_' . $matches[1];
         } else {
             $browser['platform'] = 'Windows';
         }
     } elseif (strpos($userAgent, 'Macintosh') !== false) {
         $browser['platform'] = 'macOS';
     } elseif (strpos($userAgent, 'Linux') !== false) {
         $browser['platform'] = 'Linux';
     } elseif (strpos($userAgent, 'Android') !== false) {
         $browser['platform'] = 'Android';
     } elseif (strpos($userAgent, 'iPhone') !== false || strpos($userAgent, 'iPad') !== false) {
         $browser['platform'] = 'iOS';
     }
     
     return $browser;
 }
 
 private function isUserHashBlocked() {
     $userHash = $this->generateUserHash();
     $blockKey = $this->userHashPrefix . 'blocked:' . $userHash;
     return $this->redis->exists($blockKey);
 }
 
 // ЛОГИРУЕМ ТОЛЬКО ФАКТ БЛОКИРОВКИ
 private function blockUserHash($reason = 'Bot behavior detected') {
     $userHash = $this->generateUserHash();
     $ip = $this->getRealIP();
     
     $blockData = [
         'user_hash' => $userHash,
         'ip' => $ip,
         'blocked_at' => time(),
         'blocked_reason' => $reason,
         'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
         'session_id' => 'no_session',
         'uri' => $_SERVER['REQUEST_URI'] ?? '',
         'headers' => $this->collectHeaders(),
         'browser_info' => $this->getBrowserFingerprint($_SERVER['HTTP_USER_AGENT'] ?? ''),
         'device_type' => $this->isMobileDevice($_SERVER['HTTP_USER_AGENT'] ?? '') ? 'mobile' : 'desktop'
     ];
     
     $blockKey = $this->userHashPrefix . 'blocked:' . $userHash;
     $this->redis->setex($blockKey, $this->ttlSettings['user_hash_blocked'], $blockData);
     
     $statsKey = $this->userHashPrefix . 'stats:' . $userHash;
     $this->redis->hincrby($statsKey, 'block_count', 1);
     $this->redis->hset($statsKey, 'last_blocked', time());
     $this->redis->hset($statsKey, 'last_blocked_reason', $reason);
     $this->redis->expire($statsKey, $this->ttlSettings['user_hash_stats']);
     
     // ТОЛЬКО ВАЖНАЯ ИНФОРМАЦИЯ
     error_log("Bot blocked [HASH]: " . substr($userHash, 0, 8) . " | IP: $ip | " . $blockData['device_type'] . " | " . $reason);
 }
 
 private function trackUserHashActivity() {
     $userHash = $this->generateUserHash();
     $trackingKey = $this->userHashPrefix . 'tracking:' . $userHash;
     
     $existing = $this->redis->get($trackingKey);
     
     if ($existing) {
         $existing['requests']++;
         $existing['last_activity'] = time();
         
         $currentPage = parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH);
         if (!in_array($currentPage, $existing['pages'])) {
             $existing['pages'][] = $currentPage;
         }
         
         $existing['request_times'][] = time();
         
         $currentIP = $this->getRealIP();
         if (!in_array($currentIP, $existing['ips'])) {
             $existing['ips'][] = $currentIP;
         }
         
         if (count($existing['request_times']) > 20) {
             $existing['request_times'] = array_slice($existing['request_times'], -20);
         }
         if (count($existing['pages']) > 30) {
             $existing['pages'] = array_unique(array_slice($existing['pages'], -30));
         }
         if (count($existing['ips']) > 10) {
             $existing['ips'] = array_unique(array_slice($existing['ips'], -10));
         }
         
         $this->redis->setex($trackingKey, $this->ttlSettings['user_hash_tracking'], $existing);
     } else {
         $data = [
             'user_hash' => $userHash,
             'first_seen' => time(),
             'last_activity' => time(),
             'requests' => 1,
             'pages' => [parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH)],
             'ips' => [$this->getRealIP()],
             'user_agents' => [$_SERVER['HTTP_USER_AGENT'] ?? ''],
             'request_times' => [time()],
             'browser_info' => $this->getBrowserFingerprint($_SERVER['HTTP_USER_AGENT'] ?? '')
         ];
         
         $this->redis->setex($trackingKey, $this->ttlSettings['user_hash_tracking'], $data);
     }
     
     return $existing ?: $data;
 }
 
 // БЕЗ ДЕТАЛЬНОГО ЛОГИРОВАНИЯ АНАЛИЗА
 private function analyzeUserHashBehavior() {
     $trackingData = $this->trackUserHashActivity();
     
     if (!$trackingData || $trackingData['requests'] < 8) {
         return false;
     }
     
     $score = 0;
     $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
     $isMobile = $this->isMobileDevice($userAgent);
     $browserInfo = $this->getBrowserFingerprint($userAgent);
     
     $blockThreshold = $isMobile ? 20 : 18;
     
     // 1. Подозрительный User-Agent
     if ($this->isSuspiciousUserAgent($userAgent)) {
         $score += $isMobile ? 15 : 20;
     }
     
     // 2. Анализ частоты запросов
     $requests = $trackingData['requests'];
     $timeSpent = time() - $trackingData['first_seen'];
     
     if ($timeSpent > 0) {
         $requestsPerMinute = ($requests * 60) / $timeSpent;
         
         if ($isMobile) {
             if ($requestsPerMinute > 300) $score += 12;
             elseif ($requestsPerMinute > 200) $score += 8;
             elseif ($requestsPerMinute > 120) $score += 4;
         } else {
             if ($requestsPerMinute > 250) $score += 12;
             elseif ($requestsPerMinute > 150) $score += 8;
             elseif ($requestsPerMinute > 80) $score += 4;
         }
     }
     
     // 3. Анализ разнообразия страниц
     $uniquePages = array_unique($trackingData['pages'] ?? []);
     $totalPages = count($trackingData['pages'] ?? []);
     
     if ($totalPages > 60) {
         $pageVariety = count($uniquePages) / $totalPages;
         if ($pageVariety < 0.05) {
             $score += $isMobile ? 3 : 4;
         }
     }
     
     // 4. Анализ регулярности запросов
     if (isset($trackingData['request_times']) && count($trackingData['request_times']) >= 15) {
         $intervals = [];
         $times = array_slice($trackingData['request_times'], -20);
         
         for ($i = 1; $i < count($times); $i++) {
             $intervals[] = $times[$i] - $times[$i-1];
         }
         
         if (count($intervals) >= 15) {
             $avgInterval = array_sum($intervals) / count($intervals);
             $variance = 0;
             foreach ($intervals as $interval) {
                 $variance += pow($interval - $avgInterval, 2);
             }
             $variance /= count($intervals);
             $stdDev = sqrt($variance);
             
             if ($stdDev < 0.5 && $avgInterval < 2 && $avgInterval > 0.2) {
                 $score += $isMobile ? 5 : 7;
             }
         }
     }
     
     // 5. Быстрые последовательные запросы
     if (isset($trackingData['request_times']) && count($trackingData['request_times']) >= 10) {
         $lastTen = array_slice($trackingData['request_times'], -10);
         $timeDiff = end($lastTen) - reset($lastTen);
         
         if ($timeDiff <= 3) {
             $score += $isMobile ? 6 : 8;
         }
         
         if ($timeDiff <= 1) {
             $score += 10;
         }
     }
     
     // 6. Множественные IP-адреса
     $uniqueIPs = array_unique($trackingData['ips'] ?? []);
     if (count($uniqueIPs) > 15) {
         $score += 8;
     }
     
     // 7. Проверка на повторные нарушения
     $userHash = $this->generateUserHash();
     $statsKey = $this->userHashPrefix . 'stats:' . $userHash;
     $blockCount = $this->redis->hget($statsKey, 'block_count') ?: 0;
     
     if ($blockCount > 2) {
         $score += $blockCount * 3;
     }
     
     return $score >= $blockThreshold;
 }
 
 public function protect() {
     if ($this->isStaticFile()) {
         return;
     }
     
     $ip = $this->getRealIP();
     $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
     
     if ($this->isLegitimateBot($userAgent)) {
         $this->logBotVisit($ip, $userAgent, 'legitimate');
         return;
     }
     
     if ($this->isVerifiedSearchEngine($ip, $userAgent)) {
         $this->logSearchEngineVisit($ip, $userAgent);
         return;
     }
     
     // 1. ПРОВЕРКА: блокировка по хешу пользователя
     if ($this->isUserHashBlocked()) {
         $this->sendBlockResponse();
     }
     
     // 2. ПРОВЕРКА: блокировка cookie
     if ($this->isCookieBlocked()) {
         $this->sendBlockResponse();
     }
     
     // 3. ПРОВЕРКА: блокировка IP ТОЛЬКО для подозрительных User-Agent
     if ($this->isBlocked($ip) && $this->isSuspiciousUserAgent($userAgent)) {
         $this->sendBlockResponse();
     }
     
     // 4. ПРОВЕРКА: валидный cookie
     if ($this->hasValidCookie()) {
         $this->trackUserHashActivity();
         
         if ($this->shouldAnalyzeIP($ip)) {
             if ($this->analyzeRequest($ip)) {
                 if ($this->isSuspiciousUserAgent($userAgent)) {
                     $this->blockIP($ip, 'Suspicious user agent with valid cookie');
                     $this->blockCookieHash();
                     $this->blockUserHash('Bot with valid cookie');
                 } else {
                     $this->blockUserHash('Browser behavior detected with valid cookie');
                     $this->blockCookieHash();
                 }
                 $this->sendBlockResponse();
             }
         }
         return;
     }
     
     // 5. АНАЛИЗ ДЛЯ НОВЫХ ПОЛЬЗОВАТЕЛЕЙ
     if ($this->shouldAnalyzeIP($ip)) {
         if ($this->analyzeRequest($ip)) {
             if ($this->isSuspiciousUserAgent($userAgent)) {
                 $this->blockIP($ip, 'Suspicious user agent detected');
                 if (isset($_COOKIE[$this->cookieName])) {
                     $this->blockCookieHash();
                 }
                 $this->blockUserHash('Bot detected');
             } else {
                 if (isset($_COOKIE[$this->cookieName])) {
                     $this->blockCookieHash();
                 } else {
                     $this->blockUserHash('Browser behavior detected without cookie');
                 }
             }
             $this->sendBlockResponse();
         }
     }
     
     // 6. АНАЛИЗ ПОВЕДЕНИЯ ПО ХЕШУ
     if ($this->analyzeUserHashBehavior()) {
         if ($this->isSuspiciousUserAgent($userAgent)) {
             $this->blockIP($ip, 'Bot behavior confirmed by user hash analysis');
             $this->blockUserHash('Bot confirmed');
             if (isset($_COOKIE[$this->cookieName])) {
                 $this->blockCookieHash();
             }
         } else {
             $this->blockUserHash('Browser acting like bot');
             if (isset($_COOKIE[$this->cookieName])) {
                 $this->blockCookieHash();
             }
         }
         
         $this->sendBlockResponse();
     }
     
     // 7. ИНИЦИАЛИЗАЦИЯ
     if (!isset($_COOKIE[$this->cookieName])) {
         $this->setVisitorCookie();
         $this->initTracking($ip);
     }
 }
 
 private function shouldAnalyzeIP($ip) {
     $trackingKey = $this->trackingPrefix . 'ip:' . hash('md5', $ip);
     $data = $this->redis->get($trackingKey);
     
     if ($data) {
         $requests = $data['requests'] ?? 0;
         $timeSpent = time() - ($data['first_seen'] ?? time());
         $suspicious_ua = $this->isSuspiciousUserAgent($_SERVER['HTTP_USER_AGENT'] ?? '');
         
         if ($suspicious_ua) {
             return true;
         }
         
         if ($requests > 5) {
             return true;
         }
         
         if ($timeSpent > 0 && $requests >= 5) {
             $requestsPerMinute = ($requests * 60) / $timeSpent;
             if ($requestsPerMinute > 40) {
                 return true;
             }
         }
         
         if (isset($data['request_times']) && count($data['request_times']) >= 7) {
             $recentTimes = array_slice($data['request_times'], -7);
             $timeSpan = end($recentTimes) - reset($recentTimes);
             if ($timeSpan <= 20) {
                 return true;
             }
         }
     }
     
     return false;
 }
 
 private function isSuspiciousUserAgent($userAgent) {
     $suspiciousPatterns = [
         'curl', 'wget', 'python', 'java/', 'go-http', 'node-fetch', 
         'libwww', 'scrapy', 'requests', 'urllib', 'httpie', 'bot', 'spider',
         'crawler', 'scraper', 'postman', 'insomnia'
     ];
     
     $userAgent = strtolower($userAgent);
     
     foreach ($suspiciousPatterns as $pattern) {
         if (strpos($userAgent, $pattern) !== false) {
             return true;
         }
     }
     
     return false;
 }
 
 private function isLegitimateBot($userAgent) {
     $legitimateBots = [
         'uptimerobot', 'pingdom', 'statuscake', 'site24x7',
         'cloudflare', 'fastly', 'keycdn'
     ];
     
     $userAgent = strtolower($userAgent);
     
     foreach ($legitimateBots as $bot) {
         if (strpos($userAgent, $bot) !== false) {
             return true;
         }
     }
     
     return false;
 }
 
 // БЕЗ ЛОГИРОВАНИЯ легитимных ботов
 private function logBotVisit($ip, $userAgent, $type) {
     $logEntry = [
         'timestamp' => date('Y-m-d H:i:s'),
         'ip' => $ip,
         'user_agent' => $userAgent,
         'type' => $type,
         'uri' => $_SERVER['REQUEST_URI'] ?? ''
     ];
     
     $logKey = 'logs:legitimate_bots:' . date('Y-m-d');
     $this->redis->lpush($logKey, $logEntry);
     $this->redis->expire($logKey, $this->ttlSettings['logs']);
     $this->redis->ltrim($logKey, 0, 999);
 }
 
 /**
  * УЛУЧШЕННАЯ проверка поисковиков с быстрым rDNS
  */
 private function isVerifiedSearchEngine($ip, $userAgent) {
     // Сначала быстрая проверка User-Agent
     $detectedEngine = null;
     foreach ($this->allowedSearchEngines as $engine => $config) {
         foreach ($config['user_agent_patterns'] as $pattern) {
             if (stripos($userAgent, $pattern) !== false) {
                 $detectedEngine = $engine;
                 break 2;
             }
         }
     }
     
     if (!$detectedEngine) {
         return false;
     }
     
     // Проверяем rDNS с улучшенной логикой
     return $this->verifySearchEngineByRDNS($ip, $this->allowedSearchEngines[$detectedEngine]['rdns_patterns']);
 }
 
 /**
  * УЛУЧШЕННАЯ функция проверки rDNS с поддержкой IPv4/IPv6
  * Быстрая, надежная, с кэшированием и таймаутами
  */
 private function verifySearchEngineByRDNS($ip, $allowedPatterns) {
     // Нормализуем IP
     $normalizedIP = $this->normalizeIP($ip);
     $cacheKey = $this->rdnsPrefix . 'cache:' . hash('md5', $normalizedIP);
     
     // Проверяем кэш
     $cached = $this->redis->get($cacheKey);
     if ($cached !== false) {
         return $cached['verified'];
     }
     
     $verified = false;
     $hostname = '';
     $error = '';
     
     try {
         // ЭТАП 1: Обратный DNS (IP → hostname)
         $hostname = $this->getHostnameWithTimeout($normalizedIP, 2); // 2 сек таймаут
         
         if ($hostname && $hostname !== $normalizedIP) {
             // ЭТАП 2: Проверяем, что hostname соответствует разрешенным паттернам
             $hostnameMatches = false;
             foreach ($allowedPatterns as $pattern) {
                 if ($this->matchesDomainPattern($hostname, $pattern)) {
                     $hostnameMatches = true;
                     break;
                 }
             }
             
             if ($hostnameMatches) {
                 // ЭТАП 3: Прямой DNS (hostname → IP) для подтверждения
                 $forwardIPs = $this->getIPsWithTimeout($hostname, 2); // 2 сек таймаут
                 
                 if ($forwardIPs && $this->ipInArray($normalizedIP, $forwardIPs)) {
                     $verified = true;
                 }
             }
         }
         
     } catch (Exception $e) {
         $error = $e->getMessage();
     }
     
     // Кэшируем результат (включая неудачные попытки)
     $cacheData = [
         'ip' => $normalizedIP,
         'hostname' => $hostname,
         'verified' => $verified,
         'timestamp' => time(),
         'error' => $error
     ];
     
     // Кэшируем успешные проверки на 15 мин, неудачные на 5 мин
     $cacheTTL = $verified ? $this->ttlSettings['rdns_cache'] : 300;
     $this->redis->setex($cacheKey, $cacheTTL, $cacheData);
     
     return $verified;
 }
 
 /**
  * НОВАЯ функция: получение hostname с таймаутом
  */
 private function getHostnameWithTimeout($ip, $timeoutSec = 2) {
     // Устанавливаем таймаут для DNS запросов
     $originalTimeout = ini_get('default_socket_timeout');
     ini_set('default_socket_timeout', $timeoutSec);
     
     try {
         $hostname = gethostbyaddr($ip);
         
         // Возвращаем исходный таймаут
         ini_set('default_socket_timeout', $originalTimeout);
         
         // gethostbyaddr возвращает IP при неудаче
         return ($hostname !== $ip) ? $hostname : false;
         
     } catch (Exception $e) {
         ini_set('default_socket_timeout', $originalTimeout);
         return false;
     }
 }
 
 /**
  * НОВАЯ функция: получение IP списка с таймаутом 
  */
 private function getIPsWithTimeout($hostname, $timeoutSec = 2) {
     $originalTimeout = ini_get('default_socket_timeout');
     ini_set('default_socket_timeout', $timeoutSec);
     
     $allIPs = [];
     
     try {
         // Получаем IPv4 адреса
         $ipv4List = gethostbynamel($hostname);
         if ($ipv4List) {
             $allIPs = array_merge($allIPs, $ipv4List);
         }
         
         // Получаем IPv6 адреса (если доступно)
         if (function_exists('dns_get_record')) {
             $records = @dns_get_record($hostname, DNS_AAAA);
             if ($records) {
                 foreach ($records as $record) {
                     if (isset($record['ipv6'])) {
                         $allIPs[] = $this->normalizeIPv6($record['ipv6']);
                     }
                 }
             }
         }
         
         ini_set('default_socket_timeout', $originalTimeout);
         return array_unique($allIPs);
         
     } catch (Exception $e) {
         ini_set('default_socket_timeout', $originalTimeout);
         return [];
     }
 }
 
 /**
  * НОВАЯ функция: проверка соответствия домена паттерну
  */
 private function matchesDomainPattern($hostname, $pattern) {
     $hostname = strtolower(trim($hostname));
     $pattern = strtolower(trim($pattern));
     
     // Точное совпадение
     if ($hostname === $pattern) {
         return true;
     }
     
     // Паттерн начинается с точки = проверяем суффикс
     if (strpos($pattern, '.') === 0) {
         return substr($hostname, -strlen($pattern)) === $pattern;
     }
     
     // Иначе проверяем, что hostname заканчивается на .$pattern
     $fullPattern = '.' . $pattern;
     return substr($hostname, -strlen($fullPattern)) === $fullPattern;
 }
 
 /**
  * НОВАЯ функция: проверка наличия IP в массиве (с учетом нормализации)
  */
 private function ipInArray($needle, $haystack) {
     $normalizedNeedle = $this->normalizeIP($needle);
     
     foreach ($haystack as $ip) {
         if ($this->normalizeIP($ip) === $normalizedNeedle) {
             return true;
         }
     }
     
     return false;
 }
 
 // БЕЗ ЛОГИРОВАНИЯ поисковиков
 private function logSearchEngineVisit($ip, $userAgent) {
     $logEntry = [
         'timestamp' => date('Y-m-d H:i:s'),
         'ip' => $ip,
         'user_agent' => $userAgent,
         'uri' => $_SERVER['REQUEST_URI'] ?? '',
         'hostname' => gethostbyaddr($ip)
     ];
     
     $logKey = 'logs:search_engines:' . date('Y-m-d');
     $this->redis->lpush($logKey, $logEntry);
     $this->redis->expire($logKey, $this->ttlSettings['logs']);
     $this->redis->ltrim($logKey, 0, 999);
 }
 
 private function getRealIP() {
     $ipHeaders = [
         'HTTP_CF_CONNECTING_IP',
         'HTTP_X_REAL_IP',
         'HTTP_X_FORWARDED_FOR',
         'HTTP_X_FORWARDED',
         'HTTP_X_CLUSTER_CLIENT_IP',
         'HTTP_FORWARDED_FOR',
         'HTTP_FORWARDED',
         'REMOTE_ADDR'
     ];
     
     foreach ($ipHeaders as $header) {
         if (!empty($_SERVER[$header])) {
             $ips = explode(',', $_SERVER[$header]);
             $ip = trim($ips[0]);
             
             if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                 $ip = $this->normalizeIPv6($ip);
             }
             
             if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                 if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                     return $ip;
                 }
             } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                 if (!$this->isPrivateIPv6($ip)) {
                     return $ip;
                 }
             }
         }
     }
     
     $remoteAddr = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
     if ($remoteAddr !== 'unknown' && filter_var($remoteAddr, FILTER_VALIDATE_IP)) {
         if (filter_var($remoteAddr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
             return $this->normalizeIPv6($remoteAddr);
         }
         return $remoteAddr;
     }
     
     return 'unknown';
 }
 
 private function isPrivateIPv6($ip) {
     $privateRanges = [
         '::1',
         'fe80::/10',
         'fc00::/7',
         'ff00::/8',
     ];
     
     foreach ($privateRanges as $range) {
         if ($this->ipInRange($ip, $range)) {
             return true;
         }
     }
     
     return false;
 }
 
 private function ipInRange($ip, $range) {
     if (strpos($range, '/') === false) {
         return $ip === $range;
     }
     
     list($subnet, $prefix) = explode('/', $range);
     
     $ipBin = inet_pton($ip);
     $subnetBin = inet_pton($subnet);
     
     if ($ipBin === false || $subnetBin === false) {
         return false;
     }
     
     $ipFamily = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? AF_INET6 : AF_INET;
     $subnetFamily = filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? AF_INET6 : AF_INET;
     
     if ($ipFamily !== $subnetFamily) {
         return false;
     }
     
     $maxBits = $ipFamily === AF_INET6 ? 128 : 32;
     $prefix = max(0, min($maxBits, (int)$prefix));
     
     $bytesToCheck = intval($prefix / 8);
     $bitsInLastByte = $prefix % 8;
     
     for ($i = 0; $i < $bytesToCheck; $i++) {
         if ($ipBin[$i] !== $subnetBin[$i]) {
             return false;
         }
     }
     
     if ($bitsInLastByte > 0) {
         $mask = 0xFF << (8 - $bitsInLastByte);
         if ((ord($ipBin[$bytesToCheck]) & $mask) !== (ord($subnetBin[$bytesToCheck]) & $mask)) {
             return false;
         }
     }
     
     return true;
 }
 
 private function isStaticFile() {
     $uri = $_SERVER['REQUEST_URI'] ?? '';
     $staticExtensions = [
         '.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.ico', '.svg', 
         '.woff', '.woff2', '.ttf', '.eot', '.otf', '.webp', '.avif',
         '.pdf', '.zip', '.mp4', '.webm', '.mp3', '.wav', '.txt'
     ];
     
     foreach ($staticExtensions as $ext) {
         if (substr($uri, -strlen($ext)) === $ext) {
             return true;
         }
     }
     return false;
 }
 
 private function hasValidCookie() {
     if (!isset($_COOKIE[$this->cookieName])) {
         return false;
     }
     
     $data = json_decode($_COOKIE[$this->cookieName], true);
     if (!$data || !isset($data['hash'], $data['time'])) {
         return false;
     }
     
     if (time() - $data['time'] > $this->cookieLifetime) {
         return false;
     }
     
     $expected = hash('sha256', $data['time'] . ($_SERVER['HTTP_USER_AGENT'] ?? '') . $this->secretKey);
     return hash_equals($expected, $data['hash']);
 }
 
 private function setVisitorCookie() {
     $time = time();
     $hash = hash('sha256', $time . ($_SERVER['HTTP_USER_AGENT'] ?? '') . $this->secretKey);
     $cookieData = json_encode(['time' => $time, 'hash' => $hash]);
     
     $secure = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
     setcookie($this->cookieName, $cookieData, time() + $this->cookieLifetime, '/', '', $secure, true);
     $_COOKIE[$this->cookieName] = $cookieData;
 }
 
 private function initTracking($ip) {
     $trackingKey = $this->trackingPrefix . 'ip:' . hash('md5', $ip);
     $existing = $this->redis->get($trackingKey);
     
     if ($existing) {
         $existing['requests']++;
         $existing['pages'][] = parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH);
         $existing['user_agents'][] = $_SERVER['HTTP_USER_AGENT'] ?? '';
         $existing['user_agents'] = array_unique($existing['user_agents']);
         $existing['request_times'][] = time();
         
         if (count($existing['request_times']) > 15) {
             $existing['request_times'] = array_slice($existing['request_times'], -15);
         }
         if (count($existing['pages']) > 20) {
             $existing['pages'] = array_slice($existing['pages'], -20);
         }
         if (count($existing['user_agents']) > 3) {
             $existing['user_agents'] = array_slice($existing['user_agents'], -3);
         }
         
         $this->redis->setex($trackingKey, $this->ttlSettings['tracking_ip'], $existing);
     } else {
         $data = [
             'first_seen' => time(),
             'requests' => 1,
             'pages' => [parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH)],
             'user_agents' => [$_SERVER['HTTP_USER_AGENT'] ?? ''],
             'headers' => $this->collectHeaders(),
             'session_id' => 'no_session',
             'request_times' => [time()]
         ];
         
         $this->redis->setex($trackingKey, $this->ttlSettings['tracking_ip'], $data);
     }
 }
 
 private function collectHeaders() {
     $headers = [];
     $importantHeaders = [
         'HTTP_USER_AGENT', 'HTTP_ACCEPT', 'HTTP_ACCEPT_LANGUAGE', 
         'HTTP_ACCEPT_ENCODING', 'HTTP_REFERER', 'HTTP_X_FORWARDED_FOR'
     ];
     
     foreach ($importantHeaders as $header) {
         if (isset($_SERVER[$header])) {
             $headers[$header] = $_SERVER[$header];
         }
     }
     return $headers;
 }
 
 // ЛОГИРУЕМ ТОЛЬКО ФАКТ БЛОКИРОВКИ COOKIE
 private function blockCookieHash() {
     if (!isset($_COOKIE[$this->cookieName])) {
         return;
     }
     
     $data = json_decode($_COOKIE[$this->cookieName], true);
     if (!$data || !isset($data['hash'])) {
         return;
     }
     
     $blockKey = $this->cookiePrefix . 'blocked:' . hash('md5', $data['hash']);
     $blockData = [
         'cookie_hash' => $data['hash'],
         'blocked_at' => time(),
         'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
         'uri' => $_SERVER['REQUEST_URI'] ?? '',
         'session_id' => 'no_session',
         'ip' => $this->getRealIP()
     ];
     
     $this->redis->setex($blockKey, $this->ttlSettings['cookie_blocked'], $blockData);
     
     // КРАТКОЕ ЛОГИРОВАНИЕ
     error_log("Bot blocked [COOKIE]: " . substr($data['hash'], 0, 8) . " | IP: " . $this->getRealIP());
 }
 
 private function isCookieBlocked() {
     if (!isset($_COOKIE[$this->cookieName])) {
         return false;
     }
     
     $data = json_decode($_COOKIE[$this->cookieName], true);
     if (!$data || !isset($data['hash'])) {
         return false;
     }
     
     $blockKey = $this->cookiePrefix . 'blocked:' . hash('md5', $data['hash']);
     return $this->redis->exists($blockKey);
 }
 
 private function isMobileDevice($userAgent) {
     $mobilePatterns = [
         'Mobile', 'Android', 'iPhone', 'iPad', 'iPod', 
         'Mobile Safari', 'Chrome Mobile', 'Firefox Mobile', 'Opera Mini', 'Opera Mobi',
         'BlackBerry', 'Windows Phone', 'IEMobile', 'Kindle', 'Silk',
         'Tablet', 'PlayBook',
         'webOS', 'hpwOS', 'Bada', 'Tizen', 'NetFront', 'Fennec'
     ];
     
     $userAgent = strtolower($userAgent);
     
     foreach ($mobilePatterns as $pattern) {
         if (stripos($userAgent, strtolower($pattern)) !== false) {
             return true;
         }
     }
     
     $mobileRegex = '/mobile|android|iphone|ipad|ipod|blackberry|iemobile|opera m(ob|in)i/i';
     if (preg_match($mobileRegex, $userAgent)) {
         return true;
     }
     
     return false;
 }
 
 // БЕЗ ДЕТАЛЬНОГО ЛОГИРОВАНИЯ
 private function analyzeRequest($ip) {
     $trackingKey = $this->trackingPrefix . 'ip:' . hash('md5', $ip);
     $data = $this->redis->get($trackingKey);
     
     if (!$data) {
         return false;
     }
     
     $score = 0;
     $currentUA = $_SERVER['HTTP_USER_AGENT'] ?? '';
     $isMobile = $this->isMobileDevice($currentUA);
     
     $blockThreshold = $isMobile ? 20 : 18;
     
     if ($this->isSuspiciousUserAgent($currentUA)) {
         $score += $isMobile ? 15 : 20;
     }
     
     $requests = $data['requests'] ?? 0;
     $timeSpent = time() - ($data['first_seen'] ?? time());
     
     if ($timeSpent > 0) {
         $requestsPerMinute = ($requests * 60) / $timeSpent;
         
         if ($isMobile) {
             if ($requestsPerMinute > 180) $score += 12;
             elseif ($requestsPerMinute > 120) $score += 8;
             elseif ($requestsPerMinute > 80) $score += 4;
         } else {
             if ($requestsPerMinute > 150) $score += 12;
             elseif ($requestsPerMinute > 100) $score += 8;
             elseif ($requestsPerMinute > 60) $score += 4;
         }
     }
     
     $cookieLimit = $isMobile ? 35 : 30;
     if ($requests > $cookieLimit && !isset($_COOKIE[$this->cookieName])) {
         $score += $isMobile ? 3 : 4;
     }
     
     $currentHeaders = $this->collectHeaders();
     
     if (!isset($currentHeaders['HTTP_ACCEPT']) || $currentHeaders['HTTP_ACCEPT'] === '*/*') {
         $score += $isMobile ? 1 : 2;
     }
     if (!isset($currentHeaders['HTTP_ACCEPT_LANGUAGE'])) {
         $score += $isMobile ? 1 : 2;
     }
     if (!isset($currentHeaders['HTTP_ACCEPT_ENCODING'])) {
         $score += $isMobile ? 1 : 2;
     }
     
     $uniquePages = array_unique($data['pages'] ?? []);
     $totalPages = count($data['pages'] ?? []);
     
     $pageLimit = $isMobile ? 50 : 40;
     if ($totalPages > $pageLimit && count($uniquePages) <= 2) {
         $score += $isMobile ? 2 : 3;
     }
     
     $uniqueUA = array_unique($data['user_agents'] ?? []);
     if (count($uniqueUA) > 5) {
         $score += 8;
     }
     
     if (isset($data['request_times']) && count($data['request_times']) >= 15) {
         $intervals = [];
         $lastFifteen = array_slice($data['request_times'], -15);
         
         for ($i = 1; $i < count($lastFifteen); $i++) {
             $intervals[] = $lastFifteen[$i] - $lastFifteen[$i-1];
         }
         
         if (count($intervals) >= 12) {
             $avgInterval = array_sum($intervals) / count($intervals);
             $variance = 0;
             foreach ($intervals as $interval) {
                 $variance += pow($interval - $avgInterval, 2);
             }
             $variance /= count($intervals);
             
             $varianceThreshold = $isMobile ? 1.0 : 1.5;
             $intervalThreshold = $isMobile ? 3 : 5;
             
             if ($variance < $varianceThreshold && $avgInterval < $intervalThreshold) {
                 $score += $isMobile ? 3 : 5;
             }
         }
     }
     
     if (isset($data['request_times']) && count($data['request_times']) >= 10) {
         $lastTen = array_slice($data['request_times'], -10);
         $timeDiff = end($lastTen) - reset($lastTen);
         
         if ($timeDiff <= 5) {
             $score += $isMobile ? 3 : 5;
         }
         if ($timeDiff <= 2) {
             $score += 6;
         }
     }
     
     return $score >= $blockThreshold;
 }
 
 private function isBlocked($ip) {
     $blockKey = $this->blockPrefix . 'ip:' . hash('md5', $ip);
     return $this->redis->exists($blockKey);
 }
 
 // ЛОГИРУЕМ ТОЛЬКО ФАКТ БЛОКИРОВКИ IP
 private function blockIP($ip, $reason = 'Bot behavior detected') {
     $blockKey = $this->blockPrefix . 'ip:' . hash('md5', $ip);
     
     $isRepeatOffender = $this->redis->exists($blockKey);
     
     $blockData = [
         'ip' => $ip,
         'blocked_at' => time(),
         'blocked_reason' => $reason,
         'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
         'uri' => $_SERVER['REQUEST_URI'] ?? '',
         'session_id' => 'no_session',
         'repeat_offender' => $isRepeatOffender,
         'is_suspicious_ua' => $this->isSuspiciousUserAgent($_SERVER['HTTP_USER_AGENT'] ?? ''),
         'browser_info' => $this->getBrowserFingerprint($_SERVER['HTTP_USER_AGENT'] ?? '')
     ];
     
     $blockDuration = $isRepeatOffender ? $this->ttlSettings['ip_blocked_repeat'] : $this->ttlSettings['ip_blocked'];
     $this->redis->setex($blockKey, $blockDuration, $blockData);
     
     // КРАТКОЕ ЛОГИРОВАНИЕ
     $durHours = round($blockDuration / 3600);
     error_log("Bot blocked [IP]: $ip | " . ($isRepeatOffender ? "REPEAT | " : "") . "{$durHours}h | $reason");
 }
 
 private function sendBlockResponse() {
     if (!headers_sent()) {
         http_response_code(429);
         header('Content-Type: text/plain; charset=utf-8');
         header('Retry-After: 900');
     }
     die('Rate limit exceeded. Please try again later.');
 }
 
 /**
  * ФУНКЦИЯ ДЛЯ ТЕСТИРОВАНИЯ rDNS (используйте для отладки)
  */
 public function testRDNS($ip, $userAgent = '') {
     $normalizedIP = $this->normalizeIP($ip);
     
     echo "=== ТЕСТ rDNS для IP: $ip ===\n";
     echo "Нормализованный IP: $normalizedIP\n";
     echo "User-Agent: $userAgent\n\n";
     
     // Определяем поисковик по UA
     $detectedEngine = null;
     if ($userAgent) {
         foreach ($this->allowedSearchEngines as $engine => $config) {
             foreach ($config['user_agent_patterns'] as $pattern) {
                 if (stripos($userAgent, $pattern) !== false) {
                     $detectedEngine = $engine;
                     break 2;
                 }
             }
         }
     }
     
     echo "Обнаруженный поисковик: " . ($detectedEngine ?: 'НЕ НАЙДЕН') . "\n";
     
     if (!$detectedEngine) {
         echo "❌ User-Agent не соответствует известным поисковикам\n";
         return false;
     }
     
     $allowedPatterns = $this->allowedSearchEngines[$detectedEngine]['rdns_patterns'];
     echo "Разрешенные домены: " . implode(', ', $allowedPatterns) . "\n\n";
     
     // Обратный DNS
     echo "🔍 Шаг 1: Обратный DNS (IP → hostname)\n";
     $hostname = $this->getHostnameWithTimeout($normalizedIP, 3);
     echo "Результат: " . ($hostname ?: 'НЕ НАЙДЕН') . "\n\n";
     
     if (!$hostname) {
         echo "❌ rDNS не найден\n";
         return false;
     }
     
     // Проверка паттерна
     echo "🔍 Шаг 2: Проверка домена\n";
     $hostnameMatches = false;
     foreach ($allowedPatterns as $pattern) {
         if ($this->matchesDomainPattern($hostname, $pattern)) {
             echo "✅ Hostname '$hostname' соответствует паттерну '$pattern'\n";
             $hostnameMatches = true;
             break;
         }
     }
     
     if (!$hostnameMatches) {
         echo "❌ Hostname '$hostname' НЕ соответствует разрешенным паттернам\n";
         return false;
     }
     
     // Прямой DNS
     echo "\n🔍 Шаг 3: Прямой DNS (hostname → IP)\n";
     $forwardIPs = $this->getIPsWithTimeout($hostname, 3);
     echo "Найденные IP: " . implode(', ', $forwardIPs) . "\n";
     
     if ($this->ipInArray($normalizedIP, $forwardIPs)) {
         echo "✅ IP подтвержден прямым DNS\n";
         echo "🎉 РЕЗУЛЬТАТ: Легитимный поисковик\n";
         return true;
     } else {
         echo "❌ IP НЕ найден в прямом DNS\n";
         echo "❌ РЕЗУЛЬТАТ: Подозрительный запрос\n";
         return false;
     }
 }
 
 // МЕТОДЫ ДЛЯ АДМИНИСТРИРОВАНИЯ (с минимальным логированием)
 
 public function getUserHashInfo($userHash = null) {
     $userHash = $userHash ?: $this->generateUserHash();
     
     $blockKey = $this->userHashPrefix . 'blocked:' . $userHash;
     $trackingKey = $this->userHashPrefix . 'tracking:' . $userHash;
     $statsKey = $this->userHashPrefix . 'stats:' . $userHash;
     
     return [
         'user_hash' => $userHash,
         'hash_preview' => substr($userHash, 0, 16) . '...',
         'blocked' => $this->redis->exists($blockKey),
         'block_data' => $this->redis->get($blockKey),
         'tracking_data' => $this->redis->get($trackingKey),
         'stats' => $this->redis->hgetall($statsKey),
         'block_ttl' => $this->redis->ttl($blockKey),
         'tracking_ttl' => $this->redis->ttl($trackingKey)
     ];
 }
 
 public function unblockUserHash($userHash = null) {
     $userHash = $userHash ?: $this->generateUserHash();
     
     $blockKey = $this->userHashPrefix . 'blocked:' . $userHash;
     $trackingKey = $this->userHashPrefix . 'tracking:' . $userHash;
     
     $result = [
         'user_hash' => substr($userHash, 0, 16) . '...',
         'unblocked' => $this->redis->del($blockKey) > 0,
         'tracking_cleared' => $this->redis->del($trackingKey) > 0
     ];
     
     // ЛОГИРУЕМ РАЗБЛОКИРОВКУ
     error_log("UNBLOCKED [HASH]: " . substr($userHash, 0, 8) . " | Manual");
     return $result;
 }
 
 // БЕЗ ЛОГИРОВАНИЯ диагностики
 public function diagnoseUserHash() {
     $ip = $this->getRealIP();
     $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
     $browserInfo = $this->getBrowserFingerprint($userAgent);
     $isMobile = $this->isMobileDevice($userAgent);
     
     $userHash = $this->generateUserHash();
     
     return [
         'stable_hash' => substr($userHash, 0, 16) . '...',
         'ip' => $ip,
         'ip_fingerprint' => $isMobile ? $this->getIPFingerprint($ip) : $ip,
         'device_type' => $isMobile ? 'mobile' : 'desktop',
         'browser' => $browserInfo,
         'session_id' => 'no_session',
         'user_agent' => substr($userAgent, 0, 100) . '...',
         'accept_language' => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? 'none',
         'accept_encoding' => $_SERVER['HTTP_ACCEPT_ENCODING'] ?? 'none'
     ];
 }
 
 public function getUserHashStats() {
     $stats = [
         'blocked_user_hashes' => 0,
         'tracked_user_hashes' => 0,
         'total_hash_blocks' => 0
     ];
     
     try {
         $blockedHashes = $this->redis->keys($this->userHashPrefix . 'blocked:*');
         $stats['blocked_user_hashes'] = count($blockedHashes);
         
         $trackedHashes = $this->redis->keys($this->userHashPrefix . 'tracking:*');
         $stats['tracked_user_hashes'] = count($trackedHashes);
         
         $statsKeys = $this->redis->keys($this->userHashPrefix . 'stats:*');
         $totalBlocks = 0;
         foreach ($statsKeys as $key) {
             $blockCount = $this->redis->hget($key, 'block_count') ?: 0;
             $totalBlocks += intval($blockCount);
         }
         $stats['total_hash_blocks'] = $totalBlocks;
         
     } catch (Exception $e) {
         error_log("Error getting user hash stats: " . $e->getMessage());
     }
     
     return $stats;
 }
 
 public function cleanupUserHashData() {
     $cleaned = 0;
     
     try {
         $patterns = [
             $this->userHashPrefix . 'blocked:*',
             $this->userHashPrefix . 'tracking:*',
             $this->userHashPrefix . 'stats:*'
         ];
         
         foreach ($patterns as $pattern) {
             $keys = $this->redis->keys($pattern);
             foreach ($keys as $key) {
                 $ttl = $this->redis->ttl($key);
                 if ($ttl === -1 || $ttl === -2) {
                     $this->redis->del($key);
                     $cleaned++;
                 }
             }
         }
         
     } catch (Exception $e) {
         error_log("User hash cleanup error: " . $e->getMessage());
     }
     
     return $cleaned;
 }
 
 public function getStats() {
     $stats = [
         'blocked_ips' => 0,
         'blocked_cookies' => 0,
         'tracking_records' => 0,
         'total_keys' => 0,
         'memory_usage' => 0
     ];
     
     try {
         $blockedIPs = $this->redis->keys($this->blockPrefix . 'ip:*');
         $stats['blocked_ips'] = count($blockedIPs);
         
         $blockedCookies = $this->redis->keys($this->cookiePrefix . 'blocked:*');
         $stats['blocked_cookies'] = count($blockedCookies);
         
         $trackingRecords = $this->redis->keys($this->trackingPrefix . 'ip:*');
         $stats['tracking_records'] = count($trackingRecords);
         
         $allKeys = $this->redis->keys('*');
         $stats['total_keys'] = count($allKeys);
         
         $info = $this->redis->info('memory');
         $stats['memory_usage'] = $info['used_memory_human'] ?? 'unknown';
         
         $userHashStats = $this->getUserHashStats();
         $stats = array_merge($stats, $userHashStats);
         
     } catch (Exception $e) {
         error_log("Error getting stats: " . $e->getMessage());
     }
     
     return $stats;
 }
 
 // БЕЗ ЛОГИРОВАНИЯ очистки
 public function cleanup($force = false) {
     try {
         $cleaned = 0;
         $startTime = microtime(true);
         
         $cleanupPatterns = [
             ['pattern' => $this->trackingPrefix . 'ip:*', 'priority' => 1],
             ['pattern' => $this->rdnsPrefix . 'cache:*', 'priority' => 1],
             ['pattern' => $this->userHashPrefix . 'tracking:*', 'priority' => 1],
             ['pattern' => $this->blockPrefix . 'ip:*', 'priority' => 2],
             ['pattern' => $this->cookiePrefix . 'blocked:*', 'priority' => 2],
             ['pattern' => $this->userHashPrefix . 'blocked:*', 'priority' => 2],
             ['pattern' => 'logs:*', 'priority' => 3]
         ];
         
         foreach ($cleanupPatterns as $patternInfo) {
             if (!$force && (microtime(true) - $startTime) > 2) break;
             
             $keys = $this->redis->keys($patternInfo['pattern']);
             foreach ($keys as $key) {
                 if (!$force && (microtime(true) - $startTime) > 2) break;
                 
                 $ttl = $this->redis->ttl($key);
                 
                 if ($ttl === -1) {
                     $this->redis->del($key);
                     $cleaned++;
                 } elseif ($ttl === -2) {
                     continue;
                 }
                 
                 if (strpos($key, 'logs:') === 0) {
                     $keyParts = explode(':', $key);
                     if (count($keyParts) >= 3) {
                         $logDate = end($keyParts);
                         $logTime = strtotime($logDate);
                         if ($logTime && (time() - $logTime) > $this->ttlSettings['logs']) {
                             $this->redis->del($key);
                             $cleaned++;
                         }
                     }
                 }
                 
                 if ($this->redis->type($key) === Redis::REDIS_LIST) {
                     $listSize = $this->redis->llen($key);
                     if ($listSize > 500) {
                         $this->redis->ltrim($key, 0, 499);
                         $cleaned++;
                     }
                 }
             }
         }
         
         return $cleaned;
         
     } catch (Exception $e) {
         error_log("Cleanup error: " . $e->getMessage());
         return false;
     }
 }
 
 // БЕЗ ЛОГИРОВАНИЯ глубокой очистки
 public function deepCleanup() {
     try {
         $totalCleaned = 0;
         
         for ($i = 2; $i <= 14; $i++) {
             $oldDate = date('Y-m-d', time() - ($i * 86400));
             $patterns = [
                 'logs:legitimate_bots:' . $oldDate,
                 'logs:search_engines:' . $oldDate,
                 'logs:blocked:' . $oldDate
             ];
             
             foreach ($patterns as $pattern) {
                 if ($this->redis->exists($pattern)) {
                     $this->redis->del($pattern);
                     $totalCleaned++;
                 }
             }
         }
         
         $this->cleanup(true);
         $totalCleaned += $this->cleanupUserHashData();
         
         try {
             $this->redis->bgrewriteaof();
         } catch (Exception $e) {
             // Игнорируем ошибки AOF
         }
         
         return $totalCleaned;
         
     } catch (Exception $e) {
         error_log("Deep cleanup error: " . $e->getMessage());
         return false;
     }
 }
 
 public function unblockIP($ip) {
     $blockKey = $this->blockPrefix . 'ip:' . hash('md5', $ip);
     $trackingKey = $this->trackingPrefix . 'ip:' . hash('md5', $ip);
     
     $result = [
         'ip_unblocked' => $this->redis->del($blockKey) > 0,
         'tracking_cleared' => $this->redis->del($trackingKey) > 0
     ];
     
     // ЛОГИРУЕМ РАЗБЛОКИРОВКУ
     error_log("UNBLOCKED [IP]: $ip | Manual");
     return $result;
 }
 
 public function getBlockedIPInfo($ip) {
     $blockKey = $this->blockPrefix . 'ip:' . hash('md5', $ip);
     $trackingKey = $this->trackingPrefix . 'ip:' . hash('md5', $ip);
     
     return [
         'blocked' => $this->redis->exists($blockKey),
         'block_data' => $this->redis->get($blockKey),
         'tracking_data' => $this->redis->get($trackingKey),
         'ttl' => $this->redis->ttl($blockKey)
     ];
 }
 
 public function getTTLSettings() {
     return $this->ttlSettings;
 }
 
 public function updateTTLSettings($newSettings) {
     $this->ttlSettings = array_merge($this->ttlSettings, $newSettings);
     error_log("TTL settings updated: " . json_encode($newSettings));
 }
 
 public function __destruct() {
     if ($this->redis) {
         try {
             $this->redis->close();
         } catch (Exception $e) {
             // Игнорируем ошибки при закрытии соединения
         }
     }
 }
}

// ИСПОЛЬЗОВАНИЕ ФИНАЛЬНОЙ ВЕРСИИ:
try {
 $protection = new RedisBotProtectionNoSessions(
     '127.0.0.1',    // Redis host
     6379,           // Redis port
     null,           // Redis password (если нужен)
     0               // Redis database
 );
 
 $protection->protect();
 
 // ПРИМЕРЫ ТЕСТИРОВАНИЯ rDNS (раскомментируйте для тестов):
 // $protection->testRDNS('66.249.66.1', 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)');
 // $protection->testRDNS('40.77.167.181', 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)');
 // $protection->testRDNS('1.2.3.4', 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)');
 
} catch (Exception $e) {
 error_log("CRITICAL: Bot protection failed - " . $e->getMessage());
 // В случае ошибки Redis - продолжаем работу без защиты
}
?>
