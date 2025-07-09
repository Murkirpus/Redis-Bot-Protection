<?php
// /var/www/your-site/bot_protection/redis_inline_check.php

class RedisBotProtectionWithSessions {
 private $redis;
 private $cookieName = 'visitor_verified';
 private $secretKey = 'your_secret_key_here_change_this';
 private $cookieLifetime = 86400 * 30; // 30 дней
 
 // Префиксы для Redis ключей
 private $redisPrefix = 'bot_protection:';
 private $trackingPrefix = 'tracking:';
 private $blockPrefix = 'blocked:';
 private $sessionPrefix = 'session:';
 private $cookiePrefix = 'cookie:';
 private $rdnsPrefix = 'rdns:';
 private $userHashPrefix = 'user_hash:'; // Префикс для блокировки по хешу пользователя
 
 // ОПТИМИЗИРОВАННЫЕ TTL (в секундах) - сократил в 2-4 раза
 private $ttlSettings = [
     'tracking_ip' => 1800,          // было 3600 (1ч) → 30 мин
     'session_data' => 3600,         // было 7200 (2ч) → 1 час  
     'session_blocked' => 10800,     // было 21600 (6ч) → 3 часа
     'cookie_blocked' => 7200,       // было 14400 (4ч) → 2 часа
     'ip_blocked' => 900,            // было 1800 (30мин) → 15 мин
     'ip_blocked_repeat' => 3600,    // было 7200 (2ч) → 1 час
     'rdns_cache' => 900,            // было 1800 (30мин) → 15 мин
     'logs' => 86400,                // было 172800 (2дня) → 1 день
     'cleanup_interval' => 900,      // было 1800 (30мин) → 15 мин
     'user_hash_blocked' => 3600,    // было 7200 (2ч) → 1 час
     'user_hash_tracking' => 1800,   // было 3600 (1ч) → 30 мин
     'user_hash_stats' => 172800,    // было 604800 (7дней) → 2 дня
 ];
 
 // Разрешенные поисковики с их rDNS паттернами
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
         error_log("Redis connection failed: " . $e->getMessage());
         die('Service temporarily unavailable. Please try again later.');
     }
 }
 
 // ОПТИМИЗИРОВАННАЯ автоматическая очистка каждые 15 минут
 private function autoCleanup() {
     $lastCleanupKey = 'last_cleanup';
     $lastCleanup = $this->redis->get($lastCleanupKey);
     
     if (!$lastCleanup || (time() - $lastCleanup) > $this->ttlSettings['cleanup_interval']) {
         $this->aggressiveCleanup();
         $this->redis->setex($lastCleanupKey, $this->ttlSettings['cleanup_interval'], time());
     }
 }
 
 // АГРЕССИВНАЯ очистка для быстрого освобождения памяти
 private function aggressiveCleanup() {
     try {
         $cleaned = 0;
         $startTime = microtime(true);
         $maxExecutionTime = 0.05; // Максимум 50мс на очистку
         
         // Очистка с приоритетом на самые частые ключи
         $patterns = [
             $this->trackingPrefix . 'ip:*',
             $this->userHashPrefix . 'tracking:*',
             $this->sessionPrefix . 'data:*',
             $this->rdnsPrefix . 'cache:*'
         ];
         
         foreach ($patterns as $pattern) {
             if ((microtime(true) - $startTime) > $maxExecutionTime) break;
             
             $keys = array_slice($this->redis->keys($pattern), 0, 25); // Максимум 25 ключей за раз
             foreach ($keys as $key) {
                 if ((microtime(true) - $startTime) > $maxExecutionTime) break;
                 
                 $ttl = $this->redis->ttl($key);
                 // Удаляем ключи без TTL или старше 50% от срока жизни
                 if ($ttl === -1 || ($ttl > 0 && $ttl < 450)) { // 450 сек = 50% от минимального TTL
                     $this->redis->del($key);
                     $cleaned++;
                 }
             }
             
             // Ограничиваем количество обработанных ключей
             if ($cleaned > 50) break;
         }
         
         if ($cleaned > 0) {
             error_log("Aggressive cleanup: $cleaned keys removed in " . 
                      round((microtime(true) - $startTime) * 1000) . "ms");
         }
         
     } catch (Exception $e) {
         error_log("Aggressive cleanup error: " . $e->getMessage());
     }
 }
 
 /**
  * ИСПРАВЛЕННАЯ функция нормализации IPv6
  */
 private function normalizeIPv6($ip) {
     // Проверяем, что это действительно IPv6
     if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
         return $ip;
     }
     
     // Используем inet_pton для правильной нормализации
     $binary = inet_pton($ip);
     if ($binary === false) {
         return $ip;
     }
     
     // Преобразуем обратно в стандартную форму
     $normalized = inet_ntop($binary);
     return $normalized ?: $ip;
 }
 
 /**
  * ИСПРАВЛЕННАЯ функция получения части IP для отпечатка
  */
 private function getIPFingerprint($ip) {
     $ip = $this->normalizeIPv6($ip);
     
     if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
         // Для IPv6 берем последние 4 сегмента (64 бита)
         $parts = explode(':', $ip);
         if (count($parts) >= 4) {
             return implode(':', array_slice($parts, -4));
         }
         return substr($ip, -16); // Последние 16 символов как fallback
     } else {
         // Для IPv4 берем последние 2 октета
         $parts = explode('.', $ip);
         if (count($parts) >= 2) {
             return end($parts) . '.' . prev($parts); // Последние 2 октета
         }
         return $ip;
     }
 }
 
 /**
  * ИСПРАВЛЕННАЯ функция генерации стабильного хеша пользователя
  * Один браузер = один хеш (до смены браузера/устройства)
  */
 private function generateUserHash($ip = null) {
     $ip = $ip ?: $this->getRealIP();
     $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
     $acceptLanguage = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '';
     $acceptEncoding = $_SERVER['HTTP_ACCEPT_ENCODING'] ?? '';
     $accept = $_SERVER['HTTP_ACCEPT'] ?? '';
     
     // Получаем детальную информацию о браузере
     $browserInfo = $this->getBrowserFingerprint($userAgent);
     
     // Создаем стабильный отпечаток браузера (БЕЗ случайных компонентов)
     $stableFingerprint = $userAgent . '|' . 
                         $acceptLanguage . '|' . 
                         $acceptEncoding . '|' . 
                         $accept . '|' .
                         $browserInfo['name'] . '|' .
                         $browserInfo['version'] . '|' .
                         $browserInfo['platform'] . '|' .
                         $this->secretKey;
     
     // Определяем тип устройства и добавляем IP-компонент
     if ($this->isMobileDevice($userAgent)) {
         // Для мобильных добавляем часть IP (для роуминга/смены сетей)
         $ipPart = $this->getIPFingerprint($ip);
         $stableFingerprint .= '|mobile|' . $ipPart;
         
         error_log("Mobile device hash: Browser={$browserInfo['name']} {$browserInfo['version']}, Platform={$browserInfo['platform']}, IP_part=$ipPart");
     } else {
         // Для десктопа используем полный IP (более стабильное подключение)
         $stableFingerprint .= '|desktop|' . $ip;
         
         error_log("Desktop device hash: Browser={$browserInfo['name']} {$browserInfo['version']}, Platform={$browserInfo['platform']}, Full_IP=$ip");
     }
     
     return hash('sha256', $stableFingerprint);
 }
 
 /**
  * НОВАЯ функция для генерации сессионного хеша (когда нужна уникальность)
  * Используется только в особых случаях, когда нужно различать вкладки/сессии
  */
 private function generateSessionUserHash($ip = null) {
     $stableHash = $this->generateUserHash($ip);
     
     // Добавляем сессионный компонент ТОЛЬКО если нужна уникальность сессии
     $sessionId = session_id();
     if (!$sessionId) {
         session_start();
         $sessionId = session_id();
     }
     
     // Комбинируем стабильный хеш с сессией
     $sessionFingerprint = $stableHash . '|session|' . $sessionId;
     
     return hash('sha256', $sessionFingerprint);
 }
 
 /**
  * НОВАЯ функция для получения детального отпечатка браузера
  */
 private function getBrowserFingerprint($userAgent) {
     $browser = [
         'name' => 'unknown',
         'version' => 'unknown',
         'platform' => 'unknown'
     ];
     
     // Определяем браузер
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
     
     // Определяем платформу
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
 
 /**
  * ИСПРАВЛЕННАЯ функция проверки блокировки по хешу пользователя
  */
 private function isUserHashBlocked() {
     $userHash = $this->generateUserHash(); // Стабильный хеш
     $blockKey = $this->userHashPrefix . 'blocked:' . $userHash;
     return $this->redis->exists($blockKey);
 }
 
 /**
  * ИСПРАВЛЕННАЯ функция блокировки пользователя по хешу
  */
 private function blockUserHash($reason = 'Bot behavior detected') {
     $userHash = $this->generateUserHash(); // Стабильный хеш
     $ip = $this->getRealIP();
     
     $blockData = [
         'user_hash' => $userHash,
         'ip' => $ip,
         'blocked_at' => time(),
         'blocked_reason' => $reason,
         'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
         'session_id' => session_id(),
         'uri' => $_SERVER['REQUEST_URI'] ?? '',
         'headers' => $this->collectHeaders(),
         'browser_info' => $this->getBrowserFingerprint($_SERVER['HTTP_USER_AGENT'] ?? ''),
         'device_type' => $this->isMobileDevice($_SERVER['HTTP_USER_AGENT'] ?? '') ? 'mobile' : 'desktop'
     ];
     
     $blockKey = $this->userHashPrefix . 'blocked:' . $userHash;
     $this->redis->setex($blockKey, $this->ttlSettings['user_hash_blocked'], $blockData);
     
     // Ведем статистику блокировок этого хеша
     $statsKey = $this->userHashPrefix . 'stats:' . $userHash;
     $this->redis->hincrby($statsKey, 'block_count', 1);
     $this->redis->hset($statsKey, 'last_blocked', time());
     $this->redis->hset($statsKey, 'last_blocked_reason', $reason);
     $this->redis->expire($statsKey, $this->ttlSettings['user_hash_stats']);
     
     error_log("User hash blocked: Hash=" . substr($userHash, 0, 12) . "..., IP=$ip, Reason=$reason, " .
               "Device=" . $blockData['device_type'] . ", Browser=" . $blockData['browser_info']['name']);
 }
 
 /**
  * ИСПРАВЛЕННАЯ функция отслеживания активности пользователя по хешу
  */
 private function trackUserHashActivity() {
     $userHash = $this->generateUserHash(); // Стабильный хеш
     $trackingKey = $this->userHashPrefix . 'tracking:' . $userHash;
     
     $existing = $this->redis->get($trackingKey);
     
     if ($existing) {
         // Обновляем существующую запись
         $existing['requests']++;
         $existing['last_activity'] = time();
         
         // Добавляем текущую страницу
         $currentPage = parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH);
         if (!in_array($currentPage, $existing['pages'])) {
             $existing['pages'][] = $currentPage;
         }
         
         // Добавляем время запроса
         $existing['request_times'][] = time();
         
         // Отслеживаем IP-адреса (для мониторинга смены сети)
         $currentIP = $this->getRealIP();
         if (!in_array($currentIP, $existing['ips'])) {
             $existing['ips'][] = $currentIP;
         }
         
         // СОКРАТИЛ размеры данных для экономии памяти
         if (count($existing['request_times']) > 20) { // было 50
             $existing['request_times'] = array_slice($existing['request_times'], -20);
         }
         if (count($existing['pages']) > 30) { // было 100
             $existing['pages'] = array_unique(array_slice($existing['pages'], -30));
         }
         if (count($existing['ips']) > 10) { // было 20
             $existing['ips'] = array_unique(array_slice($existing['ips'], -10));
         }
         
         $this->redis->setex($trackingKey, $this->ttlSettings['user_hash_tracking'], $existing);
     } else {
         // Создаем новую запись
         $data = [
             'user_hash' => $userHash,
             'first_seen' => time(),
             'last_activity' => time(),
             'requests' => 1,
             'pages' => [parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH)],
             'ips' => [$this->getRealIP()],
             'user_agents' => [$_SERVER['HTTP_USER_AGENT'] ?? ''],
             'session_ids' => [session_id() ?: 'no_session'],
             'request_times' => [time()],
             'browser_info' => $this->getBrowserFingerprint($_SERVER['HTTP_USER_AGENT'] ?? '')
         ];
         
         $this->redis->setex($trackingKey, $this->ttlSettings['user_hash_tracking'], $data);
     }
     
     return $existing ?: $data;
 }
 
 /**
  * ИСПРАВЛЕННАЯ функция анализа поведения пользователя по хешу
  * НЕ блокирует IP для браузеров, повышены пороги блокировки
  */
 private function analyzeUserHashBehavior() {
     $trackingData = $this->trackUserHashActivity();
     
     if (!$trackingData || $trackingData['requests'] < 8) { // Увеличили с 5 до 8
         return false; // Недостаточно данных для анализа
     }
     
     $score = 0;
     $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
     $isMobile = $this->isMobileDevice($userAgent);
     $browserInfo = $this->getBrowserFingerprint($userAgent);
     
     // ПОВЫШЕННЫЕ пороги блокировки
     $blockThreshold = $isMobile ? 20 : 18; // Было 15/12
     
     // 1. Подозрительный User-Agent - основной индикатор бота
     if ($this->isSuspiciousUserAgent($userAgent)) {
         $score += $isMobile ? 15 : 20; // Увеличили с 10/13
         error_log("Suspicious UA detected: +20 points");
     }
     
     // 2. Анализ частоты запросов (увеличили пороги)
     $requests = $trackingData['requests'];
     $timeSpent = time() - $trackingData['first_seen'];
     
     if ($timeSpent > 0) {
         $requestsPerMinute = ($requests * 60) / $timeSpent;
         
         if ($isMobile) {
             // Более мягкие пороги для мобильных
             if ($requestsPerMinute > 300) $score += 12; // Было 200/12
             elseif ($requestsPerMinute > 200) $score += 8; // Было 150/10
             elseif ($requestsPerMinute > 120) $score += 4; // Было 100/6
         } else {
             // Пороги для десктопа
             if ($requestsPerMinute > 250) $score += 12; // Было 150/12
             elseif ($requestsPerMinute > 150) $score += 8; // Было 100/10
             elseif ($requestsPerMinute > 80) $score += 4; // Было 60/6
         }
         
         if ($score > 0) {
             error_log("High request rate: {$requestsPerMinute}/min, +{$score} points");
         }
     }
     
     // 3. Анализ разнообразия страниц (увеличили лимиты)
     $uniquePages = array_unique($trackingData['pages'] ?? []);
     $totalPages = count($trackingData['pages'] ?? []);
     
     if ($totalPages > 60) { // Было 40
         $pageVariety = count($uniquePages) / $totalPages;
         
         // Если посещает одну и ту же страницу слишком часто
         if ($pageVariety < 0.05) { // Было 0.08
             $score += $isMobile ? 3 : 4; // Было 4/6
             error_log("Low page variety: {$pageVariety}, +{$score} points");
         }
     }
     
     // 4. Анализ регулярности запросов (увеличили требования)
     if (isset($trackingData['request_times']) && count($trackingData['request_times']) >= 15) { // Было 10
         $intervals = [];
         $times = array_slice($trackingData['request_times'], -20); // Было -15
         
         for ($i = 1; $i < count($times); $i++) {
             $intervals[] = $times[$i] - $times[$i-1];
         }
         
         if (count($intervals) >= 15) { // Было 12
             $avgInterval = array_sum($intervals) / count($intervals);
             $variance = 0;
             foreach ($intervals as $interval) {
                 $variance += pow($interval - $avgInterval, 2);
             }
             $variance /= count($intervals);
             $stdDev = sqrt($variance);
             
             // Слишком регулярные запросы = вероятно скрипт
             if ($stdDev < 0.5 && $avgInterval < 2 && $avgInterval > 0.2) { // Более строгие условия
                 $score += $isMobile ? 5 : 7; // Было 6/9
                 error_log("Too regular requests: stdDev={$stdDev}, avgInterval={$avgInterval}, +{$score} points");
             }
         }
     }
     
     // 5. Быстрые последовательные запросы (более строгие условия)
     if (isset($trackingData['request_times']) && count($trackingData['request_times']) >= 10) { // Было 7
         $lastTen = array_slice($trackingData['request_times'], -10); // Было -7
         $timeDiff = end($lastTen) - reset($lastTen);
         
         if ($timeDiff <= 3) { // 10 запросов за 3 секунды (было 7 за 2)
             $score += $isMobile ? 6 : 8; // Было 6/9
             error_log("Rapid fire requests: 10 requests in {$timeDiff}s, +{$score} points");
         }
         
         // Экстремально быстрые запросы
         if ($timeDiff <= 1) { // 10 запросов за 1 секунду
             $score += 10;
             error_log("Extremely rapid requests: 10 requests in {$timeDiff}s, +10 points");
         }
     }
     
     // 6. Множественные IP-адреса (возможная ротация прокси)
     $uniqueIPs = array_unique($trackingData['ips'] ?? []);
     if (count($uniqueIPs) > 15) { // Было 10
         $score += 8; // Было 7
         error_log("Multiple IPs detected: " . count($uniqueIPs) . " IPs, +8 points");
     }
     
     // 7. Проверка на повторные нарушения
     $userHash = $this->generateUserHash();
     $statsKey = $this->userHashPrefix . 'stats:' . $userHash;
     $blockCount = $this->redis->hget($statsKey, 'block_count') ?: 0;
     
     if ($blockCount > 2) { // Было 1
         $score += $blockCount * 3; // Было 2
         error_log("Repeat offender: {$blockCount} previous blocks, +{$score} points");
     }
     
     // Финальное логирование
     error_log("User hash analysis complete: Hash=" . substr($userHash, 0, 12) . "..., " .
               "Score={$score}/{$blockThreshold}, Requests={$requests}, " .
               "Mobile=" . ($isMobile ? 'Yes' : 'No') . ", " .
               "Browser={$browserInfo['name']} {$browserInfo['version']}, " .
               "Platform={$browserInfo['platform']}, " .
               "UniquePages=" . count($uniquePages) . "/" . $totalPages . ", " .
               "UniqueIPs=" . count($uniqueIPs));
     
     return $score >= $blockThreshold;
 }
 
 /**
  * ИСПРАВЛЕННАЯ основная функция защиты - НЕ блокирует IP для браузеров
  */
 public function protect() {
     // Исключаем статические файлы
     if ($this->isStaticFile()) {
         return;
     }
     
     // Запускаем сессию
     $this->startSession();
     
     $ip = $this->getRealIP();
     $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
     
     // Проверяем легитимные боты
     if ($this->isLegitimateBot($userAgent)) {
         $this->logBotVisit($ip, $userAgent, 'legitimate');
         return;
     }
     
     // Проверяем поисковики
     if ($this->isVerifiedSearchEngine($ip, $userAgent)) {
         $this->logSearchEngineVisit($ip, $userAgent);
         return;
     }
     
     // 1. ПРОВЕРКА: блокировка по хешу пользователя (приоритетная)
     if ($this->isUserHashBlocked()) {
         error_log("Request blocked by user hash: IP=$ip");
         $this->sendBlockResponse();
     }
     
     // 2. ПРОВЕРКА: блокировка сессии и cookie
     if ($this->isSessionBlocked() || $this->isCookieBlocked()) {
         $this->sendBlockResponse();
     }
     
     // 3. ПРОВЕРКА: блокировка IP ТОЛЬКО для подозрительных User-Agent
     if ($this->isBlocked($ip) && $this->isSuspiciousUserAgent($userAgent)) {
         $this->sendBlockResponse();
     }
     
     // 4. ПРОВЕРКА: валидный cookie
     if ($this->hasValidCookie()) {
         // Даже с валидным cookie отслеживаем активность по хешу
         $this->trackUserHashActivity();
         $this->updateSessionActivity();
         
         // Анализируем поведение только в критических случаях
         if ($this->shouldAnalyzeIP($ip)) {
             if ($this->analyzeRequest($ip)) {
                 // ИСПРАВЛЕНИЕ: дифференцированная блокировка
                 if ($this->isSuspiciousUserAgent($userAgent)) {
                     // Подозрительный User-Agent = блокируем IP + остальное
                     $this->blockIP($ip, 'Suspicious user agent with valid cookie');
                     $this->blockSession();
                     $this->blockCookieHash();
                     $this->blockUserHash('Bot with valid cookie');
                 } else {
                     // Браузер = НЕ блокируем IP, только остальное
                     $this->blockUserHash('Browser behavior detected with valid cookie');
                     $this->blockSession();
                     $this->blockCookieHash();
                     // БЕЗ $this->blockIP() для браузеров!
                 }
                 $this->sendBlockResponse();
             }
         }
         return;
     }
     
     // 5. АНАЛИЗ ДЛЯ НОВЫХ ПОЛЬЗОВАТЕЛЕЙ: проверяем только если есть веские основания
     if ($this->shouldAnalyzeIP($ip)) {
         if ($this->analyzeRequest($ip)) {
             // ИСПРАВЛЕНИЕ: дифференцированная блокировка
             if ($this->isSuspiciousUserAgent($userAgent)) {
                 // Подозрительный User-Agent = блокируем IP + остальное
                 $this->blockIP($ip, 'Suspicious user agent detected');
                 if (isset($_COOKIE[$this->cookieName])) {
                     $this->blockSession();
                     $this->blockCookieHash();
                 }
                 $this->blockUserHash('Bot detected');
             } else {
                 // Обычный браузер = НЕ блокируем IP, только остальное
                 if (isset($_COOKIE[$this->cookieName])) {
                     $this->blockSession();
                     $this->blockCookieHash();
                 } else {
                     // Новый пользователь браузера - только блокировка по хешу
                     $this->blockUserHash('Browser behavior detected without cookie');
                 }
                 // БЕЗ $this->blockIP() для браузеров!
             }
             $this->sendBlockResponse();
         }
     }
     
     // 6. АНАЛИЗ ПОВЕДЕНИЯ ПО ХЕШУ: основная защита для браузеров
     if ($this->analyzeUserHashBehavior()) {
         // ИСПРАВЛЕНИЕ: НЕ блокируем IP для браузеров
         if ($this->isSuspiciousUserAgent($userAgent)) {
             // Реальный бот - блокируем всё включая IP
             $this->blockIP($ip, 'Bot behavior confirmed by user hash analysis');
             $this->blockUserHash('Bot confirmed');
             if (isset($_COOKIE[$this->cookieName])) {
                 $this->blockSession();
                 $this->blockCookieHash();
             }
         } else {
             // Браузер ведет себя как бот - НЕ блокируем IP
             $this->blockUserHash('Browser acting like bot');
             if (isset($_COOKIE[$this->cookieName])) {
                 $this->blockSession();
                 $this->blockCookieHash();
             }
             // БЕЗ $this->blockIP() для браузеров!
         }
         
         $this->sendBlockResponse();
     }
     
     // 7. ИНИЦИАЛИЗАЦИЯ: если дошли сюда - устанавливаем cookie и инициализируем
     if (!isset($_COOKIE[$this->cookieName])) {
         $this->setVisitorCookie();
         $this->initTracking($ip);
         $this->initSession();
     }
 }
 
 private function isSessionBlocked() {
     $sessionId = session_id();
     if (!$sessionId) return false;
     
     return $this->redis->exists($this->sessionPrefix . 'blocked:' . $sessionId);
 }
 
 private function blockSession() {
     $sessionId = session_id();
     if (!$sessionId) return;
     
     $blockData = [
         'session_id' => $sessionId,
         'blocked_at' => time(),
         'blocked_reason' => 'Bot behavior detected',
         'ip' => $this->getRealIP(),
         'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
     ];
     
     // Блокируем сессию на 3 часа вместо 6
     $this->redis->setex($this->sessionPrefix . 'blocked:' . $sessionId, 
                        $this->ttlSettings['session_blocked'], $blockData);
     
     // Также устанавливаем флаг в PHP сессии
     $_SESSION['blocked'] = true;
     $_SESSION['blocked_at'] = time();
     $_SESSION['blocked_reason'] = 'Bot behavior detected';
     
     error_log("Session blocked: SessionID=$sessionId, IP=" . $this->getRealIP() . 
               ", UA=" . ($_SERVER['HTTP_USER_AGENT'] ?? 'unknown'));
 }
 
 private function shouldAnalyzeIP($ip) {
     $trackingKey = $this->trackingPrefix . 'ip:' . hash('md5', $ip);
     $data = $this->redis->get($trackingKey);
     
     if ($data) {
         $requests = $data['requests'] ?? 0;
         $timeSpent = time() - ($data['first_seen'] ?? time());
         $suspicious_ua = $this->isSuspiciousUserAgent($_SERVER['HTTP_USER_AGENT'] ?? '');
         
         // 1. Подозрительный User-Agent - анализируем сразу
         if ($suspicious_ua) {
             return true;
         }
         
         // 2. Много запросов (понизили порог с 10 до 5)
         if ($requests > 5) {
             return true;
         }
         
         // 3. Быстрые запросы - но только если их много
         if ($timeSpent > 0 && $requests >= 5) { // Минимум 5 запросов для анализа скорости
             $requestsPerMinute = ($requests * 60) / $timeSpent;
             // Увеличили порог с 20 до 40 запросов в минуту
             if ($requestsPerMinute > 40) {
                 return true;
             }
         }
         
         // 4. Много запросов за короткое время - но увеличили количество
         if (isset($data['request_times']) && count($data['request_times']) >= 7) { // Было 5
             $recentTimes = array_slice($data['request_times'], -7); // Было -5
             $timeSpan = end($recentTimes) - reset($recentTimes);
             // Увеличили: 7 запросов за 20 секунд (было 5 за 15)
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
         // Мониторинг
         'uptimerobot', 'pingdom', 'statuscake', 'site24x7',
         // CDN
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
 
 private function logBotVisit($ip, $userAgent, $type) {
     $logEntry = [
         'timestamp' => date('Y-m-d H:i:s'),
         'ip' => $ip,
         'user_agent' => $userAgent,
         'type' => $type,
         'uri' => $_SERVER['REQUEST_URI'] ?? ''
     ];
     
     // Логируем в Redis список с TTL 1 день вместо 2
     $logKey = 'logs:legitimate_bots:' . date('Y-m-d');
     $this->redis->lpush($logKey, $logEntry);
     $this->redis->expire($logKey, $this->ttlSettings['logs']);
     
     // Ограничиваем размер лога
     $this->redis->ltrim($logKey, 0, 999); // Максимум 1000 записей
 }
 
 private function startSession() {
     if (session_status() === PHP_SESSION_NONE) {
         // Настройки безопасности сессии
         ini_set('session.cookie_httponly', 1);
         ini_set('session.cookie_secure', isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' ? 1 : 0);
         ini_set('session.use_strict_mode', 1);
         ini_set('session.cookie_samesite', 'Lax');
         ini_set('session.gc_maxlifetime', 3600); // 1 час вместо 2
         ini_set('session.cookie_lifetime', 0);
         
         session_start();
         
         // Защита от session hijacking
         if (!isset($_SESSION['bot_protection_fingerprint'])) {
             $_SESSION['bot_protection_fingerprint'] = $this->generateFingerprint();
         } else {
             if ($_SESSION['bot_protection_fingerprint'] !== $this->generateFingerprint()) {
                 session_regenerate_id(true);
                 $_SESSION['bot_protection_fingerprint'] = $this->generateFingerprint();
             }
         }
     }
 }
 
 private function generateFingerprint() {
     return hash('sha256', 
         ($_SERVER['HTTP_USER_AGENT'] ?? '') .
         ($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '') .
         ($_SERVER['REMOTE_ADDR'] ?? '') .
         $this->secretKey
     );
 }
 
 private function initSession() {
     $sessionData = [
         'first_visit' => time(),
         'visit_count' => 1,
         'last_activity' => time(),
         'pages_visited' => 1,
         'verified' => true,
         'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
         'ip' => $this->getRealIP()
     ];
     
     $_SESSION['bot_protection'] = $sessionData;
     
     // Дублируем в Redis с сокращенным TTL
     $this->redis->setex($this->sessionPrefix . 'data:' . session_id(), 
                        $this->ttlSettings['session_data'], $sessionData);
 }
 
 private function updateSessionActivity() {
     if (isset($_SESSION['bot_protection'])) {
         $_SESSION['bot_protection']['last_activity'] = time();
         $_SESSION['bot_protection']['pages_visited']++;
         $_SESSION['bot_protection']['visit_count']++;
         
         // Обновляем в Redis с сокращенным TTL
         $this->redis->setex($this->sessionPrefix . 'data:' . session_id(), 
                            $this->ttlSettings['session_data'], $_SESSION['bot_protection']);
     } else {
         $this->initSession();
     }
 }
 
 private function isVerifiedSearchEngine($ip, $userAgent) {
     // Сначала проверяем User-Agent
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
     
     // Проверяем rDNS
     return $this->verifySearchEngineByRDNS($ip, $this->allowedSearchEngines[$detectedEngine]['rdns_patterns']);
 }
 
 private function verifySearchEngineByRDNS($ip, $allowedPatterns) {
     $cacheKey = $this->rdnsPrefix . 'cache:' . hash('md5', $ip);
     $cached = $this->redis->get($cacheKey);
     
     if ($cached !== false) {
         return $cached['verified'];
     }
     
     $verified = false;
     $hostname = '';
     
     try {
         $hostname = gethostbyaddr($ip);
         
         if ($hostname && $hostname !== $ip) {
             foreach ($allowedPatterns as $pattern) {
                 if (substr($hostname, -strlen($pattern)) === $pattern) {
                     $forwardIPs = gethostbynamel($hostname);
                     if ($forwardIPs && in_array($ip, $forwardIPs)) {
                         $verified = true;
                         break;
                     }
                 }
             }
         }
     } catch (Exception $e) {
         error_log("rDNS verification error for IP $ip: " . $e->getMessage());
     }
     
     // Кэшируем результат на 15 минут вместо 30
     $cacheData = [
         'ip' => $ip,
         'hostname' => $hostname,
         'verified' => $verified,
         'timestamp' => time()
     ];
     
     $this->redis->setex($cacheKey, $this->ttlSettings['rdns_cache'], $cacheData);
     
     return $verified;
 }
 
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
     
     // Ограничиваем размер лога
     $this->redis->ltrim($logKey, 0, 999);
 }
 
 /**
  * ИСПРАВЛЕННАЯ функция получения реального IP с поддержкой IPv4 и IPv6
  */
 private function getRealIP() {
     $ipHeaders = [
         'HTTP_CF_CONNECTING_IP',     // Cloudflare
         'HTTP_X_REAL_IP',            // Nginx
         'HTTP_X_FORWARDED_FOR',      // Load balancers
         'HTTP_X_FORWARDED',          // Proxy
         'HTTP_X_CLUSTER_CLIENT_IP',  // Cluster
         'HTTP_FORWARDED_FOR',        // Proxy
         'HTTP_FORWARDED',            // RFC 7239
         'REMOTE_ADDR'                // Direct connection
     ];
     
     foreach ($ipHeaders as $header) {
         if (!empty($_SERVER[$header])) {
             $ips = explode(',', $_SERVER[$header]);
             $ip = trim($ips[0]);
             
             // Нормализуем IPv6 перед проверкой
             if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                 $ip = $this->normalizeIPv6($ip);
             }
             
             // Проверяем валидность IP (IPv4 или IPv6)
             if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                 // Для IPv4 проверяем, что это не приватный/зарезервированный адрес
                 if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                     return $ip;
                 }
             } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                 // Для IPv6 дополнительно проверяем, что это не локальный адрес
                 if (!$this->isPrivateIPv6($ip)) {
                     return $ip;
                 }
             }
         }
     }
     
     // Возвращаем REMOTE_ADDR как последний вариант, даже если это приватный IP
     $remoteAddr = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
     if ($remoteAddr !== 'unknown' && filter_var($remoteAddr, FILTER_VALIDATE_IP)) {
         if (filter_var($remoteAddr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
             return $this->normalizeIPv6($remoteAddr);
         }
         return $remoteAddr;
     }
     
     return 'unknown';
 }
 
 /**
  * НОВАЯ функция проверки приватных IPv6 адресов
  */
 private function isPrivateIPv6($ip) {
     $privateRanges = [
         '::1',              // Loopback
         'fe80::/10',        // Link-local
         'fc00::/7',         // Unique local
         'ff00::/8',         // Multicast
     ];
     
     foreach ($privateRanges as $range) {
         if ($this->ipInRange($ip, $range)) {
             return true;
         }
     }
     
     return false;
 }
 
 /**
  * НОВАЯ функция проверки принадлежности IP к диапазону
  */
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
         // Обновляем существующую запись
         $existing['requests']++;
         $existing['pages'][] = parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH);
         $existing['user_agents'][] = $_SERVER['HTTP_USER_AGENT'] ?? '';
         $existing['user_agents'] = array_unique($existing['user_agents']);
         $existing['request_times'][] = time();
         
         // СОКРАТИЛ количество сохраняемых данных
         if (count($existing['request_times']) > 15) { // Было 20
             $existing['request_times'] = array_slice($existing['request_times'], -15);
         }
         if (count($existing['pages']) > 20) { // Было 30
             $existing['pages'] = array_slice($existing['pages'], -20);
         }
         if (count($existing['user_agents']) > 3) { // Было 5
             $existing['user_agents'] = array_slice($existing['user_agents'], -3);
         }
         
         $this->redis->setex($trackingKey, $this->ttlSettings['tracking_ip'], $existing);
     } else {
         // Создаем новую запись
         $data = [
             'first_seen' => time(),
             'requests' => 1,
             'pages' => [parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH)],
             'user_agents' => [$_SERVER['HTTP_USER_AGENT'] ?? ''],
             'headers' => $this->collectHeaders(),
             'session_id' => session_id(),
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
         'session_id' => session_id(),
         'ip' => $this->getRealIP()
     ];
     
     $this->redis->setex($blockKey, $this->ttlSettings['cookie_blocked'], $blockData);
     
     error_log("Cookie blocked: Hash=" . substr($data['hash'], 0, 8) . "..., IP=" . $this->getRealIP());
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
         // Основные мобильные платформы
         'Mobile', 'Android', 'iPhone', 'iPad', 'iPod', 
         // Мобильные браузеры
         'Mobile Safari', 'Chrome Mobile', 'Firefox Mobile', 'Opera Mini', 'Opera Mobi',
         // Другие мобильные устройства
         'BlackBerry', 'Windows Phone', 'IEMobile', 'Kindle', 'Silk',
         // Планшеты
         'Tablet', 'PlayBook',
         // Дополнительные паттерны
         'webOS', 'hpwOS', 'Bada', 'Tizen', 'NetFront', 'Fennec'
     ];
     
     $userAgent = strtolower($userAgent);
     
     foreach ($mobilePatterns as $pattern) {
         if (stripos($userAgent, strtolower($pattern)) !== false) {
             return true;
         }
     }
     
     // Дополнительная проверка по регулярным выражениям
     $mobileRegex = '/mobile|android|iphone|ipad|ipod|blackberry|iemobile|opera m(ob|in)i/i';
     if (preg_match($mobileRegex, $userAgent)) {
         return true;
     }
     
     return false;
 }
 
 /**
  * ИСПРАВЛЕННАЯ функция анализа запросов - повышены пороги блокировки
  */
 private function analyzeRequest($ip) {
     $trackingKey = $this->trackingPrefix . 'ip:' . hash('md5', $ip);
     $data = $this->redis->get($trackingKey);
     
     if (!$data) {
         return false; // Если нет данных - не блокируем
     }
     
     $score = 0;
     $currentUA = $_SERVER['HTTP_USER_AGENT'] ?? '';
     $isMobile = $this->isMobileDevice($currentUA);
     
     // ПОВЫШЕННЫЕ пороги блокировки
     $blockThreshold = $isMobile ? 20 : 18; // Было 12/10
     
     // 1. Проверка подозрительного User-Agent
     if ($this->isSuspiciousUserAgent($currentUA)) {
         $score += $isMobile ? 15 : 20; // Было 12/18
     }
     
     // 2. Анализ частоты запросов (значительно увеличили пороги)
     $requests = $data['requests'] ?? 0;
     $timeSpent = time() - ($data['first_seen'] ?? time());
     
     if ($timeSpent > 0) {
         $requestsPerMinute = ($requests * 60) / $timeSpent;
         
         if ($isMobile) {
             if ($requestsPerMinute > 180) $score += 12; // Было 120/12
             elseif ($requestsPerMinute > 120) $score += 8; // Было 90/10
             elseif ($requestsPerMinute > 80) $score += 4; // Было 60/6
         } else {
             if ($requestsPerMinute > 150) $score += 12; // Было 100/12
             elseif ($requestsPerMinute > 100) $score += 8; // Было 70/10
             elseif ($requestsPerMinute > 60) $score += 4; // Было 45/6
         }
     }
     
     // 3. Много запросов без cookies (увеличили лимиты)
     $cookieLimit = $isMobile ? 35 : 30; // Было 25/20
     if ($requests > $cookieLimit && !isset($_COOKIE[$this->cookieName])) {
         $score += $isMobile ? 3 : 4; // Было 4/6
     }
     
     // 4. Анализ HTTP заголовков (снизили штрафы)
     $currentHeaders = $this->collectHeaders();
     
     if (!isset($currentHeaders['HTTP_ACCEPT']) || $currentHeaders['HTTP_ACCEPT'] === '*/*') {
         $score += $isMobile ? 1 : 2; // Было 2/3
     }
     if (!isset($currentHeaders['HTTP_ACCEPT_LANGUAGE'])) {
         $score += $isMobile ? 1 : 2; // Было 2/3
     }
     if (!isset($currentHeaders['HTTP_ACCEPT_ENCODING'])) {
         $score += $isMobile ? 1 : 2; // Было 2/3
     }
     
     // 5. Разнообразие страниц (увеличили лимиты)
     $uniquePages = array_unique($data['pages'] ?? []);
     $totalPages = count($data['pages'] ?? []);
     
     $pageLimit = $isMobile ? 50 : 40; // Было 30/25
     if ($totalPages > $pageLimit && count($uniquePages) <= 2) {
         $score += $isMobile ? 2 : 3; // Было 3/5
     }
     
     // 6. Множественные User-Agent (снизили штраф)
     $uniqueUA = array_unique($data['user_agents'] ?? []);
     if (count($uniqueUA) > 8) { // Было 5
         $score += 4; // Было 6
     }
     
     // 7. Анализ регулярности запросов (увеличили требования)
     if (isset($data['request_times']) && count($data['request_times']) >= 15) { // Было 10
         $intervals = [];
         $lastFifteen = array_slice($data['request_times'], -15); // Было -10
         
         for ($i = 1; $i < count($lastFifteen); $i++) {
             $intervals[] = $lastFifteen[$i] - $lastFifteen[$i-1];
         }
         
         if (count($intervals) >= 12) { // Было 8
             $avgInterval = array_sum($intervals) / count($intervals);
             $variance = 0;
             foreach ($intervals as $interval) {
                 $variance += pow($interval - $avgInterval, 2);
             }
             $variance /= count($intervals);
             
             $varianceThreshold = $isMobile ? 1.0 : 1.5; // Было 1.5/2
             $intervalThreshold = $isMobile ? 3 : 5; // Было 5/8
             
             if ($variance < $varianceThreshold && $avgInterval < $intervalThreshold) {
                 $score += $isMobile ? 3 : 5; // Было 4/7
             }
         }
     }
     
     // 8. Проверка очень быстрых запросов (более строгие условия)
     if (isset($data['request_times']) && count($data['request_times']) >= 10) { // Было 7
         $lastTen = array_slice($data['request_times'], -10); // Было -7
         $timeDiff = end($lastTen) - reset($lastTen);
         
         // Если 10 запросов за 5 секунд или меньше (было 7 за 4)
         if ($timeDiff <= 5) {
             $score += $isMobile ? 3 : 5; // Было 4/7
         }
         // Если 10 запросов за 2 секунды (было 7 за 2)
         if ($timeDiff <= 2) {
             $score += 6; // Было 8
         }
     }
     
     // Логируем для отладки
     error_log("Bot analysis: IP=$ip, UA=" . substr($currentUA, 0, 50) . ", Score=$score, Requests=$requests, Mobile=" . 
               ($isMobile ? 'Yes' : 'No') . ", Threshold=$blockThreshold, SuspiciousUA=" . 
               ($this->isSuspiciousUserAgent($currentUA) ? 'Yes' : 'No'));
     
     // ВАЖНО: Функция НЕ блокирует ничего, только возвращает true/false
     return $score >= $blockThreshold;
 }
 
 private function isBlocked($ip) {
     $blockKey = $this->blockPrefix . 'ip:' . hash('md5', $ip);
     return $this->redis->exists($blockKey);
 }
 
 /**
  * ИСПРАВЛЕННАЯ функция блокировки IP с дополнительной информацией
  */
 private function blockIP($ip, $reason = 'Bot behavior detected') {
     $blockKey = $this->blockPrefix . 'ip:' . hash('md5', $ip);
     
     // Проверяем, был ли IP заблокирован ранее
     $isRepeatOffender = $this->redis->exists($blockKey);
     
     $blockData = [
         'ip' => $ip,
         'blocked_at' => time(),
         'blocked_reason' => $reason,
         'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
         'uri' => $_SERVER['REQUEST_URI'] ?? '',
         'session_id' => session_id(),
         'repeat_offender' => $isRepeatOffender,
         'is_suspicious_ua' => $this->isSuspiciousUserAgent($_SERVER['HTTP_USER_AGENT'] ?? ''),
         'browser_info' => $this->getBrowserFingerprint($_SERVER['HTTP_USER_AGENT'] ?? '')
     ];
     
     // Сокращенная блокировка: 15 минут базовая, 1 час для повторных нарушителей
     $blockDuration = $isRepeatOffender ? $this->ttlSettings['ip_blocked_repeat'] : $this->ttlSettings['ip_blocked'];
     $this->redis->setex($blockKey, $blockDuration, $blockData);
     
     error_log("Bot blocked: IP=$ip, UA=" . ($_SERVER['HTTP_USER_AGENT'] ?? 'unknown') . 
               ", Session=" . session_id() . ", Repeat: " . ($isRepeatOffender ? 'Yes' : 'No') .
               ", Duration: " . ($blockDuration/60) . " minutes, Reason: $reason");
 }
 
 private function sendBlockResponse() {
     if (!headers_sent()) {
         http_response_code(429);
         header('Content-Type: text/plain; charset=utf-8');
         header('Retry-After: 900'); // 15 минут вместо 30
     }
     die('Rate limit exceeded. Please try again later.');
 }
 
 /**
  * ИСПРАВЛЕННАЯ функция получения информации о заблокированном пользователе
  */
 public function getUserHashInfo($userHash = null) {
     $userHash = $userHash ?: $this->generateUserHash(); // Стабильный хеш
     
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
 
 /**
  * ИСПРАВЛЕННАЯ функция разблокировки пользователя по хешу
  */
 public function unblockUserHash($userHash = null) {
     $userHash = $userHash ?: $this->generateUserHash(); // Стабильный хеш
     
     $blockKey = $this->userHashPrefix . 'blocked:' . $userHash;
     $trackingKey = $this->userHashPrefix . 'tracking:' . $userHash;
     
     $result = [
         'user_hash' => substr($userHash, 0, 16) . '...',
         'unblocked' => $this->redis->del($blockKey) > 0,
         'tracking_cleared' => $this->redis->del($trackingKey) > 0
     ];
     
     error_log("User hash unblocked manually: " . substr($userHash, 0, 12) . "...");
     return $result;
 }
 
 /**
  * НОВАЯ функция для диагностики хеша пользователя
  */
 public function diagnoseUserHash() {
     $ip = $this->getRealIP();
     $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
     $browserInfo = $this->getBrowserFingerprint($userAgent);
     $isMobile = $this->isMobileDevice($userAgent);
     
     $userHash = $this->generateUserHash();
     $sessionHash = $this->generateSessionUserHash();
     
     $diagnosis = [
         'stable_hash' => substr($userHash, 0, 16) . '...',
         'session_hash' => substr($sessionHash, 0, 16) . '...',
         'ip' => $ip,
         'ip_fingerprint' => $isMobile ? $this->getIPFingerprint($ip) : $ip,
         'device_type' => $isMobile ? 'mobile' : 'desktop',
         'browser' => $browserInfo,
         'session_id' => session_id() ?: 'none',
         'user_agent' => substr($userAgent, 0, 100) . '...',
         'accept_language' => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? 'none',
         'accept_encoding' => $_SERVER['HTTP_ACCEPT_ENCODING'] ?? 'none'
     ];
     
     error_log("User hash diagnosis: " . json_encode($diagnosis, JSON_UNESCAPED_UNICODE));
     return $diagnosis;
 }
 
 /**
  * Получает статистику по хеш-блокировкам
  */
 public function getUserHashStats() {
     $stats = [
         'blocked_user_hashes' => 0,
         'tracked_user_hashes' => 0,
         'total_hash_blocks' => 0
     ];
     
     try {
         // Подсчет заблокированных хешей пользователей
         $blockedHashes = $this->redis->keys($this->userHashPrefix . 'blocked:*');
         $stats['blocked_user_hashes'] = count($blockedHashes);
         
         // Подсчет отслеживаемых хешей
         $trackedHashes = $this->redis->keys($this->userHashPrefix . 'tracking:*');
         $stats['tracked_user_hashes'] = count($trackedHashes);
         
         // Подсчет общего количества блокировок
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
 
 /**
  * Очистка данных по хешам пользователей
  */
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
 
 // Метод для получения статистики (опционально)
 public function getStats() {
     $stats = [
         'blocked_ips' => 0,
         'blocked_sessions' => 0,
         'blocked_cookies' => 0,
         'tracking_records' => 0,
         'total_keys' => 0,
         'memory_usage' => 0
     ];
     
     try {
         // Подсчет заблокированных IP
         $blockedIPs = $this->redis->keys($this->blockPrefix . 'ip:*');
         $stats['blocked_ips'] = count($blockedIPs);
         
         // Подсчет заблокированных сессий
         $blockedSessions = $this->redis->keys($this->sessionPrefix . 'blocked:*');
         $stats['blocked_sessions'] = count($blockedSessions);
         
         // Подсчет заблокированных cookies
         $blockedCookies = $this->redis->keys($this->cookiePrefix . 'blocked:*');
         $stats['blocked_cookies'] = count($blockedCookies);
         
         // Подсчет записей трекинга
         $trackingRecords = $this->redis->keys($this->trackingPrefix . 'ip:*');
         $stats['tracking_records'] = count($trackingRecords);
         
         // Общее количество ключей
         $allKeys = $this->redis->keys('*');
         $stats['total_keys'] = count($allKeys);
         
         // Информация о памяти Redis
         $info = $this->redis->info('memory');
         $stats['memory_usage'] = $info['used_memory_human'] ?? 'unknown';
         
         // Добавляем статистику по хешам пользователей
         $userHashStats = $this->getUserHashStats();
         $stats = array_merge($stats, $userHashStats);
         
     } catch (Exception $e) {
         error_log("Error getting stats: " . $e->getMessage());
     }
     
     return $stats;
 }
 
 // Улучшенный метод очистки с дополнительными фильтрами
 public function cleanup($force = false) {
     try {
         $cleaned = 0;
         $startTime = microtime(true);
         
         // Паттерны для очистки с приоритетами
         $cleanupPatterns = [
             // Высокий приоритет - короткие TTL
             ['pattern' => $this->trackingPrefix . 'ip:*', 'priority' => 1],
             ['pattern' => $this->rdnsPrefix . 'cache:*', 'priority' => 1],
             ['pattern' => $this->sessionPrefix . 'data:*', 'priority' => 1],
             ['pattern' => $this->userHashPrefix . 'tracking:*', 'priority' => 1],
             // Средний приоритет
             ['pattern' => $this->blockPrefix . 'ip:*', 'priority' => 2],
             ['pattern' => $this->cookiePrefix . 'blocked:*', 'priority' => 2],
             ['pattern' => $this->sessionPrefix . 'blocked:*', 'priority' => 2],
             ['pattern' => $this->userHashPrefix . 'blocked:*', 'priority' => 2],
             // Низкий приоритет - логи
             ['pattern' => 'logs:*', 'priority' => 3]
         ];
         
         foreach ($cleanupPatterns as $patternInfo) {
             if (!$force && (microtime(true) - $startTime) > 2) break; // Лимит 2 секунды
             
             $keys = $this->redis->keys($patternInfo['pattern']);
             foreach ($keys as $key) {
                 if (!$force && (microtime(true) - $startTime) > 2) break;
                 
                 $ttl = $this->redis->ttl($key);
                 
                 // Удаляем ключи без TTL или с истекшим сроком
                 if ($ttl === -1) {
                     $this->redis->del($key);
                     $cleaned++;
                 } elseif ($ttl === -2) {
                     // Ключ уже не существует, пропускаем
                     continue;
                 }
                 
                 // Для логов - дополнительная проверка по дате
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
                 
                 // Ограничиваем размеры списков
                 if ($this->redis->type($key) === Redis::REDIS_LIST) {
                     $listSize = $this->redis->llen($key);
                     if ($listSize > 500) { // Было 1000
                         $this->redis->ltrim($key, 0, 499);
                         $cleaned++;
                     }
                 }
             }
         }
         
         $executionTime = round((microtime(true) - $startTime) * 1000);
         error_log("Cleanup completed: $cleaned items processed in {$executionTime}ms");
         
         return $cleaned;
         
     } catch (Exception $e) {
         error_log("Cleanup error: " . $e->getMessage());
         return false;
     }
 }
 
 // Метод для массовой очистки старых данных (для крон-задач)
 public function deepCleanup() {
     try {
         $totalCleaned = 0;
         $startTime = microtime(true);
         
         // Очистка по дням для логов (сократили период хранения)
         for ($i = 2; $i <= 14; $i++) { // Было 7-30, стало 2-14
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
         
         // Принудительная очистка всех истекших ключей
         $this->cleanup(true);
         
         // Очистка данных по хешам пользователей
         $totalCleaned += $this->cleanupUserHashData();
         
         // Оптимизация Redis памяти
         try {
             $this->redis->bgrewriteaof();
         } catch (Exception $e) {
             // Игнорируем ошибки AOF
         }
         
         $executionTime = round((microtime(true) - $startTime) * 1000);
         error_log("Deep cleanup completed: $totalCleaned items removed in {$executionTime}ms");
         
         return $totalCleaned;
         
     } catch (Exception $e) {
         error_log("Deep cleanup error: " . $e->getMessage());
         return false;
     }
 }
 
 // Метод для разблокировки IP (для администратора)
 public function unblockIP($ip) {
     $blockKey = $this->blockPrefix . 'ip:' . hash('md5', $ip);
     $trackingKey = $this->trackingPrefix . 'ip:' . hash('md5', $ip);
     
     $result = [
         'ip_unblocked' => $this->redis->del($blockKey) > 0,
         'tracking_cleared' => $this->redis->del($trackingKey) > 0
     ];
     
     error_log("IP unblocked manually: $ip");
     return $result;
 }
 
 // Метод для разблокировки сессии
 public function unblockSession($sessionId) {
     $blockKey = $this->sessionPrefix . 'blocked:' . $sessionId;
     $dataKey = $this->sessionPrefix . 'data:' . $sessionId;
     
     $result = [
         'session_unblocked' => $this->redis->del($blockKey) > 0,
         'session_data_cleared' => $this->redis->del($dataKey) > 0
     ];
     
     error_log("Session unblocked manually: $sessionId");
     return $result;
 }
 
 // Метод для получения информации о заблокированном IP
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
 
 // Метод для получения информации о TTL настройках
 public function getTTLSettings() {
     return $this->ttlSettings;
 }
 
 // Метод для обновления TTL настроек
 public function updateTTLSettings($newSettings) {
     $this->ttlSettings = array_merge($this->ttlSettings, $newSettings);
     error_log("TTL settings updated: " . json_encode($newSettings));
 }
 
 // Деструктор для закрытия соединения с Redis
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

// Использование:
try {
 // Инициализация с настройками Redis
 $protection = new RedisBotProtectionWithSessions(
     '127.0.0.1',    // Redis host
     6379,           // Redis port
     null,           // Redis password (если нужен)
     0               // Redis database
 );
 
 // Запуск защиты с оптимизированными TTL
 $protection->protect();
 
 // Опционально: получение статистики (только для админов)
 // $stats = $protection->getStats();
 // error_log("Bot protection stats: " . json_encode($stats));
 
 // Пример работы с хеш-блокировками:
 // $userHashInfo = $protection->getUserHashInfo();
 // $userHashStats = $protection->getUserHashStats();
 
 // Для разблокировки пользователя:
 // $protection->unblockUserHash();
 
 // Для диагностики хеша:
 // $diagnosis = $protection->diagnoseUserHash();
 
 // Для крон-задач: глубокая очистка каждые 6 часов
 // if (date('H') % 6 === 0 && date('i') === '00') {
 //     $protection->deepCleanup();
 // }
 
} catch (Exception $e) {
 error_log("Bot protection error: " . $e->getMessage());
 // В случае ошибки Redis - продолжаем работу без защиты
}
?>
