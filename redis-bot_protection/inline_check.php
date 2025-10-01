<?php
// /var/www/your-site/bot_protection/redis_inline_check.php

class RedisBotProtectionNoSessions {
    private $redis;
    private $cookieName = 'visitor_verified';
    private $secretKey = 'your_secret_key_here_change_this12345!@#$';
    private $cookieLifetime = 86400 * 30; // 30 дней
    
    // Префиксы для Redis ключей
    private $redisPrefix = 'bot_protection:';
    private $trackingPrefix = 'tracking:';
    private $blockPrefix = 'blocked:';
    private $cookiePrefix = 'cookie:';
    private $rdnsPrefix = 'rdns:';
    private $userHashPrefix = 'user_hash:';
    
    // TTL настройки
    private $ttlSettings = [
        'tracking_ip' => 10800,         // 3 часа
        'cookie_blocked' => 7200,       // 2 часа
        'ip_blocked' => 86400,          // 24 часа
        'ip_blocked_repeat' => 259200,  // 3 дня
        'rdns_cache' => 1800,           // 30 мин
        'logs' => 172800,               // 2 дня
        'cleanup_interval' => 1800,     // 30 мин
        'user_hash_blocked' => 172800,  // 2 дня
        'user_hash_tracking' => 21600,  // 6 часов
        'user_hash_stats' => 604800,    // 7 дней
        'extended_tracking' => 86400,   // 24 часа
    ];
    
    // Настройки для медленных ботов
    private $slowBotSettings = [
        'min_requests_for_analysis' => 3,
        'slow_bot_threshold_hours' => 4,
        'slow_bot_min_requests' => 15,
        'long_session_hours' => 2,
        'suspicious_regularity_variance' => 100,
    ];
    
    // Настройки rate limiting и защиты от нагрузки
    private $rateLimitSettings = [
        'max_requests_per_minute' => 60,        // Максимум запросов в минуту
        'max_requests_per_5min' => 200,         // Максимум запросов за 5 минут
        'max_requests_per_hour' => 1000,        // Максимум запросов в час
        'burst_threshold' => 20,                 // Порог всплеска (запросов за 10 сек)
        'burst_window' => 10,                    // Окно для детекции всплеска (секунды)
        'ua_change_threshold' => 5,              // Макс. смен UA за сессию
        'ua_change_time_window' => 300,          // Окно для детекции смены UA (5 мин)
        'progressive_block_duration' => 1800,    // Прогрессивная блокировка (30 мин)
        'aggressive_block_duration' => 7200,     // Агрессивная блокировка (2 часа)
    ];
    
    // Список поисковиков с точными паттернами
    private $allowedSearchEngines = [
        'googlebot' => [
            'user_agent_patterns' => [
                'googlebot', 'google', 'googleother',
                'googlebot-image', 'googlebot-news', 'googlebot-video'
            ],
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
            'user_agent_patterns' => ['amazonbot', 'amazon bot', 'amazon-bot'],
            'rdns_patterns' => ['.amazon.com', '.amazon', '.crawl.amazonbot.amazon']
        ],
        'petalbot' => [
            'user_agent_patterns' => ['petalbot'],
            'rdns_patterns' => ['.petalsearch.com']
        ],
        'sogou' => [
            'user_agent_patterns' => ['sogou'],
            'rdns_patterns' => ['.sogou.com']
        ],
        'telegrambot' => [
            'user_agent_patterns' => ['telegrambot', 'telegram bot'],
            'rdns_patterns' => ['.telegram.org', '.ptr.telegram.org']
        ]
    ];
    
    public function __construct($redisHost = '127.0.0.1', $redisPort = 6379, $redisPassword = null, $redisDatabase = 0) {
        $this->initRedis($redisHost, $redisPort, $redisPassword, $redisDatabase);
        $this->autoCleanup();
    }
    
    private function initRedis($host, $port, $password, $database) {
        try {
            $this->redis = new Redis();
            
            if (!$this->redis->connect($host, $port, 2)) {
                throw new Exception("Cannot connect to Redis server at {$host}:{$port}");
            }
            
            if ($password) {
                if (!$this->redis->auth($password)) {
                    throw new Exception("Redis authentication failed");
                }
            }
            
            if (!$this->redis->select($database)) {
                throw new Exception("Cannot select Redis database {$database}");
            }
            
            $this->redis->setOption(Redis::OPT_SERIALIZER, Redis::SERIALIZER_JSON);
            $this->redis->setOption(Redis::OPT_PREFIX, $this->redisPrefix);
            
            if (!$this->redis->ping()) {
                throw new Exception("Redis ping failed");
            }
            
        } catch (Exception $e) {
            error_log("CRITICAL: Redis connection failed - " . $e->getMessage());
            throw $e;
        }
    }
    
    private function autoCleanup() {
        try {
            $lastCleanupKey = 'last_cleanup';
            $lastCleanup = $this->redis->get($lastCleanupKey);
            
            if (!$lastCleanup || (time() - $lastCleanup) > $this->ttlSettings['cleanup_interval']) {
                $this->aggressiveCleanup();
                $this->redis->setex($lastCleanupKey, $this->ttlSettings['cleanup_interval'], time());
            }
        } catch (Exception $e) {
            error_log("Cleanup error: " . $e->getMessage());
        }
    }
    
    private function aggressiveCleanup() {
        try {
            $cleaned = 0;
            $startTime = microtime(true);
            $maxExecutionTime = 0.05;
            
            $patterns = [
                $this->trackingPrefix . 'ip:*',
                $this->userHashPrefix . 'tracking:*',
                $this->rdnsPrefix . 'cache:*',
                $this->trackingPrefix . 'extended:*'
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
    
    private function normalizeIPv6($ip) {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return $ip;
        }
        
        $binary = @inet_pton($ip);
        if ($binary === false) {
            return $ip;
        }
        
        $normalized = @inet_ntop($binary);
        return $normalized ?: $ip;
    }
    
    private function normalizeIP($ip) {
        $ip = trim($ip);
        
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return $ip;
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
        try {
            $userHash = $this->generateUserHash();
            $blockKey = $this->userHashPrefix . 'blocked:' . $userHash;
            return $this->redis->exists($blockKey);
        } catch (Exception $e) {
            error_log("Error checking user hash block: " . $e->getMessage());
            return false;
        }
    }
    
    private function blockUserHash($reason = 'Bot behavior detected') {
        try {
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
            
            error_log("Bot blocked [HASH]: " . substr($userHash, 0, 8) . " | IP: $ip | " . $blockData['device_type'] . " | " . $reason);
        } catch (Exception $e) {
            error_log("Error blocking user hash: " . $e->getMessage());
        }
    }
    
    private function trackUserHashActivity() {
        try {
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
                
                if (count($existing['request_times']) > 30) {
                    $existing['request_times'] = array_slice($existing['request_times'], -30);
                }
                if (count($existing['pages']) > 50) {
                    $existing['pages'] = array_unique(array_slice($existing['pages'], -50));
                }
                if (count($existing['ips']) > 15) {
                    $existing['ips'] = array_unique(array_slice($existing['ips'], -15));
                }
                
                $this->redis->setex($trackingKey, $this->ttlSettings['user_hash_tracking'], $existing);
                return $existing;
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
                return $data;
            }
        } catch (Exception $e) {
            error_log("Error tracking user hash: " . $e->getMessage());
            return [];
        }
    }
    
    private function analyzeSlowBot($trackingData) {
        if (!$trackingData || $trackingData['requests'] < $this->slowBotSettings['min_requests_for_analysis']) {
            return false;
        }
        
        $score = 0;
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $isMobile = $this->isMobileDevice($userAgent);
        
        $blockThreshold = $isMobile ? 12 : 10;
        
        $requests = $trackingData['requests'];
        $timeSpent = time() - ($trackingData['first_seen'] ?? time());
        
        if ($this->isSuspiciousUserAgent($userAgent)) {
            $score += $isMobile ? 8 : 10;
        }
        
        if ($timeSpent > 3600) {
            $requestsPerHour = ($requests * 3600) / $timeSpent;
            
            if ($requestsPerHour > 30 && $requests > 20) {
                $score += 4;
            }
            
            if ($requestsPerHour > 10 && $timeSpent > 7200) {
                $score += 3;
            }
        }
        
        $uniquePages = array_unique($trackingData['pages'] ?? []);
        $totalPages = count($trackingData['pages'] ?? []);
        
        if ($totalPages > 10) {
            $pageVariety = count($uniquePages) / $totalPages;
            
            if ($pageVariety < 0.3 && $totalPages > 15) {
                $score += 3;
            }
            
            if ($pageVariety > 0.8 && $totalPages > 25) {
                $score += 2;
            }
        }
        
        $currentHeaders = $this->collectHeaders();
        if (!isset($currentHeaders['HTTP_REFERER']) && $requests > 10) {
            $score += 1;
        }
        
        $uniqueIPs = array_unique($trackingData['ips'] ?? []);
        if (count($uniqueIPs) > 3 && $requests > 10) {
            $score += 2;
        }
        
        if (isset($trackingData['request_times']) && count($trackingData['request_times']) >= 8) {
            $times = $trackingData['request_times'];
            $intervals = [];
            
            for ($i = 1; $i < count($times); $i++) {
                $intervals[] = $times[$i] - $times[$i-1];
            }
            
            if (count($intervals) >= 5) {
                $avgInterval = array_sum($intervals) / count($intervals);
                $variance = 0;
                foreach ($intervals as $interval) {
                    $variance += pow($interval - $avgInterval, 2);
                }
                $variance /= count($intervals);
                
                if ($variance < $this->slowBotSettings['suspicious_regularity_variance'] && 
                    $avgInterval > 60 && $avgInterval < 600) {
                    $score += 4;
                }
            }
        }
        
        return $score >= $blockThreshold;
    }
    
    private function enableExtendedTracking($ip, $reason = 'Potential slow bot') {
        try {
            $extendedKey = $this->trackingPrefix . 'extended:' . hash('md5', $ip);
            $extendedData = [
                'enabled_at' => time(),
                'reason' => $reason,
                'ip' => $ip,
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
                'extended_requests' => 1,
                'extended_pages' => [parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH)]
            ];
            
            $this->redis->setex($extendedKey, $this->ttlSettings['extended_tracking'], $extendedData);
            
            error_log("Extended tracking enabled for IP: $ip | Reason: $reason");
        } catch (Exception $e) {
            error_log("Error enabling extended tracking: " . $e->getMessage());
        }
    }
    
    private function checkExtendedTracking($ip) {
        try {
            $extendedKey = $this->trackingPrefix . 'extended:' . hash('md5', $ip);
            return $this->redis->exists($extendedKey);
        } catch (Exception $e) {
            error_log("Error checking extended tracking: " . $e->getMessage());
            return false;
        }
    }
    
    private function getUserTrackingData($ip) {
        try {
            $trackingKey = $this->trackingPrefix . 'ip:' . hash('md5', $ip);
            return $this->redis->get($trackingKey);
        } catch (Exception $e) {
            error_log("Error getting user tracking data: " . $e->getMessage());
            return null;
        }
    }
    
    private function isPotentialSlowBot($trackingData) {
        if (!$trackingData || $trackingData['requests'] < 5) {
            return false;
        }
        
        $timeSpent = time() - ($trackingData['first_seen'] ?? time());
        $requests = $trackingData['requests'];
        
        if ($timeSpent > ($this->slowBotSettings['long_session_hours'] * 3600) && 
            $requests > 10 && $requests < 100) {
            return true;
        }
        
        if (isset($trackingData['request_times']) && count($trackingData['request_times']) >= 8) {
            $times = $trackingData['request_times'];
            $intervals = [];
            
            for ($i = 1; $i < count($times); $i++) {
                $intervals[] = $times[$i] - $times[$i-1];
            }
            
            if (count($intervals) >= 5) {
                $avgInterval = array_sum($intervals) / count($intervals);
                $variance = 0;
                foreach ($intervals as $interval) {
                    $variance += pow($interval - $avgInterval, 2);
                }
                $variance /= count($intervals);
                
                if ($variance < $this->slowBotSettings['suspicious_regularity_variance'] && 
                    $avgInterval > 60 && $avgInterval < 600) {
                    return true;
                }
            }
        }
        
        if ($timeSpent > 3600 && $requests > 8) {
            $headers = $this->collectHeaders();
            $missingHeaders = 0;
            
            if (!isset($headers['HTTP_REFERER'])) $missingHeaders++;
            if (!isset($headers['HTTP_ACCEPT_LANGUAGE'])) $missingHeaders++;
            if (($headers['HTTP_ACCEPT'] ?? '') === '*/*') $missingHeaders++;
            
            if ($missingHeaders >= 2) {
                return true;
            }
        }
        
        return false;
    }
    
    private function analyzeUserHashBehavior() {
        $trackingData = $this->trackUserHashActivity();
        
        if (!$trackingData || $trackingData['requests'] < $this->slowBotSettings['min_requests_for_analysis']) {
            return false;
        }
        
        $standardResult = $this->performStandardUserHashAnalysis($trackingData);
        $slowBotResult = $this->analyzeSlowBot($trackingData);
        
        return $standardResult || $slowBotResult;
    }
    
    private function performStandardUserHashAnalysis($trackingData) {
        $score = 0;
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $isMobile = $this->isMobileDevice($userAgent);
        $browserInfo = $this->getBrowserFingerprint($userAgent);
        
        $blockThreshold = $isMobile ? 20 : 18;
        
        if ($this->isSuspiciousUserAgent($userAgent)) {
            $score += $isMobile ? 15 : 20;
        }
        
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
        
        $uniquePages = array_unique($trackingData['pages'] ?? []);
        $totalPages = count($trackingData['pages'] ?? []);
        
        if ($totalPages > 60) {
            $pageVariety = count($uniquePages) / $totalPages;
            if ($pageVariety < 0.05) {
                $score += $isMobile ? 3 : 4;
            }
        }
        
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
        
        $uniqueIPs = array_unique($trackingData['ips'] ?? []);
        if (count($uniqueIPs) > 15) {
            $score += 8;
        }
        
        $userHash = $this->generateUserHash();
        $statsKey = $this->userHashPrefix . 'stats:' . $userHash;
        $blockCount = $this->redis->hget($statsKey, 'block_count') ?: 0;
        
        if ($blockCount > 2) {
            $score += $blockCount * 3;
        }
        
        return $score >= $blockThreshold;
    }
    
    /**
     * НОВЫЙ МЕТОД: Проверка rate limit
     */
    private function checkRateLimit($ip) {
        try {
            $rateLimitKey = $this->trackingPrefix . 'ratelimit:' . hash('md5', $ip);
            $current = time();
            
            $data = $this->redis->get($rateLimitKey);
            
            if (!$data) {
                $data = [
                    'requests_1min' => 1,
                    'requests_5min' => 1,
                    'requests_1hour' => 1,
                    'window_1min_start' => $current,
                    'window_5min_start' => $current,
                    'window_1hour_start' => $current,
                    'last_request' => $current,
                    'violations' => 0
                ];
                
                $this->redis->setex($rateLimitKey, 3600, $data);
                return ['allowed' => true, 'reason' => null];
            }
            
            if ($current - $data['window_1min_start'] >= 60) {
                $data['requests_1min'] = 0;
                $data['window_1min_start'] = $current;
            }
            
            if ($current - $data['window_5min_start'] >= 300) {
                $data['requests_5min'] = 0;
                $data['window_5min_start'] = $current;
            }
            
            if ($current - $data['window_1hour_start'] >= 3600) {
                $data['requests_1hour'] = 0;
                $data['window_1hour_start'] = $current;
            }
            
            $data['requests_1min']++;
            $data['requests_5min']++;
            $data['requests_1hour']++;
            $data['last_request'] = $current;
            
            $violations = [];
            
            if ($data['requests_1min'] > $this->rateLimitSettings['max_requests_per_minute']) {
                $violations[] = 'requests_per_minute';
            }
            
            if ($data['requests_5min'] > $this->rateLimitSettings['max_requests_per_5min']) {
                $violations[] = 'requests_per_5min';
            }
            
            if ($data['requests_1hour'] > $this->rateLimitSettings['max_requests_per_hour']) {
                $violations[] = 'requests_per_hour';
            }
            
            if (!empty($violations)) {
                $data['violations']++;
                $this->redis->setex($rateLimitKey, 3600, $data);
                
                return [
                    'allowed' => false,
                    'reason' => 'Rate limit exceeded: ' . implode(', ', $violations),
                    'violations' => $violations,
                    'violation_count' => $data['violations'],
                    'stats' => [
                        '1min' => $data['requests_1min'],
                        '5min' => $data['requests_5min'],
                        '1hour' => $data['requests_1hour']
                    ]
                ];
            }
            
            $this->redis->setex($rateLimitKey, 3600, $data);
            return ['allowed' => true, 'reason' => null];
            
        } catch (Exception $e) {
            error_log("Error in checkRateLimit: " . $e->getMessage());
            return ['allowed' => true, 'reason' => null];
        }
    }
    
    /**
     * НОВЫЙ МЕТОД: Детекция всплесков активности
     */
    private function detectBurst($ip) {
        try {
            $trackingKey = $this->trackingPrefix . 'ip:' . hash('md5', $ip);
            $data = $this->redis->get($trackingKey);
            
            if (!$data || !isset($data['request_times'])) {
                return false;
            }
            
            $recentRequests = array_filter($data['request_times'], function($time) {
                return (time() - $time) <= $this->rateLimitSettings['burst_window'];
            });
            
            if (count($recentRequests) >= $this->rateLimitSettings['burst_threshold']) {
                return [
                    'detected' => true,
                    'requests_in_window' => count($recentRequests),
                    'threshold' => $this->rateLimitSettings['burst_threshold'],
                    'window' => $this->rateLimitSettings['burst_window']
                ];
            }
            
            return false;
            
        } catch (Exception $e) {
            error_log("Error in detectBurst: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * НОВЫЙ МЕТОД: Детекция смены User-Agent
     */
    private function detectUserAgentSwitching($ip) {
        try {
            $trackingKey = $this->trackingPrefix . 'ip:' . hash('md5', $ip);
            $data = $this->redis->get($trackingKey);
            
            if (!$data) {
                return false;
            }
            
            $uniqueUA = array_unique($data['user_agents'] ?? []);
            $uaCount = count($uniqueUA);
            
            if ($uaCount >= $this->rateLimitSettings['ua_change_threshold']) {
                $timeSpent = time() - ($data['first_seen'] ?? time());
                
                if ($timeSpent < $this->rateLimitSettings['ua_change_time_window']) {
                    return [
                        'detected' => true,
                        'unique_ua_count' => $uaCount,
                        'time_window' => $timeSpent,
                        'threshold' => $this->rateLimitSettings['ua_change_threshold'],
                        'user_agents' => array_map(function($ua) {
                            return substr($ua, 0, 50) . '...';
                        }, $uniqueUA)
                    ];
                }
            }
            
            return false;
            
        } catch (Exception $e) {
            error_log("Error in detectUserAgentSwitching: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * НОВЫЙ МЕТОД: Прогрессивная блокировка
     */
    private function applyProgressiveBlock($ip, $reason, $violationData = null) {
        try {
            $blockKey = $this->blockPrefix . 'ip:' . hash('md5', $ip);
            $historyKey = $this->blockPrefix . 'history:' . hash('md5', $ip);
            
            $history = $this->redis->get($historyKey) ?: ['count' => 0, 'last_block' => 0];
            $history['count']++;
            $history['last_block'] = time();
            
            $blockDuration = $this->rateLimitSettings['progressive_block_duration'];
            
            if ($history['count'] >= 3) {
                $blockDuration = $this->rateLimitSettings['aggressive_block_duration'] * $history['count'];
            }
            
            $blockData = [
                'ip' => $ip,
                'blocked_at' => time(),
                'blocked_reason' => $reason,
                'violation_count' => $history['count'],
                'block_duration' => $blockDuration,
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
                'uri' => $_SERVER['REQUEST_URI'] ?? '',
                'violation_data' => $violationData
            ];
            
            $this->redis->setex($blockKey, $blockDuration, $blockData);
            $this->redis->setex($historyKey, 86400 * 7, $history);
            
            $hours = round($blockDuration / 3600, 1);
            error_log("RATE LIMIT BLOCK: $ip | Count: {$history['count']} | Duration: {$hours}h | $reason");
            
            return true;
            
        } catch (Exception $e) {
            error_log("Error in applyProgressiveBlock: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * ОБНОВЛЕННЫЙ МЕТОД protect() с rate limiting
     */
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
        
        if ($this->isUserHashBlocked()) {
            $this->sendBlockResponse();
        }
        
        if ($this->isCookieBlocked()) {
            $this->sendBlockResponse();
        }
        
        if ($this->isBlocked($ip) && $this->isSuspiciousUserAgent($userAgent)) {
            $this->sendBlockResponse();
        }
        
        // НОВОЕ: Проверка rate limit
        $rateLimitResult = $this->checkRateLimit($ip);
        if (!$rateLimitResult['allowed']) {
            if ($rateLimitResult['violation_count'] >= 3) {
                $this->applyProgressiveBlock($ip, $rateLimitResult['reason'], $rateLimitResult);
                $this->blockUserHash('Repeated rate limit violations');
                $this->sendBlockResponse();
            }
            error_log("RATE LIMIT WARNING: $ip | " . $rateLimitResult['reason'] . " | Violations: " . $rateLimitResult['violation_count']);
        }
        
        // НОВОЕ: Детекция смены User-Agent
        $uaSwitching = $this->detectUserAgentSwitching($ip);
        if ($uaSwitching && $uaSwitching['detected']) {
            $this->applyProgressiveBlock($ip, 'User-Agent switching detected', $uaSwitching);
            $this->blockUserHash('UA switching');
            if (isset($_COOKIE[$this->cookieName])) {
                $this->blockCookieHash();
            }
            $this->sendBlockResponse();
        }
        
        // НОВОЕ: Детекция всплесков
        $burstDetected = $this->detectBurst($ip);
        if ($burstDetected && $burstDetected['detected']) {
            $this->applyProgressiveBlock($ip, 'Burst activity detected', $burstDetected);
            $this->blockUserHash('Burst activity');
            $this->sendBlockResponse();
        }
        
        $hasExtendedTracking = $this->checkExtendedTracking($ip);
        
        if ($this->hasValidCookie()) {
            $this->trackUserHashActivity();
            
            if ($this->shouldAnalyzeIP($ip) || $hasExtendedTracking) {
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
        
        if ($this->shouldAnalyzeIP($ip) || $hasExtendedTracking) {
            if ($this->analyzeRequest($ip)) {
                if ($this->isSuspiciousUserAgent($userAgent)) {
                    $this->blockIP($ip, 'Suspicious user agent detected');
                    if (isset($_COOKIE[$this->cookieName])) {
                        $this->blockCookieHash();
                    }
                    $this->blockUserHash('Bot detected');
                } else {
                    if (!$hasExtendedTracking) {
                        $this->enableExtendedTracking($ip, 'Suspicious browser behavior');
                    }
                    
                    if (isset($_COOKIE[$this->cookieName])) {
                        $this->blockCookieHash();
                    } else {
                        $this->blockUserHash('Browser behavior detected without cookie');
                    }
                }
                $this->sendBlockResponse();
            }
        }
        
        if ($this->analyzeUserHashBehavior()) {
            if ($this->isSuspiciousUserAgent($userAgent)) {
                $this->blockIP($ip, 'Bot behavior confirmed by user hash analysis');
                $this->blockUserHash('Bot confirmed');
                if (isset($_COOKIE[$this->cookieName])) {
                    $this->blockCookieHash();
                }
            } else {
                $this->blockUserHash('Slow bot behavior detected');
                if (isset($_COOKIE[$this->cookieName])) {
                    $this->blockCookieHash();
                }
            }
            
            $this->sendBlockResponse();
        }
        
        $trackingData = $this->getUserTrackingData($ip);
        if ($trackingData && $this->isPotentialSlowBot($trackingData)) {
            if (!$hasExtendedTracking) {
                $this->enableExtendedTracking($ip, 'Potential slow bot pattern');
            }
        }
        
        if (!isset($_COOKIE[$this->cookieName])) {
            $this->setVisitorCookie();
            $this->initTracking($ip);
        }
    }
    
    private function shouldAnalyzeIP($ip) {
        try {
            $trackingKey = $this->trackingPrefix . 'ip:' . hash('md5', $ip);
            $data = $this->redis->get($trackingKey);
            
            if ($data) {
                $requests = $data['requests'] ?? 0;
                $timeSpent = time() - ($data['first_seen'] ?? time());
                $suspicious_ua = $this->isSuspiciousUserAgent($_SERVER['HTTP_USER_AGENT'] ?? '');
                
                if ($suspicious_ua) {
                    return true;
                }
                
                if ($timeSpent > 1800 && $requests >= 5) {
                    return true;
                }
                
                if ($requests > 5) {
                    return true;
                }
                
                if ($timeSpent > 0 && $requests >= $this->slowBotSettings['min_requests_for_analysis']) {
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
        } catch (Exception $e) {
            error_log("Error in shouldAnalyzeIP: " . $e->getMessage());
            return false;
        }
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
            'cloudflare', 'fastly', 'keycdn', 'meta-externalagent',
            'OAI-SearchBot', 'ChatGPT-User', 'GPTBot', 'Claude-User', 'ClaudeBot'
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
        try {
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
        } catch (Exception $e) {
            error_log("Error logging bot visit: " . $e->getMessage());
        }
    }
    
    private function isVerifiedSearchEngine($ip, $userAgent) {
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
        
        return $this->verifySearchEngineByRDNS($ip, $this->allowedSearchEngines[$detectedEngine]['rdns_patterns']);
    }
    
    private function verifySearchEngineByRDNS($ip, $allowedPatterns) {
        try {
            $normalizedIP = $this->normalizeIP($ip);
            $cacheKey = $this->rdnsPrefix . 'cache:' . hash('md5', $normalizedIP);
            
            $cached = $this->redis->get($cacheKey);
            if ($cached !== false) {
                return $cached['verified'];
            }
            
            $verified = false;
            $hostname = '';
            $error = '';
            
            try {
                $hostname = $this->getHostnameWithTimeout($normalizedIP, 2);
                
                if ($hostname && $hostname !== $normalizedIP) {
                    $hostnameMatches = false;
                    foreach ($allowedPatterns as $pattern) {
                        if ($this->matchesDomainPattern($hostname, $pattern)) {
                            $hostnameMatches = true;
                            break;
                        }
                    }
                    
                    if ($hostnameMatches) {
                        $forwardIPs = $this->getIPsWithTimeout($hostname, 2);
                        
                        if ($forwardIPs && $this->ipInArray($normalizedIP, $forwardIPs)) {
                            $verified = true;
                        }
                    }
                }
                
            } catch (Exception $e) {
                $error = $e->getMessage();
            }
            
            $cacheData = [
                'ip' => $normalizedIP,
                'hostname' => $hostname,
                'verified' => $verified,
                'timestamp' => time(),
                'error' => $error
            ];
            
            $cacheTTL = $verified ? $this->ttlSettings['rdns_cache'] : 300;
            $this->redis->setex($cacheKey, $cacheTTL, $cacheData);
            
            return $verified;
        } catch (Exception $e) {
            error_log("Error in rDNS verification: " . $e->getMessage());
            return false;
        }
    }
    
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
    
    private function getIPsWithTimeout($hostname, $timeoutSec = 2) {
        $originalTimeout = ini_get('default_socket_timeout');
        ini_set('default_socket_timeout', $timeoutSec);
        
        $allIPs = [];
        
        try {
            $ipv4List = @gethostbynamel($hostname);
            if ($ipv4List) {
                $allIPs = array_merge($allIPs, $ipv4List);
            }
            
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
    
    private function matchesDomainPattern($hostname, $pattern) {
        $hostname = strtolower(trim($hostname));
        $pattern = strtolower(trim($pattern));
        
        if ($hostname === $pattern) {
            return true;
        }
        
        if (strpos($pattern, '.') === 0) {
            return substr($hostname, -strlen($pattern)) === $pattern;
        }
        
        $fullPattern = '.' . $pattern;
        return substr($hostname, -strlen($fullPattern)) === $fullPattern;
    }
    
    private function ipInArray($needle, $haystack) {
        $normalizedNeedle = $this->normalizeIP($needle);
        
        foreach ($haystack as $ip) {
            if ($this->normalizeIP($ip) === $normalizedNeedle) {
                return true;
            }
        }
        
        return false;
    }
    
    private function logSearchEngineVisit($ip, $userAgent) {
        try {
            $logEntry = [
                'timestamp' => date('Y-m-d H:i:s'),
                'ip' => $ip,
                'user_agent' => $userAgent,
                'uri' => $_SERVER['REQUEST_URI'] ?? '',
                'hostname' => @gethostbyaddr($ip)
            ];
            
            $logKey = 'logs:search_engines:' . date('Y-m-d');
            $this->redis->lpush($logKey, $logEntry);
            $this->redis->expire($logKey, $this->ttlSettings['logs']);
            $this->redis->ltrim($logKey, 0, 999);
        } catch (Exception $e) {
            error_log("Error logging search engine visit: " . $e->getMessage());
        }
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
        
        $ipBin = @inet_pton($ip);
        $subnetBin = @inet_pton($subnet);
        
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
        try {
            $time = time();
            $hash = hash('sha256', $time . ($_SERVER['HTTP_USER_AGENT'] ?? '') . $this->secretKey);
            $cookieData = json_encode(['time' => $time, 'hash' => $hash]);
            
            $secure = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
            setcookie($this->cookieName, $cookieData, time() + $this->cookieLifetime, '/', '', $secure, true);
            $_COOKIE[$this->cookieName] = $cookieData;
        } catch (Exception $e) {
            error_log("Error setting visitor cookie: " . $e->getMessage());
        }
    }
    
    private function initTracking($ip) {
        try {
            $trackingKey = $this->trackingPrefix . 'ip:' . hash('md5', $ip);
            $existing = $this->redis->get($trackingKey);
            
            if ($existing) {
                $existing['requests']++;
                $existing['pages'][] = parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH);
                $existing['user_agents'][] = $_SERVER['HTTP_USER_AGENT'] ?? '';
                $existing['user_agents'] = array_unique($existing['user_agents']);
                $existing['request_times'][] = time();
                $existing['real_ip'] = $ip;
                
                if (count($existing['request_times']) > 25) {
                    $existing['request_times'] = array_slice($existing['request_times'], -25);
                }
                if (count($existing['pages']) > 40) {
                    $existing['pages'] = array_slice($existing['pages'], -40);
                }
                if (count($existing['user_agents']) > 5) {
                    $existing['user_agents'] = array_slice($existing['user_agents'], -5);
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
                    'request_times' => [time()],
                    'real_ip' => $ip
                ];
                
                $this->redis->setex($trackingKey, $this->ttlSettings['tracking_ip'], $data);
            }
        } catch (Exception $e) {
            error_log("Error in initTracking: " . $e->getMessage());
        }
    }
    
    private function collectHeaders() {
        $headers = [];
        $importantHeaders = [
            'HTTP_USER_AGENT', 'HTTP_ACCEPT', 'HTTP_ACCEPT_LANGUAGE', 
            'HTTP_ACCEPT_ENCODING', 'HTTP_REFERER', 'HTTP_X_FORWARDED_FOR',
            'HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP', 'REMOTE_ADDR'
        ];
        
        foreach ($importantHeaders as $header) {
            if (isset($_SERVER[$header])) {
                $headers[$header] = $_SERVER[$header];
            }
        }
        return $headers;
    }
    
    private function blockCookieHash() {
        try {
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
            
            error_log("Bot blocked [COOKIE]: " . substr($data['hash'], 0, 8) . " | IP: " . $this->getRealIP());
        } catch (Exception $e) {
            error_log("Error blocking cookie hash: " . $e->getMessage());
        }
    }
    
    private function isCookieBlocked() {
        try {
            if (!isset($_COOKIE[$this->cookieName])) {
                return false;
            }
            
            $data = json_decode($_COOKIE[$this->cookieName], true);
            if (!$data || !isset($data['hash'])) {
                return false;
            }
            
            $blockKey = $this->cookiePrefix . 'blocked:' . hash('md5', $data['hash']);
            return $this->redis->exists($blockKey);
        } catch (Exception $e) {
            error_log("Error checking cookie block: " . $e->getMessage());
            return false;
        }
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
    
    private function analyzeRequest($ip) {
        try {
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
        } catch (Exception $e) {
            error_log("Error in analyzeRequest: " . $e->getMessage());
            return false;
        }
    }
    
    private function isBlocked($ip) {
        try {
            $blockKey = $this->blockPrefix . 'ip:' . hash('md5', $ip);
            return $this->redis->exists($blockKey);
        } catch (Exception $e) {
            error_log("Error checking IP block: " . $e->getMessage());
            return false;
        }
    }
    
    private function blockIP($ip, $reason = 'Bot behavior detected') {
        try {
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
            
            $durHours = round($blockDuration / 3600);
            error_log("Bot blocked [IP]: $ip | " . ($isRepeatOffender ? "REPEAT | " : "") . "{$durHours}h | $reason");
        } catch (Exception $e) {
            error_log("Error blocking IP: " . $e->getMessage());
        }
    }
    
    private function sendBlockResponse() {
        if (!headers_sent()) {
            http_response_code(429);
            header('Content-Type: text/plain; charset=utf-8');
            header('Retry-After: 900');
        }
        die('Rate limit exceeded. Please try again later.');
    }
    
    public function testRDNS($ip, $userAgent = '') {
        $normalizedIP = $this->normalizeIP($ip);
        
        echo "=== ТЕСТ rDNS для IP: $ip ===\n";
        echo "Нормализованный IP: $normalizedIP\n";
        echo "User-Agent: $userAgent\n\n";
        
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
        
        echo "🔍 Шаг 1: Обратный DNS (IP → hostname)\n";
        $hostname = $this->getHostnameWithTimeout($normalizedIP, 3);
        echo "Результат: " . ($hostname ?: 'НЕ НАЙДЕН') . "\n\n";
        
        if (!$hostname) {
            echo "❌ rDNS не найден\n";
            return false;
        }
        
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
    
    // АДМИНИСТРАТИВНЫЕ МЕТОДЫ
    
    public function getUserHashInfo($userHash = null) {
        try {
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
        } catch (Exception $e) {
            error_log("Error getting user hash info: " . $e->getMessage());
            return [];
        }
    }
    
    public function unblockUserHash($userHash = null) {
        try {
            $userHash = $userHash ?: $this->generateUserHash();
            
            $blockKey = $this->userHashPrefix . 'blocked:' . $userHash;
            $trackingKey = $this->userHashPrefix . 'tracking:' . $userHash;
            
            $result = [
                'user_hash' => substr($userHash, 0, 16) . '...',
                'unblocked' => $this->redis->del($blockKey) > 0,
                'tracking_cleared' => $this->redis->del($trackingKey) > 0
            ];
            
            error_log("UNBLOCKED [HASH]: " . substr($userHash, 0, 8) . " | Manual");
            return $result;
        } catch (Exception $e) {
            error_log("Error unblocking user hash: " . $e->getMessage());
            return ['error' => $e->getMessage()];
        }
    }
    
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
            'accept_encoding' => $_SERVER['HTTP_ACCEPT_ENCODING'] ?? 'none',
            'extended_tracking' => $this->checkExtendedTracking($ip)
        ];
    }
    
    public function getUserHashStats() {
        $stats = [
            'blocked_user_hashes' => 0,
            'tracked_user_hashes' => 0,
            'total_hash_blocks' => 0,
            'extended_tracking_active' => 0
        ];
        
        try {
            $blockedHashes = $this->redis->keys($this->userHashPrefix . 'blocked:*');
            $stats['blocked_user_hashes'] = count($blockedHashes);
            
            $trackedHashes = $this->redis->keys($this->userHashPrefix . 'tracking:*');
            $stats['tracked_user_hashes'] = count($trackedHashes);
            
            $extendedTracking = $this->redis->keys($this->trackingPrefix . 'extended:*');
            $stats['extended_tracking_active'] = count($extendedTracking);
            
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
                $this->userHashPrefix . 'stats:*',
                $this->trackingPrefix . 'extended:*'
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
    
    public function getRateLimitStats($ip) {
        try {
            $rateLimitKey = $this->trackingPrefix . 'ratelimit:' . hash('md5', $ip);
            $historyKey = $this->blockPrefix . 'history:' . hash('md5', $ip);
            
            return [
                'ip' => $ip,
                'current_stats' => $this->redis->get($rateLimitKey),
                'block_history' => $this->redis->get($historyKey),
                'is_blocked' => $this->isBlocked($ip),
                'extended_tracking' => $this->checkExtendedTracking($ip)
            ];
        } catch (Exception $e) {
            error_log("Error getting rate limit stats: " . $e->getMessage());
            return [];
        }
    }
    
    public function resetRateLimit($ip) {
        try {
            $rateLimitKey = $this->trackingPrefix . 'ratelimit:' . hash('md5', $ip);
            $historyKey = $this->blockPrefix . 'history:' . hash('md5', $ip);
            
            $result = [
                'rate_limit_cleared' => $this->redis->del($rateLimitKey) > 0,
                'history_cleared' => $this->redis->del($historyKey) > 0
            ];
            
            error_log("RATE LIMIT RESET: $ip | Manual");
            return $result;
        } catch (Exception $e) {
            error_log("Error resetting rate limit: " . $e->getMessage());
            return ['error' => $e->getMessage()];
        }
    }
    
    public function getTopRateLimitViolators($limit = 10) {
        try {
            $rateLimitKeys = $this->redis->keys($this->trackingPrefix . 'ratelimit:*');
            $violators = [];
            
            foreach ($rateLimitKeys as $key) {
                $data = $this->redis->get($key);
                if ($data && isset($data['violations']) && $data['violations'] > 0) {
                    $violators[] = [
                        'key' => $key,
                        'violations' => $data['violations'],
                        'requests_1min' => $data['requests_1min'] ?? 0,
                        'requests_5min' => $data['requests_5min'] ?? 0,
                        'requests_1hour' => $data['requests_1hour'] ?? 0,
                        'last_request' => date('Y-m-d H:i:s', $data['last_request'] ?? 0)
                    ];
                }
            }
            
            usort($violators, function($a, $b) {
                return $b['violations'] - $a['violations'];
            });
            
            return array_slice($violators, 0, $limit);
            
        } catch (Exception $e) {
            error_log("Error getting top violators: " . $e->getMessage());
            return [];
        }
    }
    
    public function getStats() {
        $stats = [
            'blocked_ips' => 0,
            'blocked_cookies' => 0,
            'tracking_records' => 0,
            'rate_limit_tracking' => 0,
            'rate_limit_violations' => 0,
            'extended_tracking_active' => 0,
            'block_history_records' => 0,
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
            
            $rateLimitKeys = $this->redis->keys($this->trackingPrefix . 'ratelimit:*');
            $stats['rate_limit_tracking'] = count($rateLimitKeys);
            
            $violations = 0;
            foreach ($rateLimitKeys as $key) {
                $data = $this->redis->get($key);
                if ($data && isset($data['violations'])) {
                    $violations += $data['violations'];
                }
            }
            $stats['rate_limit_violations'] = $violations;
            
            $extendedTracking = $this->redis->keys($this->trackingPrefix . 'extended:*');
            $stats['extended_tracking_active'] = count($extendedTracking);
            
            $historyKeys = $this->redis->keys($this->blockPrefix . 'history:*');
            $stats['block_history_records'] = count($historyKeys);
            
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
    
    public function cleanup($force = false) {
        try {
            $cleaned = 0;
            $startTime = microtime(true);
            
            $cleanupPatterns = [
                ['pattern' => $this->trackingPrefix . 'ip:*', 'priority' => 1],
                ['pattern' => $this->rdnsPrefix . 'cache:*', 'priority' => 1],
                ['pattern' => $this->userHashPrefix . 'tracking:*', 'priority' => 1],
                ['pattern' => $this->trackingPrefix . 'extended:*', 'priority' => 1],
                ['pattern' => $this->trackingPrefix . 'ratelimit:*', 'priority' => 1],
                ['pattern' => $this->blockPrefix . 'ip:*', 'priority' => 2],
                ['pattern' => $this->cookiePrefix . 'blocked:*', 'priority' => 2],
                ['pattern' => $this->userHashPrefix . 'blocked:*', 'priority' => 2],
                ['pattern' => $this->blockPrefix . 'history:*', 'priority' => 2],
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
        try {
            $blockKey = $this->blockPrefix . 'ip:' . hash('md5', $ip);
            $trackingKey = $this->trackingPrefix . 'ip:' . hash('md5', $ip);
            $extendedKey = $this->trackingPrefix . 'extended:' . hash('md5', $ip);
            
            $result = [
                'ip_unblocked' => $this->redis->del($blockKey) > 0,
                'tracking_cleared' => $this->redis->del($trackingKey) > 0,
                'extended_tracking_cleared' => $this->redis->del($extendedKey) > 0
            ];
            
            error_log("UNBLOCKED [IP]: $ip | Manual");
            return $result;
        } catch (Exception $e) {
            error_log("Error unblocking IP: " . $e->getMessage());
            return ['error' => $e->getMessage()];
        }
    }
    
    public function getBlockedIPInfo($ip) {
        try {
            $blockKey = $this->blockPrefix . 'ip:' . hash('md5', $ip);
            $trackingKey = $this->trackingPrefix . 'ip:' . hash('md5', $ip);
            $extendedKey = $this->trackingPrefix . 'extended:' . hash('md5', $ip);
            
            return [
                'blocked' => $this->redis->exists($blockKey),
                'block_data' => $this->redis->get($blockKey),
                'tracking_data' => $this->redis->get($trackingKey),
                'extended_tracking' => $this->redis->get($extendedKey),
                'ttl' => $this->redis->ttl($blockKey)
            ];
        } catch (Exception $e) {
            error_log("Error getting blocked IP info: " . $e->getMessage());
            return [];
        }
    }
    
    public function getTTLSettings() {
        return $this->ttlSettings;
    }
    
    public function getSlowBotSettings() {
        return $this->slowBotSettings;
    }
    
    public function getRateLimitSettings() {
        return $this->rateLimitSettings;
    }
    
    public function updateTTLSettings($newSettings) {
        $this->ttlSettings = array_merge($this->ttlSettings, $newSettings);
        error_log("TTL settings updated: " . json_encode($newSettings));
    }
    
    public function updateSlowBotSettings($newSettings) {
        $this->slowBotSettings = array_merge($this->slowBotSettings, $newSettings);
        error_log("Slow bot settings updated: " . json_encode($newSettings));
    }
    
    public function updateRateLimitSettings($newSettings) {
        $this->rateLimitSettings = array_merge($this->rateLimitSettings, $newSettings);
        error_log("Rate limit settings updated: " . json_encode($newSettings));
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

// ========================================
// ИСПОЛЬЗОВАНИЕ ФИНАЛЬНОЙ ВЕРСИИ
// ========================================

try {
    $protection = new RedisBotProtectionNoSessions(
        '127.0.0.1',    // Redis host
        6379,           // Redis port
        null,           // Redis password (если нужен)
        0               // Redis database
    );
    
    $protection->protect();
    
    // ====== ПРИМЕРЫ АДМИНИСТРИРОВАНИЯ ======
    
    // Получить общую статистику
    // $stats = $protection->getStats();
    // echo "Заблокировано IP: " . $stats['blocked_ips'] . "\n";
    // echo "Нарушений rate limit: " . $stats['rate_limit_violations'] . "\n";
    // echo "Активных отслеживаний: " . $stats['tracking_records'] . "\n";
    
    // Получить топ нарушителей rate limit
    // $violators = $protection->getTopRateLimitViolators(10);
    // foreach ($violators as $v) {
    //     echo "Нарушений: " . $v['violations'] . " | ";
    //     echo "Запросов/мин: " . $v['requests_1min'] . " | ";
    //     echo "Последний: " . $v['last_request'] . "\n";
    // }
    
    // Проверить статус конкретного IP
    // $ip = '1.2.3.4';
    // $rateLimitStats = $protection->getRateLimitStats($ip);
    // print_r($rateLimitStats);
    // 
    // $blockInfo = $protection->getBlockedIPInfo($ip);
    // print_r($blockInfo);
    
    // Разблокировать IP и сбросить все данные
    // $protection->unblockIP('1.2.3.4');
    // $protection->resetRateLimit('1.2.3.4');
    // $protection->unblockUserHash(); // текущий пользователь
    
    // Настроить лимиты под ваш сайт
    // $protection->updateRateLimitSettings([
    //     'max_requests_per_minute' => 120,  // Более мягкий лимит для крупных сайтов
    //     'max_requests_per_5min' => 400,
    //     'burst_threshold' => 30,            // Увеличить порог всплесков
    //     'ua_change_threshold' => 3          // Строже к смене UA
    // ]);
    
    // Настроить детекцию медленных ботов
    // $protection->updateSlowBotSettings([
    //     'min_requests_for_analysis' => 5,
    //     'long_session_hours' => 3
    // ]);
    
    // Диагностика текущего пользователя
    // $diagnosis = $protection->diagnoseUserHash();
    // echo "Hash: " . $diagnosis['stable_hash'] . "\n";
    // echo "IP: " . $diagnosis['ip'] . "\n";
    // echo "Устройство: " . $diagnosis['device_type'] . "\n";
    // echo "Браузер: " . $diagnosis['browser']['name'] . " " . $diagnosis['browser']['version'] . "\n";
    
    // Получить информацию о хеше пользователя
    // $hashInfo = $protection->getUserHashInfo();
    // print_r($hashInfo);
    
    // Ручная очистка Redis
    // $cleaned = $protection->cleanup(true);  // Полная очистка
    // echo "Очищено записей: $cleaned\n";
    // 
    // $deepCleaned = $protection->deepCleanup();  // Глубокая очистка
    // echo "Глубоко очищено: $deepCleaned\n";
    
    // ПРИМЕРЫ ТЕСТИРОВАНИЯ rDNS (раскомментируйте для тестов):
    // echo "\n=== ТЕСТИРОВАНИЕ ПОИСКОВИКОВ ===\n\n";
    // $protection->testRDNS('66.249.66.1', 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)');
    // echo "\n" . str_repeat("=", 50) . "\n\n";
    // $protection->testRDNS('40.77.167.181', 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)');
    // echo "\n" . str_repeat("=", 50) . "\n\n";
    // $protection->testRDNS('1.2.3.4', 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)');
    
} catch (Exception $e) {
    error_log("CRITICAL: Bot protection failed - " . $e->getMessage());
    // В случае ошибки Redis - продолжаем работу без защиты
}

/*
====================================================================
ЧТО ДЕЛАЕТ НОВАЯ ЗАЩИТА
====================================================================

1. RATE LIMITING - ограничивает количество запросов:
   ✓ 60 запросов в минуту (настраивается)
   ✓ 200 запросов за 5 минут
   ✓ 1000 запросов в час
   ✓ При превышении - прогрессивная блокировка

2. ДЕТЕКЦИЯ СМЕНЫ USER-AGENT:
   ✓ Блокирует IP, которые часто меняют UA
   ✓ Порог: 5 различных UA за 5 минут
   ✓ Помогает против ротации User-Agent

3. BURST DETECTION (всплески активности):
   ✓ Обнаруживает 20+ запросов за 10 секунд
   ✓ Немедленная блокировка при детекции
   ✓ Защита от flood-атак

4. ПРОГРЕССИВНАЯ БЛОКИРОВКА:
   ✓ 1-е нарушение: 30 минут блокировки
   ✓ 2-е нарушение: 1 час
   ✓ 3+ нарушения: 2+ часа (растет с каждым разом)
   ✓ История блокировок хранится 7 дней

5. ДЕТЕКЦИЯ МЕДЛЕННЫХ БОТОВ:
   ✓ Обнаруживает ботов с низкой активностью
   ✓ Анализирует паттерны долгосрочного поведения
   ✓ Регулярность запросов, разнообразие страниц

6. РАСШИРЕННОЕ ОТСЛЕЖИВАНИЕ:
   ✓ Автоматически включается для подозрительных
   ✓ Более строгий анализ поведения
   ✓ 24 часа детального мониторинга

7. ВЕРИФИКАЦИЯ ПОИСКОВИКОВ:
   ✓ Проверка Google, Bing, Yandex и других
   ✓ rDNS верификация (обратный + прямой DNS)
   ✓ Кеширование результатов проверки

====================================================================
РЕКОМЕНДАЦИИ ПО НАСТРОЙКЕ
====================================================================

ДЛЯ НЕБОЛЬШИХ САЙТОВ (< 1000 посетителей/день):
   - Оставьте настройки по умолчанию
   - max_requests_per_minute: 60
   - burst_threshold: 20

ДЛЯ СРЕДНИХ САЙТОВ (1000-10000 посетителей/день):
   $protection->updateRateLimitSettings([
       'max_requests_per_minute' => 90,
       'max_requests_per_5min' => 300,
       'burst_threshold' => 30
   ]);

ДЛЯ КРУПНЫХ САЙТОВ (> 10000 посетителей/день):
   $protection->updateRateLimitSettings([
       'max_requests_per_minute' => 120,
       'max_requests_per_5min' => 500,
       'max_requests_per_hour' => 2000,
       'burst_threshold' => 40
   ]);
   
   Регулярно проверяйте:
   - getTopRateLimitViolators() для мониторинга
   - getStats() для общей статистики

ДЛЯ API И ВЫСОКОНАГРУЖЕННЫХ ПРИЛОЖЕНИЙ:
   $protection->updateRateLimitSettings([
       'max_requests_per_minute' => 180,
       'max_requests_per_5min' => 800,
       'burst_threshold' => 50,
       'ua_change_threshold' => 10  // API могут менять UA
   ]);

СТРОГИЙ РЕЖИМ (максимальная защита):
   $protection->updateRateLimitSettings([
       'max_requests_per_minute' => 30,
       'max_requests_per_5min' => 100,
       'burst_threshold' => 10,
       'ua_change_threshold' => 3
   ]);

====================================================================
МОНИТОРИНГ И ОТЛАДКА
====================================================================

Регулярно проверяйте логи:
   tail -f /var/log/php_errors.log | grep "RATE LIMIT"
   tail -f /var/log/php_errors.log | grep "Bot blocked"

Проверка статистики (добавьте в cron каждый час):
   $stats = $protection->getStats();
   if ($stats['rate_limit_violations'] > 100) {
       // Отправить уведомление администратору
   }

Еженедельная очистка (добавьте в cron):
   $protection->deepCleanup();

====================================================================
TROUBLESHOOTING
====================================================================

Если блокируются легитимные пользователи:
1. Проверьте логи: grep "RATE LIMIT BLOCK" /var/log/php_errors.log
2. Увеличьте лимиты для вашего типа сайта
3. Разблокируйте конкретный IP: $protection->unblockIP('x.x.x.x')
4. Сбросьте счетчики: $protection->resetRateLimit('x.x.x.x')

Если пропускаются боты:
1. Уменьшите пороги в настройках
2. Проверьте логи на паттерны: $protection->getBlockedIPInfo('x.x.x.x')
3. Добавьте в список подозрительных UA в методе isSuspiciousUserAgent()

Если Redis падает или недоступен:
- Скрипт продолжит работу БЕЗ защиты
- Проверьте подключение к Redis
- Убедитесь что Redis запущен: redis-cli ping

====================================================================
БЕЗОПАСНОСТЬ
====================================================================

ВАЖНО: Измените секретный ключ!
   private $secretKey = 'your_secret_key_here_change_this12345!@#;
   
Используйте сложный уникальный ключ для вашего сайта.

ВАЖНО: Настройте Redis правильно!
   - Используйте пароль для Redis
   - Ограничьте доступ к Redis по IP
   - Используйте отдельную БД для bot protection

====================================================================
*/
?>
