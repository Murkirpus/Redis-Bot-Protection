<?php
/**
 * MurKir Security - Redis Bot Protection v3.8.13-optimized
 * PoW JS Challenge + Rate Limit + IP Whitelist + Custom UA Logging
 */

// ======================== КОНФІГУРАЦІЯ ========================

// ВЛАСНІ USER AGENTS (пропускаються без JS Challenge)
$CUSTOM_USER_AGENTS = array('botprotection', 'murkir-cleanup');

// БІЛИЙ СПИСОК АДМІНСЬКИХ IP
$ADMIN_IP_WHITELIST = array(
    '::1', '127.0.0.1',
    '185.109.48.79',
    '2a03:3f40:2:e:0:4:0:2',
    '2a03:3f40:2:e:0:4:0:3',
);

// БІЛИЙ СПИСОК URL АДМІНКИ
$ADMIN_URL_WHITELIST_ENABLED = true;
$ADMIN_URL_WHITELIST = array(
    '/js_challenge_lite', '/redis-bot_protection/api',
    '/engine/classes', '/engine/modules/antibot',
    '/admin', '/engine/ajax', '/engine/admin', '/engine/inc/',
);

// НАЛАШТУВАННЯ RATE LIMIT ДЛЯ AJAX
$AJAX_SKIP_RATE_LIMIT = false;
$AJAX_RATE_LIMIT_MULTIPLIER = 3.0;

// БІЛИЙ СПИСОК IP ПОШУКОВИХ СИСТЕМ (консолідовані CIDR)
$SEARCH_ENGINE_IP_RANGES = array(
    // GOOGLE IPv4 (консолідовані /27 -> /24 та ширші)
    '74.125.0.0/16', '172.217.0.0/16', '142.250.0.0/15',
    '66.102.0.0/20', '66.249.64.0/19',
    // Google Special Crawlers
    '192.178.4.0/24', '192.178.5.0/27',
    '192.178.6.0/24', '192.178.7.0/24',
    // Google Cloud ranges
    '34.100.182.96/28', '34.101.50.144/28', '34.118.254.0/28', '34.118.66.0/28',
    '34.126.178.96/28', '34.146.150.144/28', '34.147.110.144/28', '34.151.74.144/28',
    '34.152.50.64/28', '34.154.114.144/28', '34.155.98.32/28', '34.165.18.176/28',
    '34.175.160.64/28', '34.176.130.16/28', '34.22.85.0/27', '34.64.82.64/28',
    '34.65.242.112/28', '34.80.50.80/28', '34.88.194.0/28', '34.89.10.80/28',
    '34.89.198.80/28', '34.96.162.48/28', '35.247.243.240/28',
    // GOOGLEBOT IPv6 (консолідовані /64 -> /32)
    '2001:4860:4801::/32',
    // YANDEX IPv4
    '5.45.192.0/18', '5.255.192.0/18', '37.9.64.0/18', '37.140.128.0/18',
    '77.88.0.0/18', '84.201.128.0/18', '87.250.224.0/19', '90.156.176.0/22',
    '93.158.128.0/18', '95.108.128.0/17', '100.43.64.0/19', '130.193.32.0/19',
    '141.8.128.0/18', '178.154.128.0/17', '185.32.187.0/24', '199.21.96.0/22',
    '199.36.240.0/22', '213.180.192.0/19',
    // YANDEX IPv6
    '2a02:6b8::/32',
    // BINGBOT IPv4
    '157.55.39.0/24', '207.46.13.0/24', '40.77.167.0/24',
    '13.66.139.0/24', '13.66.144.0/24', '52.167.144.0/24',
    '13.67.10.16/28', '13.69.66.240/28', '13.71.172.224/28',
    '139.217.52.0/28', '191.233.204.224/28', '20.36.108.32/28',
    '20.43.120.16/28', '40.79.131.208/28', '40.79.186.176/28',
    '52.231.148.0/28', '20.79.107.240/28', '51.105.67.0/28',
    '20.125.163.80/28', '40.77.188.0/22', '65.55.210.0/24',
    '199.30.24.0/23', '40.77.202.0/24', '40.77.139.0/25',
    '20.74.197.0/28', '20.15.133.160/27', '40.77.177.0/24', '40.77.178.0/23',
    // BING IPv6
    '2620:1ec:c::0/40', '2620:1ec:8f8::/46', '2a01:111::/32',
    // BAIDU
    '116.179.0.0/16', '119.63.192.0/21', '123.125.71.0/24',
    '180.76.0.0/16', '220.181.0.0/16',
    // DUCKDUCKGO
    '20.191.45.212/32', '40.88.21.235/32', '52.142.24.149/32',
    '52.142.26.175/32', '72.94.249.34/32', '72.94.249.35/32',
    // YAHOO
    '67.195.0.0/16', '72.30.0.0/16', '74.6.0.0/16', '98.136.0.0/14',
    // FACEBOOK IPv4+IPv6
    '31.13.24.0/21', '31.13.64.0/18', '66.220.144.0/20', '69.63.176.0/20',
    '69.171.224.0/19', '157.240.0.0/16', '173.252.64.0/18', '185.60.216.0/22',
    '2a03:2880::/32',
    // APPLE IPv4+IPv6
    '17.0.0.0/8', '2620:149::/32', '2a01:b740::/32',
    // PETALBOT (HUAWEI)
    '114.119.128.0/17',
);

// JS CHALLENGE КОНФІГУРАЦІЯ
$_JSC_CONFIG = array(
    'enabled' => true,
    'secret_key' => 'CHANGE_THIS_SECRET_KEY_123!',
    'cookie_name' => 'mk_verified',
    'token_lifetime' => 129600,
    'pow_enabled' => true,
    'pow_difficulty' => 3,
    'pow_timeout' => 60,
    'pow_style' => 'cloudflare',
    'mode' => 'auto',
);

$_JSC_AUTO_CONFIG = array(
    'no_cookie_threshold' => 9999, 'no_cookie_window' => 30,
    'burst_threshold' => 2, 'burst_window' => 2,
    'rate_threshold' => 30, 'rate_window' => 60,
    'check_empty_ua' => true, 'check_suspicious_ua' => true,
    'check_no_referer' => false, 'check_no_accept_language' => true,
    'suspicion_threshold' => 3,
    'grace_requests' => 2, 'grace_requests_no_cookie' => 2,
    'log_triggers' => true,
);

$_HAMMER_PROTECTION = array(
    'enabled' => true,
    'challenge_threshold' => 3, 'challenge_window' => 60,
    'blocked_threshold' => 5, 'blocked_window' => 30,
    'api_block_enabled' => true,
    'log_enabled' => true, 'redis_stats' => true,
);

$_API_CONFIG = array(
    'enabled' => true,
    'url' => 'https://blog.dj-x.info/redis-bot_protection/API/iptables.php',
    'api_key' => 'Asd12345',
    'method' => 'POST',
    'timeout' => 5,
    'retry_on_failure' => 2,
    'verify_ssl' => true,
    'user_agent' => 'BotProtection/3.8.13',
    'block_on_api' => true,
    'block_on_redis' => true,
);

// ======================== УТИЛІТИ ========================

/** Єдина функція отримання IP клієнта */
function _jsc_getClientIP() {
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        $ip = $_SERVER['HTTP_CF_CONNECTING_IP'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        $ip = trim($ips[0]);
    } elseif (!empty($_SERVER['HTTP_X_REAL_IP'])) {
        $ip = $_SERVER['HTTP_X_REAL_IP'];
    } else {
        $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '0.0.0.0';
    }
    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '0.0.0.0';
}

/** Отримання поточного домену для ізоляції Redis ключів між сайтами */
function _get_site_id() {
    static $siteId = null;
    if ($siteId === null) {
        $host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : 'default';
        // Видаляємо порт і нормалізуємо
        $host = preg_replace('/:\d+$/', '', strtolower(trim($host)));
        // Короткий хеш для компактності ключів
        $siteId = substr(md5($host), 0, 8);
    }
    return $siteId;
}

/** Shared Redis підключення для standalone функцій */
function _get_shared_redis() {
    static $redis = null;
    static $connected = false;
    if ($redis === null) {
        try {
            $redis = new Redis();
            $connected = $redis->connect('127.0.0.1', 6379, 0.5);
            if ($connected) {
                $redis->select(1);
                $redis->setOption(Redis::OPT_SERIALIZER, Redis::SERIALIZER_PHP);
            }
        } catch (Exception $e) {
            $connected = false;
        }
    }
    return $connected ? $redis : null;
}

/** Єдина перевірка IPv6 в CIDR */
function _ipv6_in_cidr($ip, $subnet, $bits) {
    if ($bits < 0 || $bits > 128) return false;
    $ip_bin = @inet_pton($ip);
    $subnet_bin = @inet_pton($subnet);
    if ($ip_bin === false || $subnet_bin === false) return false;
    if ($bits === 0) return true;
    $full_bytes = (int)floor($bits / 8);
    $remaining_bits = $bits % 8;
    for ($i = 0; $i < $full_bytes; $i++) {
        if ($ip_bin[$i] !== $subnet_bin[$i]) return false;
    }
    if ($remaining_bits > 0 && $full_bytes < 16) {
        $mask = 0xFF << (8 - $remaining_bits);
        if ((ord($ip_bin[$full_bytes]) & $mask) !== (ord($subnet_bin[$full_bytes]) & $mask)) return false;
    }
    return true;
}

/** Єдина перевірка IP в CIDR (IPv4 + IPv6) */
function _ip_in_cidr($ip, $cidr) {
    if (strpos($cidr, '/') === false) return $ip === $cidr;
    list($subnet, $bits) = explode('/', $cidr, 2);
    $bits = (int)$bits;
    $ipIsV6 = (strpos($ip, ':') !== false);
    $cidrIsV6 = (strpos($subnet, ':') !== false);
    if ($ipIsV6 !== $cidrIsV6) return false;
    if ($ipIsV6) return _ipv6_in_cidr($ip, $subnet, $bits);
    if ($bits < 0 || $bits > 32) return false;
    $ip_long = ip2long($ip);
    $subnet_long = ip2long($subnet);
    if ($ip_long === false || $subnet_long === false) return false;
    if ($bits === 0) return true;
    $mask = -1 << (32 - $bits);
    return ($ip_long & $mask) === ($subnet_long & $mask);
}

/** Визначення пошукової системи по CIDR (lookup таблиця) */
function _detect_engine_by_cidr($cidr) {
    static $prefixMap = null;
    if ($prefixMap === null) {
        $prefixMap = array(
            // IPv6
            '2001:4860' => 'Google', '2a02:6b8' => 'Yandex',
            '2620:1ec' => 'Bing', '2a01:111' => 'Bing',
            '2a03:2880' => 'Facebook', '2620:149' => 'Apple', '2a01:b740' => 'Apple',
            // IPv4 prefixes
            '66.249' => 'Google', '66.102' => 'Google', '74.125' => 'Google',
            '142.250' => 'Google', '172.217' => 'Google', '192.178' => 'Google',
            '34.' => 'Google', '35.247' => 'Google',
            '5.45' => 'Yandex', '5.255' => 'Yandex', '37.9' => 'Yandex',
            '37.140' => 'Yandex', '77.88' => 'Yandex', '84.201' => 'Yandex',
            '87.250' => 'Yandex', '90.156' => 'Yandex', '93.158' => 'Yandex',
            '95.108' => 'Yandex', '100.43' => 'Yandex', '130.193' => 'Yandex',
            '141.8' => 'Yandex', '178.154' => 'Yandex', '185.32.187' => 'Yandex',
            '199.21' => 'Yandex', '199.36' => 'Yandex', '213.180' => 'Yandex',
            '13.' => 'Bing', '20.' => 'Bing', '40.' => 'Bing', '51.105' => 'Bing',
            '52.' => 'Bing', '65.55' => 'Bing', '139.217' => 'Bing',
            '157.55' => 'Bing', '191.233' => 'Bing', '199.30' => 'Bing', '207.46' => 'Bing',
            '116.179' => 'Baidu', '119.63' => 'Baidu', '123.125' => 'Baidu',
            '180.76' => 'Baidu', '220.181' => 'Baidu',
            '31.13' => 'Facebook', '66.220' => 'Facebook', '69.63' => 'Facebook',
            '69.171' => 'Facebook', '157.240' => 'Facebook', '173.252' => 'Facebook', '185.60' => 'Facebook',
            '17.' => 'Apple',
            '20.191' => 'DuckDuckGo', '40.88' => 'DuckDuckGo', '52.142' => 'DuckDuckGo', '72.94' => 'DuckDuckGo',
            '67.195' => 'Yahoo', '72.30' => 'Yahoo', '74.6' => 'Yahoo', '98.13' => 'Yahoo',
            '114.119' => 'PetalBot',
        );
    }
    // Перевіряємо від найдовшого до найкоротшого префіксу
    foreach ($prefixMap as $prefix => $engine) {
        if (strpos($cidr, $prefix) === 0) return $engine;
    }
    return 'Other';
}

// ======================== WHITELIST ПЕРЕВІРКИ ========================

/** Логування візиту пошукового бота в Redis */
function _log_search_engine_visit($redis, $ip, $method, $engine = null) {
    if (!$redis) return;
    try {
        if (!$engine) {
            $ua = isset($_SERVER['HTTP_USER_AGENT']) ? strtolower($_SERVER['HTTP_USER_AGENT']) : '';
            $botMap = array(
                'googlebot' => 'Google', 'google-inspectiontool' => 'Google',
                'yandex' => 'Yandex', 'bingbot' => 'Bing', 'msnbot' => 'Bing',
                'baiduspider' => 'Baidu', 'duckduckbot' => 'DuckDuckGo',
                'facebookexternalhit' => 'Facebook', 'facebot' => 'Facebook',
                'applebot' => 'Apple', 'petalbot' => 'PetalBot',
            );
            $engine = 'Other';
            foreach ($botMap as $pattern => $name) {
                if (strpos($ua, $pattern) !== false) { $engine = $name; break; }
            }
        }
        $today = date('Y-m-d');
        $host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : 'unknown';
        $url = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '/';
        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '-';
        if (strlen($ua) > 100) $ua = substr($ua, 0, 100) . '...';
        $prefix = 'bot_protection:';
        $engineLower = strtolower($engine);
        $redis->incr($prefix . 'search_stats:total:' . $engineLower);
        $todayKey = $prefix . 'search_stats:today:' . $today . ':' . $engineLower;
        $redis->incr($todayKey);
        $redis->expire($todayKey, 86400 * 7);
        $hostKey = $prefix . 'search_stats:hosts:' . $host;
        $redis->incr($hostKey);
        $redis->expire($hostKey, 86400 * 30);
        $redis->incr($prefix . 'search_stats:methods:' . strtolower($method));
        $logKey = $prefix . 'search_log';
        $redis->lpush($logKey, array(
            'time' => date('Y-m-d H:i:s'), 'engine' => $engine,
            'ip' => $ip, 'method' => $method, 'host' => $host, 'url' => $url, 'ua' => $ua,
        ));
        $redis->ltrim($logKey, 0, 499);
    } catch (Exception $e) {}
}

/** Перевірка IP адмінського whitelist */
function _is_admin_ip($ip) {
    global $ADMIN_IP_WHITELIST;
    if (empty($ADMIN_IP_WHITELIST) || empty($ip)) return false;
    foreach ($ADMIN_IP_WHITELIST as $cidr) {
        if (empty($cidr)) continue;
        if (strpos($cidr, '/') === false) {
            $cidr .= (strpos($cidr, ':') !== false ? '/128' : '/32');
        }
        if (_ip_in_cidr($ip, $cidr)) {
            error_log("ADMIN IP WHITELIST: Allowing IP $ip (matched $cidr)");
            return true;
        }
    }
    return false;
}

/** Перевірка IP пошукових систем */
function _is_search_engine_ip($ip) {
    global $SEARCH_ENGINE_IP_RANGES;
    static $logged = array();
    $redis = _get_shared_redis();
    
    if ($redis) {
        $cacheKey = 'bot_protection:ip_whitelist:' . $ip;
        try {
            $cached = $redis->get($cacheKey);
            if ($cached !== false) {
                if ($cached === '1' || $cached === 1 || $cached === true) {
                    if (!isset($logged[$ip])) {
                        $logged[$ip] = true;
                        _log_search_engine_visit($redis, $ip, 'IP-cached');
                    }
                    return true;
                }
                return false;
            }
        } catch (Exception $e) {}
    }
    
    $result = false;
    $matchedEngine = 'unknown';
    $isIPv6 = (strpos($ip, ':') !== false);
    foreach ($SEARCH_ENGINE_IP_RANGES as $cidr) {
        if ($isIPv6 !== (strpos($cidr, ':') !== false)) continue;
        if (_ip_in_cidr($ip, $cidr)) {
            $result = true;
            $matchedEngine = _detect_engine_by_cidr($cidr);
            break;
        }
    }
    
    if ($redis) {
        try { $redis->setex($cacheKey, 86400, $result ? '1' : '0'); } catch (Exception $e) {}
    }
    if ($result) {
        error_log("SEARCH ENGINE IP WHITELIST: Allowing IP=$ip (engine=$matchedEngine)");
        if ($redis && !isset($logged[$ip])) {
            $logged[$ip] = true;
            _log_search_engine_visit($redis, $ip, 'IP', $matchedEngine);
        }
    }
    return $result;
}

/** Універсальна перевірка IP по ВСІХ білих списках */
function _is_whitelisted_ip($ip) {
    if (empty($ip)) return false;
    if (_is_admin_ip($ip)) return 'admin';
    if (_is_search_engine_ip($ip)) return 'search_engine';
    return false;
}

/** Перевірка чи URL належить до адмінки */
function _is_admin_url() {
    global $ADMIN_URL_WHITELIST_ENABLED, $ADMIN_URL_WHITELIST;
    if (empty($ADMIN_URL_WHITELIST_ENABLED) || empty($ADMIN_URL_WHITELIST)) return false;
    $uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
    if (empty($uri)) return false;
    $path = parse_url($uri, PHP_URL_PATH);
    if ($path === null || $path === false || $path === '') $path = $uri;
    $uriLower = strtolower((string)$uri);
    $pathLower = strtolower((string)$path);
    foreach ($ADMIN_URL_WHITELIST as $adminPath) {
        if (empty($adminPath)) continue;
        $ap = strtolower($adminPath);
        if (strpos($pathLower, $ap) !== false || strpos($uriLower, $ap) !== false) return true;
    }
    return false;
}

/** Перевірка чи запит є AJAX */
function _is_ajax_request() {
    if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') return true;
    if (!empty($_SERVER['CONTENT_TYPE']) && strpos(strtolower($_SERVER['CONTENT_TYPE']), 'application/json') !== false) return true;
    if (!empty($_SERVER['HTTP_ACCEPT']) && strpos(strtolower($_SERVER['HTTP_ACCEPT']), 'application/json') === 0) return true;
    if (!empty($_SERVER['HTTP_X_JSC_RESPONSE'])) return true;
    return false;
}

/** Пропускати Rate Limit? */
function _should_skip_rate_limit($ip) {
    global $AJAX_SKIP_RATE_LIMIT;
    $wl = _is_whitelisted_ip($ip);
    if ($wl !== false) return 'ip_whitelist:' . $wl;
    if (_is_admin_url()) return 'admin_url';
    if (!empty($AJAX_SKIP_RATE_LIMIT) && _is_ajax_request()) return 'ajax_request';
    return false;
}

/** Множник Rate Limit для AJAX */
function _get_rate_limit_multiplier() {
    global $AJAX_RATE_LIMIT_MULTIPLIER;
    if (_is_ajax_request() && !empty($AJAX_RATE_LIMIT_MULTIPLIER) && $AJAX_RATE_LIMIT_MULTIPLIER > 1.0) {
        return (float)$AJAX_RATE_LIMIT_MULTIPLIER;
    }
    return 1.0;
}

// ======================== USER AGENT ПЕРЕВІРКИ ========================

/** Перевірка власних User Agents */
function _is_custom_ua($userAgent) {
    global $CUSTOM_USER_AGENTS;
    static $logged = array();
    if (empty($CUSTOM_USER_AGENTS) || empty($userAgent)) return false;
    $uaLower = strtolower($userAgent);
    foreach ($CUSTOM_USER_AGENTS as $customUA) {
        if (empty($customUA)) continue;
        if (stripos($uaLower, strtolower($customUA)) !== false) {
            error_log("CUSTOM UA WHITELIST: Allowing - contains: $customUA | Full UA: " . substr($userAgent, 0, 100));
            $ip = _jsc_getClientIP();
            $redis = _get_shared_redis();
            if ($redis && !isset($logged[$ip . ':' . $customUA])) {
                $logged[$ip . ':' . $customUA] = true;
                _log_search_engine_visit($redis, $ip, 'CustomUA', 'CustomUA:' . $customUA);
            }
            return true;
        }
    }
    return false;
}

/** Швидка перевірка SEO ботів */
function _is_seo_bot($userAgent) {
    if (empty($userAgent)) return false;
    $uaLower = strtolower($userAgent);
    $seoBots = array('googlebot','yandex','bingbot','duckduckbot','facebookexternalhit','twitterbot','pinterest','linkedinbot','whatsapp','telegram','viber','petalbot');
    foreach ($seoBots as $bot) {
        if (strpos($uaLower, $bot) !== false) return true;
    }
    return false;
}

// ======================== HAMMER PROTECTION ========================

/** Відстеження та блокування ботів що долбять сторінки */
function _track_page_hammer($ip, $pageType = 'challenge') {
    global $_HAMMER_PROTECTION;
    if (empty($_HAMMER_PROTECTION['enabled'])) return false;
    
    if ($pageType === 'blocked') {
        $threshold = $_HAMMER_PROTECTION['blocked_threshold'];
        $window = $_HAMMER_PROTECTION['blocked_window'];
        $keyPrefix = 'hammer:blocked:';
        $blockReason = '502_page_hammer';
    } else {
        $threshold = $_HAMMER_PROTECTION['challenge_threshold'];
        $window = $_HAMMER_PROTECTION['challenge_window'];
        $keyPrefix = 'hammer:challenge:';
        $blockReason = 'challenge_page_hammer';
    }
    
    $redis = _get_shared_redis();
    if (!$redis) return false;
    $prefix = 'bot_protection:' . _get_site_id() . ':';
    $key = $prefix . $keyPrefix . $ip;
    $now = time();
    
    try {
        $attempts = $redis->get($key);
        if (!$attempts || !is_array($attempts)) $attempts = array();
        $filtered = array();
        foreach ($attempts as $ts) {
            if (($now - $ts) < $window) $filtered[] = $ts;
        }
        $filtered[] = $now;
        $attemptCount = count($filtered);
        $redis->setex($key, $window * 2, $filtered);
        
        if (!empty($_HAMMER_PROTECTION['redis_stats'])) {
            $statsKey = $prefix . 'hammer_stats:' . $pageType . ':' . date('Y-m-d');
            $redis->incr($statsKey);
            $redis->expire($statsKey, 86400 * 7);
        }
        
        if ($attemptCount >= $threshold) {
            if (!empty($_HAMMER_PROTECTION['log_enabled'])) {
                $ua = isset($_SERVER['HTTP_USER_AGENT']) ? substr($_SERVER['HTTP_USER_AGENT'], 0, 100) : '-';
                error_log(sprintf("HAMMER ATTACK: IP=%s, page=%s, hits=%d/%d in %dsec, UA=%s", $ip, $pageType, $attemptCount, $threshold, $window, $ua));
            }
            $redis->setex($prefix . 'blocked:hammer:' . $ip, 3600, array(
                'ip' => $ip, 'time' => $now, 'reason' => $blockReason,
                'page_type' => $pageType, 'attempts' => $attemptCount,
                'ua' => isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '-',
            ));
            if (!empty($_HAMMER_PROTECTION['redis_stats'])) {
                $bsk = $prefix . 'hammer_blocks:' . $pageType . ':' . date('Y-m-d');
                $redis->incr($bsk);
                $redis->expire($bsk, 86400 * 7);
            }
            if (!empty($_HAMMER_PROTECTION['api_block_enabled'])) {
                $apiResult = _hammer_call_api($ip, $blockReason);
                if ($apiResult && isset($apiResult['status'])) {
                    if ($apiResult['status'] === 'success') {
                        error_log("HAMMER API BLOCK SUCCESS: IP=$ip (reason=$blockReason)");
                    } elseif ($apiResult['status'] !== 'already_blocked') {
                        error_log("HAMMER API BLOCK FAILED: IP=$ip, reason=" . (isset($apiResult['message']) ? $apiResult['message'] : 'unknown'));
                    }
                }
            }
            return true;
        }
    } catch (Exception $e) {
        error_log("HAMMER PROTECTION ERROR: " . $e->getMessage());
    }
    return false;
}

/** Виклик API для блокування IP (hammer) */
function _hammer_call_api($ip, $reason = 'hammer_attack') {
    global $_API_CONFIG;
    if (empty($_API_CONFIG['enabled']) || empty($_API_CONFIG['block_on_api'])) {
        return array('status' => 'skipped');
    }
    return _call_block_api($_API_CONFIG, $ip, $reason, $_API_CONFIG['user_agent'] . '-Hammer');
}

/** Універсальний виклик API блокування */
function _call_block_api($config, $ip, $reason, $ua = null) {
    $method = isset($config['method']) ? strtoupper($config['method']) : 'POST';
    $params = array('action' => 'block', 'ip' => $ip, 'api' => 1, 'api_key' => $config['api_key'], 'reason' => $reason);
    try {
        $ch = curl_init();
        if (!$ch) return array('status' => 'error', 'message' => 'cURL init failed');
        $opts = array(
            CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => $config['timeout'],
            CURLOPT_CONNECTTIMEOUT => 3, CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_SSL_VERIFYPEER => $config['verify_ssl'],
            CURLOPT_SSL_VERIFYHOST => $config['verify_ssl'] ? 2 : 0,
            CURLOPT_USERAGENT => $ua ?: $config['user_agent'],
            CURLOPT_HTTPHEADER => array('Accept: application/json', 'Cache-Control: no-cache'),
        );
        if ($method === 'POST') {
            $opts[CURLOPT_URL] = $config['url'];
            $opts[CURLOPT_POST] = true;
            $opts[CURLOPT_POSTFIELDS] = http_build_query($params);
        } else {
            $opts[CURLOPT_URL] = $config['url'] . '?' . http_build_query($params);
        }
        curl_setopt_array($ch, $opts);
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err = curl_error($ch);
        curl_close($ch);
        if (!empty($err)) return array('status' => 'error', 'message' => $err);
        if ($httpCode !== 200) return array('status' => 'error', 'message' => 'HTTP ' . $httpCode);
        $result = json_decode($response, true);
        return (json_last_error() === JSON_ERROR_NONE) ? $result : array('status' => 'error', 'message' => 'Invalid JSON');
    } catch (Exception $e) {
        return array('status' => 'error', 'message' => $e->getMessage());
    }
}

/** Перевірка чи IP заблокований за hammer */
function _is_hammer_blocked($ip) {
    $redis = _get_shared_redis();
    if (!$redis) return false;
    try { return $redis->exists('bot_protection:' . _get_site_id() . ':blocked:hammer:' . $ip); }
    catch (Exception $e) { return false; }
}

// ======================== JS CHALLENGE ========================

/** Перевірка аномальної активності (auto mode) */
function _jsc_check_anomaly($ip, $userAgent) {
    global $_JSC_AUTO_CONFIG;
    $redis = _get_shared_redis();
    if (!$redis) return array('reason' => 'redis_unavailable', 'score' => 99);
    
    $siteId = _get_site_id();
    $prefix = 'bot_protection:' . $siteId . ':';
    $now = time();
    $suspicionScore = 0;
    $triggers = array();
    
    // Незавершений Challenge (per-site)
    $pendingKey = $prefix . 'jsc_auto:pending:' . $ip;
    try {
        if ($redis->exists($pendingKey)) {
            if (!isset($_COOKIE['bot_protection_uid']) || empty($_COOKIE['bot_protection_uid'])) {
                if (!empty($_JSC_AUTO_CONFIG['log_triggers'])) {
                    error_log("JSC AUTO: IP=$ip has pending challenge, showing again");
                }
                return array('reason' => 'pending_challenge', 'score' => 99, 'triggers' => array('pending_challenge'));
            }
            $redis->del($pendingKey);
        }
    } catch (Exception $e) {}
    
    // Порожній UA
    if ($_JSC_AUTO_CONFIG['check_empty_ua'] && empty($userAgent)) {
        $suspicionScore += 2;
        $triggers[] = 'empty_ua';
    }
    // Підозрілий UA
    if ($_JSC_AUTO_CONFIG['check_suspicious_ua'] && !empty($userAgent)) {
        $uaLower = strtolower($userAgent);
        foreach (array('curl','wget','python','java/','libwww','httpclient','axios','node-fetch','go-http','scrapy') as $p) {
            if (strpos($uaLower, $p) !== false) {
                $suspicionScore += 1;
                $triggers[] = 'suspicious_ua:' . $p;
                break;
            }
        }
    }
    // Без Accept-Language
    if ($_JSC_AUTO_CONFIG['check_no_accept_language'] && empty($_SERVER['HTTP_ACCEPT_LANGUAGE'])) {
        $suspicionScore += 1;
        $triggers[] = 'no_accept_language';
    }
    // Без Referer
    if ($_JSC_AUTO_CONFIG['check_no_referer']) {
        $uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '/';
        if ($uri !== '/' && empty($_SERVER['HTTP_REFERER'])) {
            $suspicionScore += 1;
            $triggers[] = 'no_referer';
        }
    }
    
    // Rate check
    $hasCookieRate = isset($_COOKIE['bot_protection_uid']) && !empty($_COOKIE['bot_protection_uid']);
    $userIdentifier = $hasCookieRate ? 'uid:' . hash('md5', $_COOKIE['bot_protection_uid']) : 'ip:' . $ip;
    $requestKey = $prefix . 'jsc_auto:requests:' . $userIdentifier;
    
    try {
        $requests = $redis->get($requestKey);
        if (!$requests || !is_array($requests)) $requests = array();
        $requests[] = $now;
        $requests = array_values(array_filter($requests, function($t) use ($now) { return ($now - $t) < 60; }));
        $redis->setex($requestKey, 120, $requests);
        $totalRequests = count($requests);
        
        $graceLimit = $hasCookieRate ? $_JSC_AUTO_CONFIG['grace_requests'] : $_JSC_AUTO_CONFIG['grace_requests_no_cookie'];
        if ($totalRequests <= $graceLimit) return false;
        
        // Burst
        $burstCount = 0;
        foreach ($requests as $t) {
            if (($now - $t) < $_JSC_AUTO_CONFIG['burst_window']) $burstCount++;
        }
        if ($burstCount >= $_JSC_AUTO_CONFIG['burst_threshold']) {
            $suspicionScore += 3;
            $triggers[] = "burst:$burstCount/{$_JSC_AUTO_CONFIG['burst_window']}s";
        }
        // Rate
        if ($totalRequests >= $_JSC_AUTO_CONFIG['rate_threshold']) {
            $suspicionScore += 2;
            $triggers[] = "rate:$totalRequests/60s";
        }
    } catch (Exception $e) {}
    
    // No cookie check
    $hasCookie = isset($_COOKIE['bot_protection_uid']) && !empty($_COOKIE['bot_protection_uid']);
    if (!$hasCookie) {
        $noCookieKey = $prefix . 'jsc_auto:no_cookie:' . $ip;
        try {
            $ncr = $redis->get($noCookieKey);
            if (!$ncr || !is_array($ncr)) $ncr = array();
            $w = $_JSC_AUTO_CONFIG['no_cookie_window'];
            $ncr = array_values(array_filter($ncr, function($t) use ($now, $w) { return ($now - $t) < $w; }));
            $ncr[] = $now;
            $redis->setex($noCookieKey, $w * 2, $ncr);
            if (count($ncr) >= $_JSC_AUTO_CONFIG['no_cookie_threshold']) {
                $suspicionScore += 2;
                $triggers[] = "no_cookie:" . count($ncr) . "/{$w}s";
            }
        } catch (Exception $e) {}
    }
    
    if ($suspicionScore >= $_JSC_AUTO_CONFIG['suspicion_threshold']) {
        if (!empty($_JSC_AUTO_CONFIG['log_triggers'])) {
            error_log(sprintf("JSC AUTO TRIGGERED: IP=%s, score=%d, triggers=[%s], UA=%s",
                $ip, $suspicionScore, implode(', ', $triggers), substr($userAgent, 0, 80)));
        }
        return array('reason' => 'anomaly_detected', 'score' => $suspicionScore, 'triggers' => $triggers);
    }
    return false;
}

function _jsc_isVerified($secret_key, $cookie_name) {
    if (!isset($_COOKIE[$cookie_name])) return false;
    $cookie = $_COOKIE[$cookie_name];
    if (!preg_match('/^[a-f0-9]{64}$/', $cookie)) {
        _jsc_logStats('failed', _jsc_getClientIP());
        return false;
    }
    $ip = _jsc_getClientIP();
    foreach (array(date('Y-m-d'), date('Y-m-d', strtotime('-1 day')), date('Y-m-d', strtotime('-2 days'))) as $day) {
        if (hash_equals(hash('sha256', $ip . $day . $secret_key), $cookie)) return true;
    }
    _jsc_logStats('expired', $ip);
    return false;
}

function _jsc_logStats($type, $ip = null) {
    static $logged = array();
    if (isset($logged[$type])) return;
    $logged[$type] = true;
    if ($ip === null) $ip = _jsc_getClientIP();
    $redis = _get_shared_redis();
    if (!$redis) return;
    try {
        $prefix = 'bot_protection:' . _get_site_id() . ':jsc_stats:';
        $today = date('Y-m-d');
        $hour = date('Y-m-d:H');
        $redis->incr($prefix . 'total:' . $type);
        $dk = $prefix . 'daily:' . $today . ':' . $type;
        $redis->incr($dk); $redis->expire($dk, 86400 * 7);
        $hk = $prefix . 'hourly:' . $hour . ':' . $type;
        $redis->incr($hk); $redis->expire($hk, 86400 * 2);
        $logKey = $prefix . 'log:' . $type;
        $redis->lPush($logKey, array('date' => date('Y-m-d H:i:s'), 'ip' => $ip, 'ua' => isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '-'));
        $redis->lTrim($logKey, 0, 99);
    } catch (Exception $e) {}
}

function _jsc_generateChallenge($secret_key) {
    global $_JSC_CONFIG;
    $id = bin2hex(random_bytes(16));
    $timestamp = time();
    $numbers = array();
    for ($i = 0; $i < 5; $i++) $numbers[] = mt_rand(10, 99);
    $answer = array_sum($numbers);
    $sumTarget = hash('sha256', $id . $timestamp . $answer . $secret_key);
    
    if (!empty($_JSC_CONFIG['pow_enabled'])) {
        $difficulty = isset($_JSC_CONFIG['pow_difficulty']) ? (int)$_JSC_CONFIG['pow_difficulty'] : 4;
        return array(
            'type' => 'pow', 'id' => $id, 'timestamp' => $timestamp,
            'difficulty' => $difficulty, 'timeout' => isset($_JSC_CONFIG['pow_timeout']) ? (int)$_JSC_CONFIG['pow_timeout'] : 60,
            'style' => isset($_JSC_CONFIG['pow_style']) ? $_JSC_CONFIG['pow_style'] : 'cloudflare',
            'target' => str_repeat('0', $difficulty),
            'fallback' => array('numbers' => $numbers, 'target' => $sumTarget),
        );
    }
    return array('type' => 'sum', 'id' => $id, 'timestamp' => $timestamp, 'numbers' => $numbers, 'target' => $sumTarget, 'difficulty' => 3);
}

/** Спільний JS для обох стилів challenge */
function _jsc_getSharedJS() {
    return '
    var challengeComplete = false, challengeStarted = false;
    function updateProgress(p,m){document.getElementById("progress").style.width=p+"%";document.getElementById("status").textContent=m;}
    function showError(msg){
        var e=document.getElementById("error"),s=document.getElementById("spinner"),st=document.getElementById("status"),ss=document.getElementById("stats");
        if(msg&&msg.toLowerCase().indexOf("expired")!==-1){e.innerHTML="<strong>⏰ Время проверки истекло</strong><br>Обновление через 3 сек...";e.style.display="block";s.style.display="none";st.textContent="Обновление...";ss.textContent="";setTimeout(function(){location.reload()},3e3);return;}
        e.innerHTML="<strong>⚠️ Ошибка</strong>"+msg;e.style.display="block";s.style.display="none";st.textContent="Проверка не пройдена";ss.textContent="";
    }
    async function sha256(str){var b=new TextEncoder().encode(str),h=await crypto.subtle.digest("SHA-256",b);return Array.from(new Uint8Array(h)).map(function(v){return v.toString(16).padStart(2,"0")}).join("");}
    function areCookiesEnabled(){try{document.cookie="ct=1;SameSite=Lax";var r=document.cookie.indexOf("ct=")!==-1;document.cookie="ct=1;expires=Thu,01 Jan 1970 00:00:00 GMT;SameSite=Lax";return r}catch(e){return false}}
    function checkLoopProtection(){try{var k="pow_"+challengeData.id.substr(0,8),a=parseInt(sessionStorage.getItem(k)||"0",10);if(a>=5)return false;sessionStorage.setItem(k,(a+1).toString());return true}catch(e){return true}}
    function isCryptoSupported(){try{return !!(window.crypto&&window.crypto.subtle&&window.crypto.subtle.digest)}catch(e){return false}}
    function sendResult(data){
        var x=new XMLHttpRequest();x.open("POST",window.location.href,true);x.setRequestHeader("Content-Type","application/json");x.setRequestHeader("X-JSC-Response","1");
        x.onload=function(){if(x.status===200){try{var r=JSON.parse(x.responseText);if(r.success){challengeComplete=true;updateProgress(100,"Проверка завершена!");showSuccess();try{sessionStorage.removeItem("pow_"+challengeData.id.substr(0,8))}catch(e){}setTimeout(function(){window.location.href=redirectUrl},800)}else{showError("<br>"+(r.error||"Ошибка"))}}catch(e){showError("<br>Некорректный ответ")}}else{showError("<br>HTTP "+x.status)}};
        x.onerror=function(){showError("<br>Сетевая ошибка")};x.send(JSON.stringify(data));
    }
    async function performChallenge(){
        if(challengeStarted||challengeComplete)return;challengeStarted=true;
        try{
            updateProgress(5,"Анализ окружения...");await new Promise(function(r){setTimeout(r,400)});
            if(!checkLoopProtection()){showError("<br>Цикл проверки. Очистите cookies.");return;}
            updateProgress(10,"Проверка cookies...");await new Promise(function(r){setTimeout(r,300)});
            if(!areCookiesEnabled()){showError("<br>Включите cookies в браузере.");return;}
            if(isCryptoSupported()){
                updateProgress(15,"Вычисление токена...");
                var n=0,h="",t=challengeData.target||"0".repeat(challengeData.difficulty||4),st=Date.now(),to=(challengeData.timeout||60)*1e3,ss=document.getElementById("stats");
                while(true){if(document.hidden){await new Promise(function(r){setTimeout(r,100)});st+=100;continue;}h=await sha256(challengeData.id+n);if(h.startsWith(t))break;n++;if(n%1e3===0){var el=Date.now()-st,hr=Math.round(n/(el/1e3)),pr=Math.min(85,15+(el/to)*70);updateProgress(pr,"Вычисление токена...");ss.textContent=n.toLocaleString()+" хешей | "+hr.toLocaleString()+" H/s";if(el>to){showError("<br>Время истекло. Обновите страницу.");return;}await new Promise(function(r){setTimeout(r,0)})}}
                ss.textContent=n.toLocaleString()+" хешей за "+((Date.now()-st)/1e3).toFixed(2)+" сек";
                updateProgress(90,"Верификация...");sendResult({challenge_id:challengeData.id,nonce:n,hash:h,timestamp:challengeData.timestamp,type:"pow"});
            }else{
                updateProgress(15,"Режим совместимости...");document.getElementById("stats").textContent="Без PoW";
                var fb=challengeData.fallback;if(!fb||!fb.numbers){showError("<br>Данные недоступны");return;}
                await new Promise(function(r){setTimeout(r,500)});updateProgress(50,"Обработка...");
                var sum=0;for(var i=0;i<fb.numbers.length;i++)sum+=fb.numbers[i];
                await new Promise(function(r){setTimeout(r,500)});updateProgress(90,"Верификация...");
                sendResult({challenge_id:challengeData.id,answer:sum,timestamp:challengeData.timestamp,type:"sum"});
            }
        }catch(e){showError("<br>Ошибка: "+e.message)}
    }
    document.addEventListener("visibilitychange",function(){if(document.visibilityState==="visible"&&!challengeComplete&&!challengeStarted)setTimeout(performChallenge,300);else if(document.visibilityState==="visible"&&!challengeComplete&&challengeStarted)setTimeout(function(){if(!challengeComplete)location.reload()},1e3)});
    window.addEventListener("load",function(){if(!document.hidden)setTimeout(performChallenge,500)});';
}

function _jsc_showChallengePage($challenge, $redirect_url) {
    $ip = _jsc_getClientIP();
    if (_track_page_hammer($ip, 'challenge')) { _show_502_error(); return; }
    _jsc_logStats('shown');
    $cj = json_encode($challenge);
    $rj = json_encode($redirect_url);
    $isPow = isset($challenge['type']) && $challenge['type'] === 'pow';
    $style = isset($challenge['style']) ? $challenge['style'] : 'cloudflare';
    http_response_code(503);
    header('Content-Type: text/html; charset=UTF-8');
    header('Cache-Control: no-cache, no-store, must-revalidate');
    header('Retry-After: 5');
    header('X-Robots-Tag: noindex, nofollow');
    if ($isPow && $style === 'cloudflare') {
        _jsc_showCloudflarePoWPage($cj, $rj);
    } else {
        _jsc_showSMFChallengePage($cj, $rj, $isPow);
    }
    exit;
}

function _jsc_showCloudflarePoWPage($cj, $rj) {
    $sharedJS = _jsc_getSharedJS();
    echo '<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><meta name="robots" content="noindex,nofollow"><title>Проверка... Подождите</title>
<style>
html,body{width:100%;height:100%;margin:0;padding:0;background:#fff;color:#000;font-family:-apple-system,system-ui,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;font-size:17px;display:flex;align-items:center;justify-content:center;text-align:center}
.container{max-width:540px;padding:40px 24px}
.cf-logo{width:360px;max-width:90vw;margin-bottom:48px}
h1{font-size:34px;font-weight:500;margin:0 0 16px}
.subtitle{font-size:20px;color:#222;margin:0 0 40px}
.cf-spinner{position:relative;width:80px;height:80px;margin:0 auto 32px}
.cf-spinner::before,.cf-spinner::after{content:"";position:absolute;top:0;left:0;width:100%;height:100%;border-radius:50%;border:6px solid transparent}
.cf-spinner::before{border-top-color:#f38020;animation:spin 1.2s linear infinite}
.cf-spinner::after{border-top-color:#e04e2a;animation:spin 1.5s linear infinite reverse}
@keyframes spin{to{transform:rotate(360deg)}}
.progress-container{margin:24px 0}.progress-bar{width:100%;height:8px;background:#e5e5e5;border-radius:4px;overflow:hidden}
.progress-fill{height:100%;background:linear-gradient(90deg,#f38020,#e04e2a);width:0%;transition:width .3s}
.status{font-size:18px;color:#444;margin-top:16px;min-height:24px}.status.success{color:#2e7d32;font-weight:600}
.stats{font-size:14px;color:#888;margin-top:12px;font-family:monospace}
.error{margin-top:30px;padding:20px;background:#fff5f5;border:1px solid #fcc;border-radius:8px;color:#c00;display:none;text-align:left;font-size:15px;line-height:1.5}
.small{margin-top:60px;font-size:13px;color:#999}.small a{color:#f38020;text-decoration:none}
.checkmark{display:none;width:80px;height:80px;margin:0 auto 32px}.checkmark.show{display:block;animation:scaleIn .3s ease}
@keyframes scaleIn{from{transform:scale(0)}to{transform:scale(1)}}
.checkmark circle{fill:#2e7d32}.checkmark path{stroke:#fff;stroke-width:3;stroke-linecap:round;stroke-linejoin:round;stroke-dasharray:24;stroke-dashoffset:24;animation:draw .4s ease .2s forwards}
@keyframes draw{to{stroke-dashoffset:0}}
</style></head><body>
<div class="container">
<img src="https://www.cloudflare.com/img/logo-cloudflare-dark.svg" alt="Security" class="cf-logo" onerror="this.style.display=\'none\'">
<h1 id="title">Проверка...</h1><p class="subtitle" id="subtitle">Проверяем ваш браузер перед входом на сайт</p>
<div class="cf-spinner" id="spinner"></div>
<svg class="checkmark" id="checkmark" viewBox="0 0 80 80"><circle cx="40" cy="40" r="38"/><path d="M24 42 L35 53 L56 28" fill="none"/></svg>
<div class="progress-container"><div class="progress-bar"><div class="progress-fill" id="progress"></div></div></div>
<div class="status" id="status">Инициализация...</div><div class="stats" id="stats"></div>
<div class="error" id="error"></div>
<div class="small">Powered by <a href="#">MurKir Security</a> | PoW Protection</div>
</div>
<script>
var challengeData=' . $cj . ',redirectUrl=' . $rj . ';
function showSuccess(){document.getElementById("spinner").style.display="none";document.getElementById("checkmark").classList.add("show");document.getElementById("title").textContent="Проверка пройдена!";document.getElementById("subtitle").textContent="Перенаправление...";document.getElementById("status").className="status success";}
' . $sharedJS . '
</script></body></html>';
}

function _jsc_showSMFChallengePage($cj, $rj, $isPow = false) {
    $sharedJS = _jsc_getSharedJS();
    echo '<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><meta name="robots" content="noindex,nofollow"><title>Проверка безопасности</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}body{font-family:Verdana,Arial,sans-serif;font-size:13px;background:#e5e5e8;color:#000;padding:20px}
#wrapper{max-width:900px;margin:0 auto;background:#fff;border:1px solid #bbb}
#header{background:linear-gradient(to bottom,#315d7d,#1e5380);padding:20px;border-bottom:1px solid #144063}
#header h1{color:#fff;font-size:22px;font-weight:normal;text-shadow:1px 1px 2px rgba(0,0,0,.3);margin:0}
#content{padding:30px;background:#fff}
.catbg{background:linear-gradient(to bottom,#fff,#e0e0e0);border:1px solid #ccc;border-bottom:1px solid #aaa;padding:10px;font-weight:bold;color:#444;margin-bottom:15px}
.windowbg{background:#f0f0f0;border:1px solid #ccc;padding:25px;margin-bottom:15px}
.spinner{width:40px;height:40px;border:4px solid #e5e5e8;border-top:4px solid #1e5380;border-radius:50%;animation:spin 1s linear infinite;margin:0 auto 20px}
@keyframes spin{to{transform:rotate(360deg)}}
.info-text{text-align:center;color:#444;line-height:1.6;margin:15px 0}
.progress-bar{width:100%;height:24px;background:#fff;border:1px solid #bbb;border-radius:3px;overflow:hidden;margin:20px 0;box-shadow:inset 0 1px 3px rgba(0,0,0,.1)}
.progress-fill{height:100%;background:linear-gradient(to bottom,#7db8e5,#4e9bd6);width:0%;transition:width .3s;box-shadow:inset 0 1px 0 rgba(255,255,255,.4)}
.status{text-align:center;color:#666;font-size:12px;margin-top:15px;font-style:italic}.status.success{color:#080}
.stats{text-align:center;color:#888;font-size:11px;margin-top:10px;font-family:monospace}
.error{background:#fff0f0;border:1px solid #c30;color:#c30;padding:15px;border-radius:3px;margin-top:15px;display:none}
.smalltext{font-size:11px;color:#777;text-align:center;margin-top:20px;padding-top:15px;border-top:1px solid #ddd}
#footer{background:#e5e5e8;padding:15px;text-align:center;font-size:11px;color:#666;border-top:1px solid #bbb}
</style></head><body>
<div id="wrapper"><div id="header"><h1>🛡️ Система безопасности</h1></div>
<div id="content"><div class="catbg">Проверка безопасности' . ($isPow ? ' (PoW)' : '') . '</div>
<div class="windowbg">
<div class="spinner" id="spinner"></div>
<div class="info-text"><strong>Пожалуйста, подождите...</strong><br>Проверка вашего браузера.</div>
<div class="progress-bar"><div class="progress-fill" id="progress"></div></div>
<div class="status" id="status">Инициализация...</div><div class="stats" id="stats"></div>
<div class="error" id="error"></div>
<div class="smalltext">Проверка займёт несколько секунд. Не закрывайте окно.</div>
</div></div><div id="footer">Powered by MurKir Security</div></div>
<script>
var challengeData=' . $cj . ',redirectUrl=' . $rj . ';
function showSuccess(){document.getElementById("spinner").style.display="none";document.getElementById("status").className="status success";}
' . $sharedJS . '
</script></body></html>';
}

// ======================== POST HANDLER JS CHALLENGE ========================

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_SERVER['HTTP_X_JSC_RESPONSE'])) {
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-cache, no-store');
    $rawInput = file_get_contents('php://input');
    if (strlen($rawInput) > 4096) { echo json_encode(array('success' => false, 'error' => 'Request too large')); exit; }
    $input = json_decode($rawInput, true);
    if (!$input || !is_array($input) || !isset($input['challenge_id']) || !isset($input['timestamp'])) {
        echo json_encode(array('success' => false, 'error' => 'Invalid request')); exit;
    }
    $challengeId = isset($input['challenge_id']) ? $input['challenge_id'] : '';
    if (!preg_match('/^[a-f0-9]{32}$/', $challengeId)) { echo json_encode(array('success' => false, 'error' => 'Invalid challenge ID')); exit; }
    $timestamp = (int)$input['timestamp'];
    $now = time();
    if ($timestamp > $now + 60 || $timestamp < $now - 600) { echo json_encode(array('success' => false, 'error' => 'Invalid timestamp')); exit; }
    $challengeType = isset($input['type']) ? $input['type'] : 'sum';
    if (!in_array($challengeType, array('pow', 'sum'), true)) $challengeType = 'sum';
    $maxAge = ($challengeType === 'pow') ? 120 : 300;
    if ($now - $timestamp > $maxAge) { echo json_encode(array('success' => false, 'error' => 'Challenge expired')); exit; }
    
    if ($challengeType === 'pow') {
        if (!isset($input['nonce']) || !isset($input['hash'])) { echo json_encode(array('success' => false, 'error' => 'Missing PoW data')); exit; }
        $nonce = $input['nonce'];
        if (!is_numeric($nonce) || $nonce < 0 || $nonce > 4294967295) { echo json_encode(array('success' => false, 'error' => 'Invalid nonce')); exit; }
        $nonce = (int)$nonce;
        $clientHash = isset($input['hash']) ? $input['hash'] : '';
        if (!preg_match('/^[a-f0-9]{64}$/', $clientHash)) { echo json_encode(array('success' => false, 'error' => 'Invalid hash')); exit; }
        $difficulty = isset($_JSC_CONFIG['pow_difficulty']) ? (int)$_JSC_CONFIG['pow_difficulty'] : 4;
        $serverHash = hash('sha256', $challengeId . $nonce);
        $target = str_repeat('0', $difficulty);
        if (!hash_equals($serverHash, $clientHash)) { _jsc_logStats('failed', _jsc_getClientIP()); echo json_encode(array('success' => false, 'error' => 'Hash mismatch')); exit; }
        if (strpos($serverHash, $target) !== 0) { _jsc_logStats('failed', _jsc_getClientIP()); echo json_encode(array('success' => false, 'error' => 'Invalid PoW')); exit; }
    } else {
        if (!isset($input['answer'])) { _jsc_logStats('failed', _jsc_getClientIP()); echo json_encode(array('success' => false, 'error' => 'Missing answer')); exit; }
    }
    
    _jsc_logStats('passed', _jsc_getClientIP());
    $ip = _jsc_getClientIP();
    $token = hash('sha256', $ip . date('Y-m-d') . $_JSC_CONFIG['secret_key']);
    $secure = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
    $lifetime = $_JSC_CONFIG['token_lifetime'];
    $cn = $_JSC_CONFIG['cookie_name'];
    if (PHP_VERSION_ID >= 70300) {
        setcookie($cn, $token, ['expires' => time() + $lifetime, 'path' => '/', 'secure' => $secure, 'httponly' => true, 'samesite' => 'Lax']);
    } else {
        setcookie($cn, $token, time() + $lifetime, '/', '', $secure, true);
    }
    try {
        $pr = new Redis(); $pr->connect('127.0.0.1', 6379, 1); $pr->select(1);
        $pr->del('bot_protection:' . _get_site_id() . ':jsc_auto:pending:' . $ip); $pr->close();
    } catch (Exception $e) {}
    echo json_encode(array('success' => true, 'token' => $token));
    exit;
}

// ======================== QUICK BLOCK CHECK ========================

function _quick_block_check() {
    try {
        // Адмінський IP завжди пропускається
        $ip = _jsc_getClientIP();
        if (_is_admin_ip($ip)) return false;
        
        $redis = new Redis();
        $redis->connect('127.0.0.1', 6379, 1);
        $redis->select(1);
        $siteId = _get_site_id();
        $prefix = 'bot_protection:' . $siteId . ':';
        if ($redis->exists($prefix . 'blocked:hammer:' . $ip)) return true;
        if ($redis->exists($prefix . 'ua_blocked:' . $ip)) return true;
        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
        $lang = isset($_SERVER['HTTP_ACCEPT_LANGUAGE']) ? $_SERVER['HTTP_ACCEPT_LANGUAGE'] : '';
        $bh = hash('sha256', $ua . '|' . $lang);
        $cookieId = isset($_COOKIE['bot_protection_uid']) ? $_COOKIE['bot_protection_uid'] : '';
        $userId = !empty($cookieId) ? $cookieId . '_' . substr($bh, 0, 16) : $ip . '_' . substr($bh, 0, 16);
        if ($redis->exists($prefix . 'blocked:' . hash('md5', $userId))) return true;
        $redis->close();
        return false;
    } catch (Exception $e) { return false; }
}

function _show_502_error() {
    $ip = _jsc_getClientIP();
    _track_page_hammer($ip, 'blocked');
    http_response_code(503);
    header('Content-Type: text/html; charset=UTF-8');
    header('Cache-Control: no-cache, no-store');
    header('Retry-After: 60');
    echo '<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><meta name="robots" content="noindex,nofollow"><title>502 Bad Gateway</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:Verdana,Arial,sans-serif;font-size:13px;background:#e5e5e8;color:#000;padding:20px}#wrapper{max-width:900px;margin:0 auto;background:#fff;border:1px solid #bbb}#header{background:linear-gradient(to bottom,#7d3131,#803e1e);padding:20px;border-bottom:1px solid #631414}#header h1{color:#fff;font-size:22px;font-weight:normal;text-shadow:1px 1px 2px rgba(0,0,0,.3);margin:0}#content{padding:30px}
.catbg{background:linear-gradient(to bottom,#fff,#ffe0e0);border:1px solid #c99;border-bottom:1px solid #a77;padding:10px;font-weight:bold;color:#800;margin-bottom:15px}
.windowbg{background:#fff5f5;border:1px solid #c99;padding:25px;margin-bottom:15px}
.error-icon{text-align:center;font-size:48px;margin-bottom:20px;color:#c30}
.error-code{text-align:center;font-size:18px;font-weight:bold;color:#c30;margin-bottom:15px}
.info-text{color:#444;line-height:1.8;margin:15px 0;text-align:center}
.info-box{background:#f0f0f0;border:1px solid #ccc;padding:15px;margin:20px 0;border-left:4px solid #c30}.info-box strong{display:block;margin-bottom:10px;color:#800}.info-box ul{margin-left:20px;color:#666}.info-box li{margin:5px 0}
.button{display:inline-block;background:linear-gradient(to bottom,#7db8e5,#4e9bd6);border:1px solid #3a7ba8;color:#fff;padding:8px 20px;text-decoration:none;border-radius:3px;font-weight:bold;cursor:pointer;margin-top:15px}.button:hover{background:linear-gradient(to bottom,#8dc5f0,#5ea8e0)}
.center{text-align:center}.smalltext{font-size:11px;color:#777;text-align:center;margin-top:20px;padding-top:15px;border-top:1px solid #ddd}
#footer{background:#e5e5e8;padding:15px;text-align:center;font-size:11px;color:#666;border-top:1px solid #bbb}</style></head><body>
<div id="wrapper"><div id="header"><h1>⚠️ Ошибка сервера</h1></div><div id="content">
<div class="catbg">Ошибка 503 - Service Temporarily Unavailable</div><div class="windowbg">
<div class="error-icon">⚠</div><div class="error-code">HTTP 503 Service Temporarily Unavailable</div>
<div class="info-text"><strong>Сервер временно недоступен</strong><br>Страница временно недоступна, попробуйте позже.</div>
<div class="info-box"><strong>Возможные причины:</strong><ul><li>Сервер перегружен</li><li>Технические работы</li><li>Временные проблемы</li></ul></div>
<div class="center"><a href="javascript:location.reload()" class="button">🔄 Обновить страницу</a></div>
<div class="smalltext">Если проблема сохраняется, обратитесь к администратору.</div>
</div></div><div id="footer">SMF 2.0.15 | Powered by MurKir Security</div></div></body></html>';
    exit;
}

if (_quick_block_check()) { _show_502_error(); }

// ======================== JS CHALLENGE FLOW ========================

if ($_JSC_CONFIG['enabled']) {
    $clientIP = _jsc_getClientIP();
    $userAgent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
    $_jsc_skip = false;
    
    // ПРІОРИТЕТ 0: Білі списки IP
    if (_is_whitelisted_ip($clientIP) !== false) $_jsc_skip = true;
    // ПРІОРИТЕТ 0.5: Admin URL
    if (!$_jsc_skip && _is_admin_url()) $_jsc_skip = true;
    // ПРІОРИТЕТ 1: Власні UA
    if (!$_jsc_skip && _is_custom_ua($userAgent)) $_jsc_skip = true;
    // ПРІОРИТЕТ 2: SEO боти
    if (!$_jsc_skip && _is_seo_bot($userAgent)) $_jsc_skip = true;
    // ПРІОРИТЕТ 3: Статичні файли та AJAX
    if (!$_jsc_skip) {
        $uri = isset($_SERVER['REQUEST_URI']) ? strtolower($_SERVER['REQUEST_URI']) : '';
        foreach (array('.js','.css','.json','.xml','.txt','.ico','.png','.jpg','.jpeg','.gif','.webp','.svg','.woff','.woff2','.ttf','.mp4','.mp3','.pdf','.zip','.rar') as $ext) {
            if (strpos($uri, $ext) !== false) { $_jsc_skip = true; break; }
        }
        if (!$_jsc_skip && !empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') $_jsc_skip = true;
        if (!$_jsc_skip && isset($_GET['api']) && $_GET['api'] == '1' && _is_admin_url()) $_jsc_skip = true;
    }
    
    if (!$_jsc_skip && !_jsc_isVerified($_JSC_CONFIG['secret_key'], $_JSC_CONFIG['cookie_name'])) {
        $mode = isset($_JSC_CONFIG['mode']) ? $_JSC_CONFIG['mode'] : 'always';
        $showChallenge = false;
        if ($mode === 'auto') {
            $showChallenge = (_jsc_check_anomaly($clientIP, $userAgent) !== false);
        } elseif ($mode !== 'never') {
            $showChallenge = true;
        }
        if ($showChallenge) {
            try {
                $pr = new Redis(); $pr->connect('127.0.0.1', 6379, 1); $pr->select(1);
                $pr->setex('bot_protection:' . _get_site_id() . ':jsc_auto:pending:' . $clientIP, 300, time()); $pr->close();
            } catch (Exception $e) {}
            _jsc_showChallengePage(_jsc_generateChallenge($_JSC_CONFIG['secret_key']), _jsc_getSafeCurrentUrl());
        }
    }
}

function _jsc_getSafeCurrentUrl() {
    $host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '';
    $host = preg_replace('/:\d+$/', '', $host);
    if (!preg_match('/^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$/', $host) || strlen($host) > 253) $host = 'localhost';
    $uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '/';
    if (strlen($uri) > 2048) $uri = substr($uri, 0, 2048);
    $uri = preg_replace('/[\x00-\x1F\x7F]/', '', $uri);
    $scheme = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    return $scheme . '://' . $host . $uri;
}

// ======================== КЛАС ЗАХИСТУ ========================

class SimpleBotProtection {
    private $redis = null;
    private $redisHost = '127.0.0.1';
    private $redisPort = 6379;
    private $redisDB = 1;
    private $redisPassword = '';
    private $redisPrefix = 'bot_protection:'; // буде оновлено в __construct з _get_site_id()
    private $debugMode = false;
    
    private $rateLimitSettings = array(
        'max_requests_per_minute' => 30, 'max_requests_per_5min' => 100,
        'max_requests_per_hour' => 500, 'burst_threshold' => 10,
        'block_duration' => 900, 'cookie_multiplier' => 2.0, 'js_verified_multiplier' => 3.0,
    );
    
    private $uaRotationSettings = array(
        'enabled' => true, 'max_unique_ua_per_5min' => 10,
        'max_unique_ua_per_hour' => 20, 'block_duration' => 7200, 'tracking_window' => 3600,
    );
    
    private $apiSettings = array();
    private $noCookieThreshold = 9999;
    private $noCookieTimeWindow = 60;
    private $noCookieRateLimits = array('minute' => 30, '5min' => 150, 'hour' => 500, 'day' => 2000, 'burst' => 5);
    
    private $rdnsSettings = array(
        'enabled' => true, 'cache_ttl' => 3600,
        'rate_limit_per_minute' => 10, 'rdns_on_limit_action' => 'skip',
    );
    private $rdnsPrefix = 'rdns:';
    
    private $searchLogSettings = array(
        'enabled' => true, 'file' => '/var/log/search_engines.log',
        'max_size' => 1048576, 'keep_backups' => 3,
        'log_host' => true, 'log_url' => true, 'log_ua' => true, 'ua_max_length' => 100,
        'redis_stats' => true, 'redis_log_max' => 500, 'redis_stats_ttl' => 2592000,
    );
    
    // Компактний список пошукових систем
    private $searchEngines = array(
        'google' => array(
            'ua' => array('google-read-aloud','googlebot','google-inspectiontool','adsbot-google','apis-google','mediapartners-google','googleother','google-site-verification','googlebot-image','googlebot-news','googlebot-video','google-structured-data'),
            'rdns' => array('.googlebot.com','.google.com'), 'skip_fwd' => false,
            'ips' => array('66.249.64.0/19','64.233.160.0/19','72.14.192.0/18','203.208.32.0/19','74.125.0.0/16','216.239.32.0/19','2001:4860::/32'),
        ),
        'yandex' => array(
            'ua' => array('yandex','yandexbot','yandexmetrika','yandexwebmaster','yandexdirect','yandexmobilebot','yandeximages'),
            'rdns' => array('.yandex.ru','.yandex.net','.yandex.com'), 'skip_fwd' => false,
            'ips' => array('5.45.192.0/18','5.255.192.0/18','37.9.64.0/18','37.140.128.0/18','77.88.0.0/16','87.250.224.0/19','93.158.128.0/18','95.108.128.0/17','100.43.64.0/19','141.8.128.0/18','178.154.128.0/17','213.180.192.0/19','2a02:6b8::/32'),
        ),
        'bing' => array(
            'ua' => array('bingbot','bingpreview','msnbot','adidxbot'),
            'rdns' => array('.search.msn.com'), 'skip_fwd' => false,
            'ips' => array('13.66.0.0/16','13.67.0.0/16','13.68.0.0/16','40.76.0.0/14','157.55.0.0/16','199.30.16.0/20','207.46.0.0/16','2620:1ec:c::0/40'),
        ),
        'baidu' => array(
            'ua' => array('baiduspider','baidu'), 'rdns' => array('.crawl.baidu.com','.baidu.com'), 'skip_fwd' => false,
            'ips' => array('116.179.0.0/16','119.63.192.0/21','123.125.71.0/24','180.76.0.0/16','220.181.0.0/16'),
        ),
        'duckduckgo' => array(
            'ua' => array('duckduckbot','duckduckgo'), 'rdns' => array('.duckduckgo.com'), 'skip_fwd' => true,
            'ips' => array('20.191.45.212/32','40.88.21.235/32','52.142.26.175/32','52.142.24.149/32','72.94.249.34/32','72.94.249.35/32'),
        ),
        'yahoo' => array(
            'ua' => array('slurp','yahoo'), 'rdns' => array('.crawl.yahoo.net'), 'skip_fwd' => false,
            'ips' => array('67.195.0.0/16','74.6.0.0/16','98.136.0.0/14','202.160.176.0/20','209.191.64.0/18'),
        ),
        'applebot' => array(
            'ua' => array('applebot'), 'rdns' => array('.applebot.apple.com'), 'skip_fwd' => false,
            'ips' => array('17.0.0.0/8','2a01:b740::/32'),
        ),
        'facebook' => array(
            'ua' => array('facebookexternalhit','facebookcatalog'), 'rdns' => array('.facebook.com','.fbsv.net'), 'skip_fwd' => true,
            'ips' => array('31.13.24.0/21','31.13.64.0/18','66.220.144.0/20','69.63.176.0/20','173.252.64.0/18','2a03:2880::/32'),
        ),
        'petalbot' => array(
            'ua' => array('petalbot'), 'rdns' => array('.petalsearch.com','.aspiegel.com'), 'skip_fwd' => true,
            'ips' => array('114.119.128.0/17'),
        ),
    );
    
    // Прості боти (тільки UA pattern, skip_fwd=true, без IP ranges)
    private $simpleBots = array(
        'seznam' => array('ua' => array('seznambot','seznam'), 'rdns' => array('.seznam.cz')),
        'sogou' => array('ua' => array('sogou'), 'rdns' => array('.sogou.com')),
        'exabot' => array('ua' => array('exabot'), 'rdns' => array('.exabot.com')),
        'twitter' => array('ua' => array('twitterbot'), 'rdns' => array('.twitter.com')),
        'instagram' => array('ua' => array('instagram'), 'rdns' => array('.instagram.com')),
        'pinterest' => array('ua' => array('pinterest'), 'rdns' => array('.pinterest.com')),
        'linkedin' => array('ua' => array('linkedinbot'), 'rdns' => array('.linkedin.com')),
        'tiktok' => array('ua' => array('tiktok','bytespider','bytedance'), 'rdns' => array('.bytedance.com','.tiktok.com')),
        'whatsapp' => array('ua' => array('whatsapp'), 'rdns' => array('.whatsapp.net')),
        'telegram' => array('ua' => array('telegrambot','telegram'), 'rdns' => array('.telegram.org')),
        'viber' => array('ua' => array('viber'), 'rdns' => array('.viber.com')),
        'discord' => array('ua' => array('discordbot','discord'), 'rdns' => array('.discord.com')),
        'slack' => array('ua' => array('slackbot','slack'), 'rdns' => array('.slack.com')),
        'semrush' => array('ua' => array('semrushbot'), 'rdns' => array('.semrush.com')),
        'ahrefs' => array('ua' => array('ahrefsbot'), 'rdns' => array('.ahrefs.com')),
        'majestic' => array('ua' => array('majestic','mj12bot'), 'rdns' => array('.majestic12.co.uk')),
        'screaming_frog' => array('ua' => array('screaming frog'), 'rdns' => array()),
        'sitebulb' => array('ua' => array('sitebulb'), 'rdns' => array()),
        'pingdom' => array('ua' => array('pingdom'), 'rdns' => array('.pingdom.com')),
        'uptimerobot' => array('ua' => array('uptimerobot'), 'rdns' => array('.uptimerobot.com')),
        'statuscake' => array('ua' => array('statuscake'), 'rdns' => array('.statuscake.com')),
        'gtmetrix' => array('ua' => array('gtmetrix'), 'rdns' => array('.gtmetrix.com')),
        'webpagetest' => array('ua' => array('webpagetest'), 'rdns' => array('.webpagetest.org')),
        'lighthouse' => array('ua' => array('lighthouse','chrome-lighthouse'), 'rdns' => array()),
    );
    
    private $customUserAgents = array();
    
    public function __construct() {
        global $CUSTOM_USER_AGENTS, $_API_CONFIG;
        $this->customUserAgents = $CUSTOM_USER_AGENTS;
        $this->apiSettings = $_API_CONFIG;
        // Per-site ізоляція: кожен домен має окремі лічильники rate limit
        $this->redisPrefix = 'bot_protection:' . _get_site_id() . ':';
        $this->connectRedis();
    }
    
    private function connectRedis() {
        try {
            $this->redis = new Redis();
            $this->redis->connect($this->redisHost, $this->redisPort, 1);
            if ($this->redisPassword) $this->redis->auth($this->redisPassword);
            $this->redis->select($this->redisDB);
            $this->redis->setOption(Redis::OPT_SERIALIZER, Redis::SERIALIZER_PHP);
        } catch (Exception $e) {
            error_log("Redis connection failed: " . $e->getMessage());
            $this->redis = null;
        }
    }
    
    public function protect() {
        try {
            $ip = _jsc_getClientIP();
            $userAgent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
            
            $skipReason = _should_skip_rate_limit($ip);
            if ($skipReason !== false) return;
            if ($this->isCustomUserAgent($userAgent)) return;
            if ($this->verifySearchEngineRDNS($ip, $userAgent)) return;
            if (!$this->redis) return;
            
            $rateMultiplier = _get_rate_limit_multiplier();
            if ($this->checkUserAgentRotation($ip)) { $this->show502Error(); }
            if ($this->checkRateLimit($ip, $rateMultiplier)) { $this->show502Error(); }
        } catch (Exception $e) {
            error_log("BOT PROTECTION ERROR: " . $e->getMessage());
        }
    }
    
    private function isCustomUserAgent($userAgent) {
        if (empty($this->customUserAgents)) return false;
        $uaLower = strtolower($userAgent);
        foreach ($this->customUserAgents as $ua) {
            if (stripos($uaLower, strtolower($ua)) !== false) return true;
        }
        return false;
    }
    
    private function findEngineConfig($userAgent) {
        if (empty($userAgent)) return null;
        // Перевіряємо основні двигуни
        foreach ($this->searchEngines as $engine => $config) {
            foreach ($config['ua'] as $pattern) {
                if (stripos($userAgent, $pattern) !== false) {
                    return array('name' => $engine, 'config' => $config, 'simple' => false);
                }
            }
        }
        // Перевіряємо прості боти
        foreach ($this->simpleBots as $engine => $config) {
            foreach ($config['ua'] as $pattern) {
                if (stripos($userAgent, $pattern) !== false) {
                    return array('name' => $engine, 'config' => $config, 'simple' => true);
                }
            }
        }
        return null;
    }
    
    private function verifySearchEngineRDNS($ip, $userAgent = '') {
        $found = $this->findEngineConfig($userAgent);
        if (!$found || empty($found['config']['rdns'])) return false;
        $verified = $this->performRDNSVerification($ip, $found['config']);
        if ($verified) $this->logSearchEngine($found['name'], $ip, 'rDNS');
        return $verified;
    }
    
    private function performRDNSVerification($ip, $config) {
        try {
            $cacheKey = $this->redisPrefix . $this->rdnsPrefix . 'cache:' . hash('md5', $ip);
            $cached = $this->redis->get($cacheKey);
            if ($cached !== false) return $cached === '1';
            if (!$this->checkRDNSRateLimit()) return false;
            
            $verified = false;
            $rdnsPatterns = $config['rdns'];
            $skipFwd = isset($config['skip_fwd']) ? $config['skip_fwd'] : true;
            $hostname = $this->getHostnameWithTimeout($ip, 2);
            
            if ($hostname && $hostname !== $ip) {
                $hostnameMatches = false;
                foreach ($rdnsPatterns as $pattern) {
                    if ($this->matchesDomainPattern($hostname, $pattern)) { $hostnameMatches = true; break; }
                }
                if ($hostnameMatches) {
                    if ($skipFwd) { $verified = true; }
                    else {
                        $fwdIPs = gethostbynamel($hostname);
                        if ($fwdIPs && in_array($ip, $fwdIPs)) $verified = true;
                    }
                }
            }
            $this->redis->setex($cacheKey, $this->rdnsSettings['cache_ttl'], $verified ? '1' : '0');
            return $verified;
        } catch (Exception $e) { return false; }
    }
    
    private function checkRDNSRateLimit() {
        $key = $this->redisPrefix . $this->rdnsPrefix . 'ratelimit';
        $count = $this->redis->incr($key);
        if ($count === 1) $this->redis->expire($key, 60);
        return $count <= $this->rdnsSettings['rate_limit_per_minute'];
    }
    
    private function getHostnameWithTimeout($ip, $timeout = 2) {
        $start = microtime(true);
        $hostname = @gethostbyaddr($ip);
        if ((microtime(true) - $start) > $timeout) return null;
        return ($hostname !== $ip) ? $hostname : null;
    }
    
    private function matchesDomainPattern($hostname, $pattern) {
        if (substr($pattern, 0, 1) === '.') return substr($hostname, -strlen($pattern)) === $pattern;
        return $hostname === $pattern;
    }
    
    private function checkUserAgentRotation($ip) {
        if (!$this->uaRotationSettings['enabled']) return false;
        $userAgent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
        if (empty($userAgent)) return false;
        $now = time();
        $uaKey = $this->redisPrefix . 'ua:' . $ip;
        $blockKey = $this->redisPrefix . 'ua_blocked:' . $ip;
        if ($this->redis->exists($blockKey)) return true;
        
        $uaData = $this->redis->get($uaKey);
        if (!$uaData || !is_array($uaData)) $uaData = array();
        $filtered = array();
        foreach ($uaData as $ts => $ua) {
            if (($now - $ts) < $this->uaRotationSettings['tracking_window']) $filtered[$ts] = $ua;
        }
        $filtered[$now] = $userAgent;
        $u5 = array(); $uH = array();
        foreach ($filtered as $ts => $ua) {
            if (($now - $ts) < 300) $u5[$ua] = true;
            if (($now - $ts) < 3600) $uH[$ua] = true;
        }
        $this->redis->setex($uaKey, $this->uaRotationSettings['tracking_window'], $filtered);
        
        if (count($u5) > $this->uaRotationSettings['max_unique_ua_per_5min'] ||
            count($uH) > $this->uaRotationSettings['max_unique_ua_per_hour']) {
            $this->redis->setex($blockKey, $this->uaRotationSettings['block_duration'],
                array('time' => $now, 'count_5min' => count($u5), 'count_hour' => count($uH)));
            error_log("UA ROTATION BLOCK: IP=$ip, 5min=" . count($u5) . ", hour=" . count($uH));
            if ($this->apiSettings['enabled'] && $this->apiSettings['block_on_api']) {
                $this->callBlockingAPI($ip, 'block');
            }
            return true;
        }
        return false;
    }
    
    private function generateUserIdentifier() {
        $ip = _jsc_getClientIP();
        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
        $lang = isset($_SERVER['HTTP_ACCEPT_LANGUAGE']) ? $_SERVER['HTTP_ACCEPT_LANGUAGE'] : '';
        $bh = hash('sha256', $ua . '|' . $lang);
        $cookieName = 'bot_protection_uid';
        $cookieId = isset($_COOKIE[$cookieName]) ? $_COOKIE[$cookieName] : '';
        if (empty($cookieId)) {
            $cookieId = bin2hex(random_bytes(16));
            $secure = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
            if (PHP_VERSION_ID >= 70300) {
                setcookie($cookieName, $cookieId, ['expires' => time() + 2592000, 'path' => '/', 'secure' => $secure, 'httponly' => true, 'samesite' => 'Lax']);
            } else {
                setcookie($cookieName, $cookieId, time() + 2592000, '/', '', $secure, true);
            }
        }
        return $cookieId . '_' . substr($bh, 0, 16);
    }
    
    private function hasValidCookie() {
        return isset($_COOKIE['bot_protection_uid']) && !empty($_COOKIE['bot_protection_uid']);
    }
    
    private function isJSVerified() {
        global $_JSC_CONFIG;
        return _jsc_isVerified($_JSC_CONFIG['secret_key'], $_JSC_CONFIG['cookie_name']);
    }
    
    private function checkNoCookieAttempts($ip) {
        $key = $this->redisPrefix . 'no_cookie_attempts:' . $ip;
        $attempts = $this->redis->get($key);
        if (!$attempts || !is_array($attempts)) $attempts = array();
        $now = time();
        $filtered = array();
        foreach ($attempts as $ts) {
            if (($now - $ts) < $this->noCookieTimeWindow) $filtered[] = $ts;
        }
        $filtered[] = $now;
        $this->redis->setex($key, $this->noCookieTimeWindow * 2, $filtered);
        $cnt = count($filtered);
        if ($cnt >= $this->noCookieThreshold) {
            error_log(sprintf("NO COOKIE ATTACK: IP=%s, attempts=%d/%d in %dsec", $ip, $cnt, $this->noCookieThreshold, $this->noCookieTimeWindow));
            $this->redis->setex($this->redisPrefix . 'blocked:no_cookie:' . $ip, 3600, array(
                'ip' => $ip, 'time' => $now, 'reason' => 'no_cookie_attack',
                'attempts' => $cnt, 'threshold' => $this->noCookieThreshold,
            ));
            if ($this->apiSettings['enabled'] && $this->apiSettings['block_on_api']) {
                $this->callBlockingAPI($ip, 'block');
            }
            return true;
        }
        return false;
    }
    
    private function checkRateLimit($ip, $ajaxMultiplier = 1.0) {
        $now = time();
        $userId = $this->generateUserIdentifier();
        $hasCookie = $this->hasValidCookie();
        $useStrictLimits = false;
        
        if (!$hasCookie) {
            if ($this->checkNoCookieAttempts($ip)) return true;
            $useStrictLimits = true;
        } else {
            $ak = $this->redisPrefix . 'no_cookie_attempts:' . $ip;
            if ($this->redis->exists($ak)) $this->redis->del($ak);
        }
        
        $key = $this->redisPrefix . 'rate:' . hash('md5', $userId);
        $blockKey = $this->redisPrefix . 'blocked:' . hash('md5', $userId);
        if ($this->redis->exists($blockKey)) return true;
        
        $data = $this->redis->get($key);
        $requests = ($data && is_array($data)) ? $data : array('minute' => array(), '5min' => array(), 'hour' => array(), 'last_10sec' => array());
        foreach (array('minute','5min','hour','last_10sec') as $k) {
            if (!isset($requests[$k]) || !is_array($requests[$k])) $requests[$k] = array();
        }
        
        // Фільтрація
        $windows = array('minute' => 60, '5min' => 300, 'hour' => 3600, 'last_10sec' => 10);
        foreach ($windows as $k => $w) {
            $requests[$k] = array_values(array_filter($requests[$k], function($t) use ($now, $w) { return ($now - $t) < $w; }));
            $requests[$k][] = $now;
        }
        
        if ($useStrictLimits) {
            $limits = array('minute' => $this->noCookieRateLimits['minute'], '5min' => $this->noCookieRateLimits['5min'],
                'hour' => $this->noCookieRateLimits['hour'], 'burst' => $this->noCookieRateLimits['burst']);
        } else {
            $mult = $hasCookie ? $this->rateLimitSettings['cookie_multiplier'] : 1.0;
            if ($this->isJSVerified()) $mult = $this->rateLimitSettings['js_verified_multiplier'];
            $totalMult = $mult * $ajaxMultiplier;
            $limits = array(
                'minute' => (int)($this->rateLimitSettings['max_requests_per_minute'] * $totalMult),
                '5min' => (int)($this->rateLimitSettings['max_requests_per_5min'] * $totalMult),
                'hour' => (int)($this->rateLimitSettings['max_requests_per_hour'] * $totalMult),
                'burst' => (int)($this->rateLimitSettings['burst_threshold'] * $totalMult),
            );
        }
        
        $this->redis->setex($key, 3600, $requests);
        
        $violations = array();
        if (count($requests['minute']) > $limits['minute']) $violations[] = 'minute';
        if (count($requests['5min']) > $limits['5min']) $violations[] = '5min';
        if (count($requests['hour']) > $limits['hour']) $violations[] = 'hour';
        if (count($requests['last_10sec']) > $limits['burst']) $violations[] = 'burst';
        
        if (!empty($violations)) {
            $this->blockUser($userId, $ip, $violations, $hasCookie, $limits);
            return true;
        }
        return false;
    }
    
    private function blockUser($userId, $ip, $violations, $hasCookie, $limits) {
        $blockKey = $this->redisPrefix . 'blocked:' . hash('md5', $userId);
        if ($this->apiSettings['block_on_redis']) {
            $this->redis->setex($blockKey, $this->rateLimitSettings['block_duration'], array(
                'time' => time(), 'violations' => $violations, 'user_id' => $userId,
                'ip' => $ip, 'has_cookie' => $hasCookie, 'limits' => $limits,
            ));
        }
        error_log("RATE LIMIT BLOCK: user_id=" . substr($userId, 0, 20) . ", ip=$ip, cookie=" . ($hasCookie ? 'Y' : 'N') . ", v=" . implode(',', $violations));
        if (!$hasCookie && $this->apiSettings['enabled'] && $this->apiSettings['block_on_api']) {
            $this->callBlockingAPI($ip, 'block');
        }
    }
    
    private function callBlockingAPI($ip, $action = 'block') {
        if (!$this->apiSettings['enabled'] || !$this->apiSettings['block_on_api']) {
            return array('status' => 'skipped');
        }
        $maxRetries = max(1, $this->apiSettings['retry_on_failure']);
        $lastError = null;
        for ($attempt = 0; $attempt < $maxRetries; $attempt++) {
            $result = _call_block_api($this->apiSettings, $ip, $action);
            if (isset($result['status']) && $result['status'] !== 'error') return $result;
            $lastError = isset($result['message']) ? $result['message'] : 'unknown';
            if ($attempt < $maxRetries - 1) usleep(500000);
        }
        return array('status' => 'error', 'message' => $lastError);
    }
    
    private function show502Error() { _show_502_error(); }
    
    private function logSearchEngine($engine, $ip, $method = 'IP') {
        if (!$this->searchLogSettings['enabled']) return;
        if ($this->searchLogSettings['redis_stats'] && $this->redis) {
            _log_search_engine_visit($this->redis, $ip, $method, $engine);
        }
        $logFile = $this->searchLogSettings['file'];
        if (file_exists($logFile) && filesize($logFile) >= $this->searchLogSettings['max_size']) {
            $this->rotateSearchLog();
        }
        $parts = array(date('Y-m-d H:i:s'), $engine, $ip, $method);
        if ($this->searchLogSettings['log_host']) $parts[] = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '-';
        if ($this->searchLogSettings['log_url']) $parts[] = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '-';
        if ($this->searchLogSettings['log_ua']) {
            $ua = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '-';
            $mx = $this->searchLogSettings['ua_max_length'];
            if (strlen($ua) > $mx) $ua = substr($ua, 0, $mx) . '...';
            $parts[] = $ua;
        }
        @file_put_contents($logFile, implode(' | ', $parts) . "\n", FILE_APPEND | LOCK_EX);
    }
    
    private function rotateSearchLog() {
        $f = $this->searchLogSettings['file'];
        $k = $this->searchLogSettings['keep_backups'];
        $oldest = $f . '.' . $k;
        if (file_exists($oldest)) @unlink($oldest);
        for ($i = $k - 1; $i >= 1; $i--) {
            $from = $f . '.' . $i;
            if (file_exists($from)) @rename($from, $f . '.' . ($i + 1));
        }
        if (file_exists($f)) @rename($f, $f . '.1');
    }
    
    public function setDebugMode($enabled) { $this->debugMode = (bool)$enabled; }
    public function updateRateLimitSettings($s) { $this->rateLimitSettings = array_merge($this->rateLimitSettings, $s); }
    public function updateNoCookieSettings($s) {
        if (isset($s['threshold'])) $this->noCookieThreshold = max(1, (int)$s['threshold']);
        if (isset($s['time_window'])) $this->noCookieTimeWindow = max(10, (int)$s['time_window']);
    }
    
    public function __destruct() {
        if ($this->redis !== null) {
            try { $this->redis->close(); } catch (Exception $e) {}
            $this->redis = null;
        }
    }
}

// АВТОМАТИЧНИЙ ЗАХИСТ
$protection = new SimpleBotProtection();
$protection->protect();
