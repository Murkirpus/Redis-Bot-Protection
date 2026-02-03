<?php
/**
 * ============================================================================
 * MurKir Security - Admin Panel v1.6
 * ============================================================================
 * 
 * Полноценная админ-панель для управления Redis Bot Protection
 * 
 * НОВОЕ v1.6 (2026-02-02):
 * ✅ API розблокування в iptables при натисканні "Розблокувати"
 * ✅ unblockIP() тепер викликає API перед видаленням з Redis
 * ✅ unblockByKey() тепер викликає API
 * ✅ clearAllBlocks() тепер викликає API для кожного IP
 * ✅ Налаштування API в конфігурації (api_url, api_key)
 * ✅ clearAllBlocks тепер видаляє ua_blocked:* (новий формат)
 * ✅ Сумісність з inline_check_lite.php v3.8.9
 * 
 * НОВОЕ v1.5 (2026-01-29):
 * ✅ Статус перевірки в "JS Challenge Статистика" → "Показано"
 * ✅ Галочка (✓) для пройдених, хрестик (✗) для провалених
 * ✅ Годинник (⏱) для протермінованих, крапки (⋯) для очікування
 * ✅ Повний User Agent без обрізки
 * 
 * НОВОЕ v1.4 (2026-01-27):
 * ✅ rDNS відображення в "Лог пошукових систем"
 * ✅ rDNS відображення в "JS Challenge Статистика"
 * ✅ Кешування rDNS запитів в Redis (1 година)
 * ✅ Асинхронне завантаження rDNS для кращої продуктивності
 * 
 * НОВОЕ v1.3 (для inline_check_lite v3.7.0):
 * ✅ Статистика IP Whitelist кешу пошукових систем
 * ✅ API endpoint для перегляду/очистки ip_whitelist кешу
 * ✅ Розблокування blocked:no_cookie:{IP} в unblockIP()
 * ✅ Відображення кількості закешованих IP в Dashboard
 * 
 * НОВОЕ v1.2:
 * ✅ Виправлено відображення IP для blocked:no_cookie (v3.6.6+)
 * ✅ Підтримка нового формату blocked:no_cookie:{IP}
 * ✅ Функція extractIP() тепер розпізнає всі формати блокувань
 * 
 * НОВОЕ v1.2:
 * ✅ Раздел "Пошуковики" - просмотр лога поисковых ботов
 * ✅ Статистика по каждому боту (Google, Yandex, Bing и др.)
 * ✅ Просмотр URL, IP, метод верификации
 * ✅ Очистка лога
 * 
 * ВОЗМОЖНОСТИ:
 * ✅ Dashboard с статистикой в реальном времени
 * ✅ Просмотр заблокированных IP (Rate Limit + UA Rotation)
 * ✅ Разблокировка IP/пользователей
 * ✅ Просмотр активных сессий
 * ✅ Настройки системы
 * ✅ Логи событий
 * ✅ API endpoints для AJAX
 * ✅ Авторизация с защитой от брутфорса
 * 
 * ИСПОЛЬЗОВАНИЕ:
 * 1. Разместите файл на сервере
 * 2. Измените $adminPassword на свой пароль
 * 3. Настройте Redis подключение если нужно
 * 
 * ============================================================================
 */

// ============================================================================
// КОНФИГУРАЦИЯ
// ============================================================================

$config = [
    // Авторизация
    'admin_password' => 'info@murkir.pp.ua',  // ИЗМЕНИТЕ НА СВОЙ ПАРОЛЬ!
    'session_lifetime' => 3600 * 8,      // 8 часов
    'max_login_attempts' => 5,           // Максимум попыток входа
    'lockout_time' => 900,               // Блокировка на 15 минут
    
    // Redis
    'redis_host' => '127.0.0.1',
    'redis_port' => 6379,
    'redis_password' => null,
    'redis_db' => 1,
    'redis_prefix' => 'bot_protection:',
    'rdns_prefix' => 'rdns:',
    
    // v1.6: API iptables (для розблокування IP)
    'api_enabled' => true,
    'api_url' => 'https://blog.dj-x.info/redis-bot_protection/API/iptables.php',
    'api_key' => 'Asd123456',
    'api_timeout' => 5,
    
    // Панель
    'items_per_page' => 20,
    'refresh_interval' => 30,            // Автообновление каждые 30 сек
    
    // Лог пошукових систем
    'search_log_file' => '/tmp/search_bots.log',  // Шлях до лог-файлу
    'search_log_lines' => 100,                     // Кількість рядків для відображення
];

// ============================================================================
// ИНИЦИАЛИЗАЦИЯ
// ============================================================================

session_start();
date_default_timezone_set('Europe/Kiev');

// Подключение к Redis
$redis = null;
$redisError = null;

try {
    $redis = new Redis();
    $redis->connect($config['redis_host'], $config['redis_port'], 2);
    
    if ($config['redis_password']) {
        $redis->auth($config['redis_password']);
    }
    
    $redis->select($config['redis_db']);
    $redis->setOption(Redis::OPT_SERIALIZER, Redis::SERIALIZER_PHP);
} catch (Exception $e) {
    $redisError = $e->getMessage();
    $redis = null;
}

// ============================================================================
// ФУНКЦИИ АВТОРИЗАЦИИ
// ============================================================================

function isLoggedIn() {
    global $config;
    if (!isset($_SESSION['admin_logged_in']) || $_SESSION['admin_logged_in'] !== true) {
        return false;
    }
    if (time() - ($_SESSION['admin_login_time'] ?? 0) > $config['session_lifetime']) {
        logout();
        return false;
    }
    return true;
}

function login($password) {
    global $config, $redis;
    
    $ip = $_SERVER['REMOTE_ADDR'];
    $attemptKey = 'admin_login_attempts:' . $ip;
    
    // Проверка блокировки
    if ($redis) {
        $attempts = $redis->get($attemptKey);
        if ($attempts && $attempts >= $config['max_login_attempts']) {
            return ['success' => false, 'message' => 'Занадто багато спроб. Спробуйте через 15 хвилин.'];
        }
    }
    
    if ($password === $config['admin_password']) {
        $_SESSION['admin_logged_in'] = true;
        $_SESSION['admin_login_time'] = time();
        $_SESSION['admin_ip'] = $ip;
        
        if ($redis) {
            $redis->del($attemptKey);
        }
        
        return ['success' => true];
    }
    
    // Неудачная попытка
    if ($redis) {
        $redis->incr($attemptKey);
        $redis->expire($attemptKey, $config['lockout_time']);
    }
    
    return ['success' => false, 'message' => 'Невірний пароль'];
}

function logout() {
    $_SESSION = [];
    session_destroy();
}

// ============================================================================
// ФУНКЦИИ РАБОТЫ С ДАННЫМИ
// ============================================================================

function getStats($redis, $prefix) {
    if (!$redis) return null;
    
    $keys = $redis->keys($prefix . '*');
    
    $stats = [
        'total_tracked' => 0,
        'blocked_rate_limit' => 0,
        'blocked_ua_rotation' => 0,
        'blocked_no_cookie' => 0,      // v1.3: blocked:no_cookie
        'rate_limit_keys' => 0,
        'ua_rotation_tracked' => 0,
        'rdns_cache' => 0,
        'ip_whitelist_cache' => 0,     // v1.3: ip_whitelist кеш
        'active_users' => 0,
    ];
    
    foreach ($keys as $key) {
        // ВИПРАВЛЕННЯ: Використовуємо сувору перевірку префікса (початок ключа),
        // замість пошуку входження підстроки де завгодно.
        
        // 1. UA Rotation & UA Blocked
        if (strpos($key, $prefix . 'ua_rotation_blocked:') === 0 || strpos($key, $prefix . 'ua_blocked:') === 0) {
            $stats['blocked_ua_rotation']++;
        } 
        // 2. Blocked No Cookie
        elseif (strpos($key, $prefix . 'blocked:no_cookie:') === 0) {
            $stats['blocked_no_cookie']++;
        } 
        // 3. Blocked Rate Limit (звичайна блокировка)
        elseif (strpos($key, $prefix . 'blocked:') === 0) {
            $stats['blocked_rate_limit']++;
        } 
        // 4. Rate Limit Keys (Активні сесії)
        elseif (strpos($key, $prefix . 'rate:') === 0) {
            $stats['rate_limit_keys']++;
            $stats['total_tracked']++;
        } 
        // 5. UA Rotation Tracking
        elseif (strpos($key, $prefix . 'ua_rotation_5min:') === 0 || strpos($key, $prefix . 'ua_rotation_hour:') === 0 || strpos($key, $prefix . 'ua:') === 0) {
            $stats['ua_rotation_tracked']++;
        } 
        // 6. rDNS Cache
        elseif (strpos($key, $prefix . 'rdns:cache:') === 0) { // Тут потрібно перевірити чи префікс rdns входить в загальний prefix
            // Зазвичай rdns: має свій префікс, але в поточному коді ми скануємо $prefix.*
            // Якщо rDNS ключі лежать окремо, вони не потраплять в цей цикл, якщо prefix не пустий.
            // Але якщо вони під загальним префіксом:
            $stats['rdns_cache']++;
        }
        elseif (strpos($key, 'rdns:cache:') !== false && $prefix === '') {
             // Fallback для rDNS якщо немає префікса бота
             $stats['rdns_cache']++;
        }
        // 7. IP Whitelist Cache
        elseif (strpos($key, $prefix . 'ip_whitelist:') === 0) {
            $stats['ip_whitelist_cache']++;
        }
    }
    
    $stats['active_users'] = $stats['rate_limit_keys'];
    $stats['total_blocked'] = $stats['blocked_rate_limit'] + $stats['blocked_ua_rotation'] + $stats['blocked_no_cookie'];
    
    return $stats;
}

function getBlockedIPs($redis, $prefix, $type = 'all', $page = 1, $perPage = 20) {
    if (!$redis) return ['items' => [], 'total' => 0, 'pages' => 0];
    
    $blocked = [];
    
    // Rate limit blocks (включая no_cookie)
    if ($type === 'all' || $type === 'rate_limit' || $type === 'no_cookie') {
        $keys = $redis->keys($prefix . 'blocked:*');
        if (is_array($keys)) {
            foreach ($keys as $key) {
                $data = $redis->get($key);
                $ttl = $redis->ttl($key);
                $ip = extractIP($key);
                
                // v1.3: Визначаємо тип блокування
                $blockType = 'rate_limit';
                if (strpos($key, ':blocked:no_cookie:') !== false) {
                    $blockType = 'no_cookie';
                }
                
                // Фільтр по типу
                if ($type !== 'all' && $type !== $blockType) {
                    continue;
                }
                
                // Handle both array data and simple values
                if (is_array($data)) {
                    $blocked[] = [
                        'key' => $key,
                        'type' => $blockType,
                        'ip' => $data['ip'] ?? $ip,
                        'user_id' => $data['user_id'] ?? null,
                        'violations' => $data['violations'] ?? [],
                        'reason' => $data['reason'] ?? null,  // v1.3: причина блокування
                        'attempts' => $data['attempts'] ?? null,  // v1.3: кількість спроб
                        'time' => $data['time'] ?? null,
                        'has_cookie' => $data['has_cookie'] ?? false,
                        'ttl' => $ttl,
                        'expires' => $ttl > 0 ? date('Y-m-d H:i:s', time() + $ttl) : 'N/A',
                    ];
                } else {
                    // Simple value (true, 1, timestamp, etc)
                    $blocked[] = [
                        'key' => $key,
                        'type' => $blockType,
                        'ip' => $ip,
                        'user_id' => null,
                        'violations' => [],
                        'reason' => null,
                        'attempts' => null,
                        'time' => is_numeric($data) ? (int)$data : null,
                        'has_cookie' => false,
                        'ttl' => $ttl,
                        'expires' => $ttl > 0 ? date('Y-m-d H:i:s', time() + $ttl) : 'N/A',
                    ];
                }
            }
        }
    }
    
    // UA Rotation blocks (обидва формати ключів)
    if ($type === 'all' || $type === 'ua_rotation') {
        // v1.3: Перевіряємо обидва формати ключів
        $uaKeys1 = $redis->keys($prefix . 'ua_rotation_blocked:*');
        $uaKeys2 = $redis->keys($prefix . 'ua_blocked:*');
        $keys = array_merge(
            is_array($uaKeys1) ? $uaKeys1 : [],
            is_array($uaKeys2) ? $uaKeys2 : []
        );
        $keys = array_unique($keys);
        
        foreach ($keys as $key) {
                $data = $redis->get($key);
                $ttl = $redis->ttl($key);
                
                // v1.3: Витягуємо IP з обох форматів ключів
                $ip = $key;
                $ip = str_replace($prefix . 'ua_rotation_blocked:', '', $ip);
                $ip = str_replace($prefix . 'ua_blocked:', '', $ip);
                
                // v1.3: Додаємо count_5min та count_hour з нового формату
                $count5min = 0;
                $countHour = 0;
                if (is_array($data)) {
                    $count5min = $data['unique_ua_5min'] ?? $data['count_5min'] ?? 0;
                    $countHour = $data['unique_ua_hour'] ?? $data['count_hour'] ?? 0;
                }
                
                // Handle both array data and simple values
                if (is_array($data)) {
                    $blocked[] = [
                        'key' => $key,
                        'type' => 'ua_rotation',
                        'ip' => $data['ip'] ?? $ip,
                        'unique_ua_5min' => $count5min,
                        'unique_ua_hour' => $countHour,
                        'violations' => $data['violations'] ?? [],
                        'time' => $data['time'] ?? null,
                        'ttl' => $ttl,
                        'expires' => $ttl > 0 ? date('Y-m-d H:i:s', time() + $ttl) : 'N/A',
                    ];
                } else {
                    // Simple value
                    $blocked[] = [
                        'key' => $key,
                        'type' => 'ua_rotation',
                        'ip' => $ip,
                        'unique_ua_5min' => 0,
                        'unique_ua_hour' => 0,
                        'violations' => [],
                        'time' => is_numeric($data) ? (int)$data : null,
                        'ttl' => $ttl,
                        'expires' => $ttl > 0 ? date('Y-m-d H:i:s', time() + $ttl) : 'N/A',
                    ];
                }
        }
    }
    
    // Сортировка по времени (новые первые)
    usort($blocked, function($a, $b) {
        return ($b['time'] ?? 0) - ($a['time'] ?? 0);
    });
    
    $total = count($blocked);
    $pages = ceil($total / $perPage);
    $offset = ($page - 1) * $perPage;
    
    return [
        'items' => array_slice($blocked, $offset, $perPage),
        'total' => $total,
        'pages' => $pages,
        'page' => $page,
        'per_page' => $perPage
    ];
}

function extractIP($key) {
    // Формат 1: blocked:no_cookie:{IP} (v3.6.6+)
    if (preg_match('/blocked:no_cookie:([0-9a-f:\.]+)$/i', $key, $matches)) {
        return $matches[1];
    }
    // Формат 2: blocked:{IP} (старий формат з прямим IP)
    if (preg_match('/blocked:([0-9a-f:\.]+)$/i', $key, $matches)) {
        return $matches[1];
    }
    // Формат 3: blocked:{hash} (MD5 хеш) - повертаємо unknown
    return 'unknown';
}

function getActiveSessions($redis, $prefix, $page = 1, $perPage = 20) {
    if (!$redis) return ['items' => [], 'total' => 0, 'pages' => 0];
    
    $sessions = [];
    $keys = $redis->keys($prefix . 'rate:*');
    
    if (!is_array($keys)) {
        return ['items' => [], 'total' => 0, 'pages' => 0];
    }
    
    // Собираем все blocked записи для определения IP по user_id
    $blockedKeys = $redis->keys($prefix . 'blocked:*');
    $userToIP = [];
    if (is_array($blockedKeys)) {
        foreach ($blockedKeys as $bKey) {
            $bData = $redis->get($bKey);
            if ($bData && isset($bData['user_id']) && isset($bData['ip'])) {
                $hash = hash('md5', $bData['user_id']);
                $userToIP[$hash] = $bData['ip'];
            }
        }
    }
    
    foreach ($keys as $key) {
        $data = $redis->get($key);
        if ($data && is_array($data)) {
            $ttl = $redis->ttl($key);
            $lastRequest = 0;
            
            foreach (['minute', '5min', 'hour', 'last_10sec'] as $period) {
                if (!empty($data[$period]) && is_array($data[$period])) {
                    $lastRequest = max($lastRequest, max($data[$period]));
                }
            }
            
            // Извлекаем hash из ключа (rate:HASH)
            $keyHash = str_replace($prefix . 'rate:', '', $key);
            
            // Пробуем найти IP
            $ip = $userToIP[$keyHash] ?? null;
            
            // Если в данных есть IP напрямую
            if (!$ip && isset($data['ip'])) {
                $ip = $data['ip'];
            }
            
            // Определяем тип сессии
            $sessionType = 'user';
            if (strpos($key, 'ip:') !== false) {
                $sessionType = 'ip';
            }
            
            $sessions[] = [
                'key' => $key,
                'key_hash' => $keyHash,
                'ip' => $ip,
                'session_type' => $sessionType,
                'requests_minute' => count($data['minute'] ?? []),
                'requests_5min' => count($data['5min'] ?? []),
                'requests_hour' => count($data['hour'] ?? []),
                'burst' => count($data['last_10sec'] ?? []),
                'last_request' => $lastRequest > 0 ? date('H:i:s', $lastRequest) : 'N/A',
                'last_request_ts' => $lastRequest,
                'ttl' => $ttl,
            ];
        }
    }
    
    // Сортировка по активности (requests_minute DESC, потом last_request DESC)
    usort($sessions, function($a, $b) {
        if ($b['requests_minute'] !== $a['requests_minute']) {
            return $b['requests_minute'] - $a['requests_minute'];
        }
        return ($b['last_request_ts'] ?? 0) - ($a['last_request_ts'] ?? 0);
    });
    
    $total = count($sessions);
    $pages = ceil($total / $perPage);
    $offset = ($page - 1) * $perPage;
    
    return [
        'items' => array_slice($sessions, $offset, $perPage),
        'total' => $total,
        'pages' => $pages,
        'page' => $page,
        'per_page' => $perPage
    ];
}

function getRedisMemoryInfo($redis) {
    if (!$redis) return null;
    
    try {
        $info = $redis->info('memory');
        
        $used = $info['used_memory'] ?? 0;
        $usedHuman = $info['used_memory_human'] ?? '0B';
        $peak = $info['used_memory_peak'] ?? 0;
        $peakHuman = $info['used_memory_peak_human'] ?? '0B';
        $maxMemory = $info['maxmemory'] ?? 0;
        $maxMemoryHuman = $info['maxmemory_human'] ?? '0B';
        
        // Если maxmemory не установлен, пробуем получить из конфига
        if ($maxMemory == 0) {
            $config = $redis->config('GET', 'maxmemory');
            $maxMemory = $config['maxmemory'] ?? 0;
        }
        
        // Рассчитываем процент использования
        $usagePercent = 0;
        if ($maxMemory > 0) {
            $usagePercent = round(($used / $maxMemory) * 100, 1);
        }
        
        // Форматируем maxmemory если нужно
        if ($maxMemory > 0 && $maxMemoryHuman === '0B') {
            $maxMemoryHuman = formatBytes($maxMemory);
        }
        
        return [
            'used' => $used,
            'used_human' => $usedHuman,
            'peak' => $peak,
            'peak_human' => $peakHuman,
            'max' => $maxMemory,
            'max_human' => $maxMemory > 0 ? $maxMemoryHuman : 'Unlimited',
            'usage_percent' => $usagePercent,
            'has_limit' => $maxMemory > 0,
        ];
    } catch (Exception $e) {
        error_log("Redis memory info error: " . $e->getMessage());
        return null;
    }
}

function formatBytes($bytes, $precision = 2) {
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    
    $bytes = max($bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    $pow = min($pow, count($units) - 1);
    
    $bytes /= pow(1024, $pow);
    
    return round($bytes, $precision) . $units[$pow];
}

function resolveRDNS($ip, $redis = null, $cacheTime = 3600) {
    // Проверяем кеш
    if ($redis) {
        $cacheKey = 'admin:rdns:' . $ip;
        $cached = $redis->get($cacheKey);
        if ($cached !== false) {
            return $cached;
        }
    }
    
    // Делаем rDNS запрос
    $hostname = @gethostbyaddr($ip);
    
    // Если не удалось разрешить, возвращаем null
    if ($hostname === $ip || $hostname === false) {
        $hostname = null;
    }
    
    // Кешируем результат
    if ($redis) {
        $redis->setex($cacheKey, $cacheTime, $hostname ?? '');
    }
    
    return $hostname;
}

function resolveMultipleRDNS($ips, $redis = null) {
    $results = [];
    
    foreach ($ips as $ip) {
        if (!empty($ip) && filter_var($ip, FILTER_VALIDATE_IP)) {
            $results[$ip] = resolveRDNS($ip, $redis);
        }
    }
    
    return $results;
}

function getRDNSStats($redis, $prefix, $rdnsPrefix) {
    if (!$redis) return null;
    
    $currentMinute = floor(time() / 60);
    $prevMinute = $currentMinute - 1;
    
    $currentKey = $prefix . $rdnsPrefix . 'ratelimit:' . $currentMinute;
    $prevKey = $prefix . $rdnsPrefix . 'ratelimit:' . $prevMinute;
    
    $currentCount = $redis->get($currentKey) ?: 0;
    $prevCount = $redis->get($prevKey) ?: 0;
    
    $cacheKeys = $redis->keys($prefix . $rdnsPrefix . 'cache:*');
    
    return [
        'current_minute' => (int)$currentCount,
        'previous_minute' => (int)$prevCount,
        'cache_entries' => count($cacheKeys),
    ];
}

// ============================================================================
// IP WHITELIST ФУНКЦІЇ (v1.3)
// ============================================================================

/**
 * Статистика IP Whitelist кешу
 */
function getIPWhitelistStats($redis, $prefix) {
    if (!$redis) return null;
    
    $keys = $redis->keys($prefix . 'ip_whitelist:*');
    
    $stats = [
        'total_cached' => 0,
        'whitelisted' => 0,
        'not_whitelisted' => 0,
        'items' => [],
    ];
    
    if (is_array($keys)) {
        $stats['total_cached'] = count($keys);
        
        // Отримуємо останні 50 записів
        $sampleKeys = array_slice($keys, 0, 50);
        
        foreach ($sampleKeys as $key) {
            $value = $redis->get($key);
            $ttl = $redis->ttl($key);
            $ip = str_replace($prefix . 'ip_whitelist:', '', $key);
            
            $isWhitelisted = ($value === '1' || $value === 1 || $value === true);
            
            if ($isWhitelisted) {
                $stats['whitelisted']++;
            } else {
                $stats['not_whitelisted']++;
            }
            
            $stats['items'][] = [
                'ip' => $ip,
                'whitelisted' => $isWhitelisted,
                'ttl' => $ttl,
                'expires' => $ttl > 0 ? date('Y-m-d H:i:s', time() + $ttl) : 'N/A',
            ];
        }
    }
    
    return $stats;
}

/**
 * Очистка IP Whitelist кешу
 */
function clearIPWhitelistCache($redis, $prefix) {
    if (!$redis) return ['success' => false, 'message' => 'Redis недоступний'];
    
    $keys = $redis->keys($prefix . 'ip_whitelist:*');
    $deleted = 0;
    
    if (is_array($keys)) {
        foreach ($keys as $key) {
            if ($redis->del($key)) {
                $deleted++;
            }
        }
    }
    
    return [
        'success' => true,
        'message' => "Видалено $deleted записів IP Whitelist кешу",
        'deleted' => $deleted
    ];
}

/**
 * v1.6: Виклик API для розблокування IP в iptables
 */
function unblockViaAPI($ip) {
    global $config;
    
    if (empty($config['api_enabled'])) {
        return ['status' => 'disabled', 'message' => 'API disabled'];
    }
    
    $url = $config['api_url'] . '?' . http_build_query([
        'action' => 'unblock',
        'ip' => $ip,
        'api_key' => $config['api_key']
    ]);
    
    try {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $config['api_timeout'],
            CURLOPT_CONNECTTIMEOUT => $config['api_timeout'],
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_USERAGENT => 'MurKir-Admin/1.6',
            CURLOPT_HTTPHEADER => [
                'Accept: application/json',
                'Cache-Control: no-cache'
            ]
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);
        
        if ($curlError) {
            return ['status' => 'error', 'message' => "CURL: $curlError"];
        }
        
        if ($httpCode !== 200) {
            return ['status' => 'error', 'message' => "HTTP $httpCode"];
        }
        
        $data = json_decode($response, true);
        
        if (!$data) {
            return ['status' => 'error', 'message' => 'Invalid JSON'];
        }
        
        if (isset($data['status'])) {
            if ($data['status'] === 'success' || $data['status'] === 'not_blocked') {
                return ['status' => 'success', 'message' => 'Unblocked via API'];
            }
            return ['status' => 'error', 'message' => $data['message'] ?? 'Unknown error'];
        }
        
        return ['status' => 'success', 'message' => 'OK'];
        
    } catch (Exception $e) {
        return ['status' => 'error', 'message' => $e->getMessage()];
    }
}

function unblockIP($redis, $prefix, $ip) {
    if (!$redis) return ['success' => false, 'message' => 'Redis недоступний'];
    
    $deleted = 0;
    $apiResult = null;
    
    // v1.6: Спочатку викликаємо API для розблокування в iptables
    if (filter_var($ip, FILTER_VALIDATE_IP)) {
        $apiResult = unblockViaAPI($ip);
    }
    
    // Прямые ключи для удаления
    $directKeys = [
        $prefix . 'blocked:' . $ip,
        $prefix . 'blocked:' . hash('md5', 'ip:' . $ip),
        $prefix . 'blocked:no_cookie:' . $ip,          // v1.3: no_cookie блокування
        $prefix . 'ua_rotation_blocked:' . $ip,
        $prefix . 'ua_blocked:' . $ip,                 // v1.3: альтернативний ключ
        $prefix . 'rate:' . $ip,
        $prefix . 'rate:' . hash('md5', 'ip:' . $ip),
        $prefix . 'ua_rotation_5min:' . $ip,
        $prefix . 'ua_rotation_hour:' . $ip,
        $prefix . 'ua:' . $ip,                         // v1.3: альтернативний ключ
        $prefix . 'no_cookie_attempts:' . $ip,         // v1.3: лічильник спроб без cookie
        $prefix . 'ip_whitelist:' . $ip,               // v1.3: кеш IP whitelist
    ];
    
    // Удаляем прямые ключи
    foreach ($directKeys as $key) {
        if ($redis->del($key)) {
            $deleted++;
        }
    }
    
    // Ищем блокировки по IP в данных (для user-based блокировок)
    $allBlockedKeys = $redis->keys($prefix . 'blocked:*');
    if (is_array($allBlockedKeys)) {
        foreach ($allBlockedKeys as $key) {
            $data = $redis->get($key);
            if ($data && isset($data['ip']) && $data['ip'] === $ip) {
                if ($redis->del($key)) {
                    $deleted++;
                }
            }
        }
    }
    
    // v1.6: Формуємо повідомлення з результатом API
    $message = "IP $ip розблоковано (Redis: $deleted)";
    if ($apiResult) {
        if ($apiResult['status'] === 'success') {
            $message .= " ✓ API: OK";
        } elseif ($apiResult['status'] === 'disabled') {
            $message .= " (API вимкнено)";
        } else {
            $message .= " ⚠ API: " . $apiResult['message'];
        }
    }
    
    return [
        'success' => true, 
        'message' => $message, 
        'deleted' => $deleted,
        'api_result' => $apiResult
    ];
}

function unblockByKey($redis, $key) {
    if (!$redis) return ['success' => false, 'message' => 'Redis недоступний'];
    
    // v1.6: Витягуємо IP з ключа для API
    $ip = null;
    if (preg_match('/([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/', $key, $matches)) {
        $ip = $matches[1];
    } elseif (preg_match('/([0-9a-f:]+:[0-9a-f:]+)/i', $key, $matches)) {
        $ip = $matches[1]; // IPv6
    }
    
    // Також перевіряємо дані ключа
    if (!$ip) {
        $data = $redis->get($key);
        if (is_array($data) && isset($data['ip'])) {
            $ip = $data['ip'];
        }
    }
    
    // Викликаємо API якщо знайшли IP
    $apiResult = null;
    if ($ip && filter_var($ip, FILTER_VALIDATE_IP)) {
        $apiResult = unblockViaAPI($ip);
    }
    
    $deleted = $redis->del($key);
    
    $message = $deleted > 0 ? 'Розблоковано' : 'Ключ не знайдено';
    if ($apiResult && $apiResult['status'] === 'success') {
        $message .= ' ✓ API: OK';
    }
    
    return ['success' => $deleted > 0, 'message' => $message, 'api_result' => $apiResult];
}

function clearAllBlocks($redis, $prefix) {
    if (!$redis) return ['success' => false, 'message' => 'Redis недоступний'];
    
    $deleted = 0;
    $apiSuccess = 0;
    $apiFailed = 0;
    $processedIPs = [];  // Щоб не викликати API двічі для одного IP
    
    // Получаем все ключи блокировок (все форматы)
    $blockedKeys = $redis->keys($prefix . 'blocked:*');
    $uaRotationKeys = $redis->keys($prefix . 'ua_rotation_blocked:*');
    $uaBlockedKeys = $redis->keys($prefix . 'ua_blocked:*');  // v1.6: новий формат
    
    $keys = array_merge(
        is_array($blockedKeys) ? $blockedKeys : [],
        is_array($uaRotationKeys) ? $uaRotationKeys : [],
        is_array($uaBlockedKeys) ? $uaBlockedKeys : []
    );
    
    // Видаляємо дублікати
    $keys = array_unique($keys);
    
    foreach ($keys as $key) {
        // v1.6: Витягуємо IP для API
        $ip = null;
        if (preg_match('/([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/', $key, $matches)) {
            $ip = $matches[1];
        }
        
        // Також перевіряємо дані
        if (!$ip) {
            $data = $redis->get($key);
            if (is_array($data) && isset($data['ip'])) {
                $ip = $data['ip'];
            }
        }
        
        // Викликаємо API (один раз для кожного IP)
        if ($ip && filter_var($ip, FILTER_VALIDATE_IP) && !isset($processedIPs[$ip])) {
            $processedIPs[$ip] = true;
            $apiResult = unblockViaAPI($ip);
            if ($apiResult['status'] === 'success') {
                $apiSuccess++;
            } else {
                $apiFailed++;
            }
            usleep(50000); // 50ms затримка між API запитами
        }
        
        // Видаляємо ключ з Redis
        if ($redis->del($key)) {
            $deleted++;
        }
    }
    
    $message = "Видалено $deleted блокувань";
    if ($apiSuccess > 0 || $apiFailed > 0) {
        $message .= " | API: ✓$apiSuccess";
        if ($apiFailed > 0) {
            $message .= " ✗$apiFailed";
        }
    }
    
    return [
        'success' => true, 
        'message' => $message, 
        'deleted' => $deleted,
        'api_success' => $apiSuccess,
        'api_failed' => $apiFailed
    ];
}

function getUARotationInfo($redis, $prefix, $ip) {
    if (!$redis) return null;
    
    $key5min = $prefix . 'ua_rotation_5min:' . $ip;
    $keyHour = $prefix . 'ua_rotation_hour:' . $ip;
    $blockKey = $prefix . 'ua_rotation_blocked:' . $ip;
    
    $data5min = $redis->get($key5min);
    $dataHour = $redis->get($keyHour);
    $blockData = $redis->get($blockKey);
    
    $uniqueUAs = [];
    if ($data5min && is_array($data5min)) {
        $uniqueUAs = array_merge($uniqueUAs, array_keys($data5min));
    }
    if ($dataHour && is_array($dataHour)) {
        $uniqueUAs = array_merge($uniqueUAs, array_keys($dataHour));
    }
    
    return [
        'ip' => $ip,
        'is_blocked' => $redis->exists($blockKey),
        'unique_ua_5min' => $data5min && is_array($data5min) ? count($data5min) : 0,
        'unique_ua_hour' => $dataHour && is_array($dataHour) ? count($dataHour) : 0,
        'block_info' => $blockData ?: null,
        'unique_ua_hashes' => array_unique($uniqueUAs),
    ];
}

/**
 * Отримання логу пошукових систем
 */
/**
 * v1.3: Отримання статистики пошукових ботів з Redis
 */
function getSearchBotStatsFromRedis($redis, $prefix) {
    if (!$redis) return null;
    
    $result = [
        'stats' => [],           // Загальна статистика по ботах
        'today_stats' => [],     // Статистика за сьогодні
        'hosts' => [],           // Статистика по хостах
        'methods' => [],         // Статистика по методах верифікації
        'lines' => [],           // Останні візити
        'total_visits' => 0,
        'today_visits' => 0,
    ];
    
    try {
        // 1. Загальна статистика по ботах
        $totalKeys = $redis->keys($prefix . 'search_stats:total:*');
        if (is_array($totalKeys)) {
            foreach ($totalKeys as $key) {
                $engine = str_replace($prefix . 'search_stats:total:', '', $key);
                $count = (int)$redis->get($key);
                $result['stats'][ucfirst($engine)] = $count;
                $result['total_visits'] += $count;
            }
            arsort($result['stats']);
        }
        
        // 2. Статистика за сьогодні
        $today = date('Y-m-d');
        $todayKeys = $redis->keys($prefix . 'search_stats:today:' . $today . ':*');
        if (is_array($todayKeys)) {
            foreach ($todayKeys as $key) {
                $engine = preg_replace('/.*:today:' . $today . ':/', '', $key);
                $count = (int)$redis->get($key);
                $result['today_stats'][ucfirst($engine)] = $count;
                $result['today_visits'] += $count;
            }
            arsort($result['today_stats']);
        }
        
        // 3. Статистика по хостах
        $hostKeys = $redis->keys($prefix . 'search_stats:hosts:*');
        if (is_array($hostKeys)) {
            foreach ($hostKeys as $key) {
                $host = str_replace($prefix . 'search_stats:hosts:', '', $key);
                $count = (int)$redis->get($key);
                $result['hosts'][$host] = $count;
            }
            arsort($result['hosts']);
        }
        
        // 4. Статистика по методах
        $methodKeys = $redis->keys($prefix . 'search_stats:methods:*');
        if (is_array($methodKeys)) {
            foreach ($methodKeys as $key) {
                $method = str_replace($prefix . 'search_stats:methods:', '', $key);
                $count = (int)$redis->get($key);
                $result['methods'][strtoupper($method)] = $count;
            }
            arsort($result['methods']);
        }
        
        // 5. Останні візити з логу
        $logKey = $prefix . 'search_log';
        $logs = $redis->lrange($logKey, 0, 99);
        if (is_array($logs)) {
            // v1.4: Додаємо rDNS до кожного запису
            foreach ($logs as &$log) {
                if (is_array($log) && isset($log['ip']) && filter_var($log['ip'], FILTER_VALIDATE_IP)) {
                    $log['rdns'] = resolveRDNS($log['ip'], $redis);
                }
            }
            unset($log);
            $result['lines'] = $logs;
        }
        
    } catch (Exception $e) {
        error_log("getSearchBotStatsFromRedis error: " . $e->getMessage());
    }
    
    return $result;
}

/**
 * v1.3: Очищення статистики пошукових ботів в Redis
 */
function clearSearchBotStatsRedis($redis, $prefix) {
    if (!$redis) return ['success' => false, 'message' => 'Redis недоступний'];
    
    $deleted = 0;
    
    try {
        // Видаляємо всі ключі статистики
        $patterns = [
            $prefix . 'search_stats:total:*',
            $prefix . 'search_stats:today:*',
            $prefix . 'search_stats:hosts:*',
            $prefix . 'search_stats:methods:*',
            $prefix . 'search_log',
        ];
        
        foreach ($patterns as $pattern) {
            if (strpos($pattern, '*') !== false) {
                $keys = $redis->keys($pattern);
                if (is_array($keys)) {
                    foreach ($keys as $key) {
                        if ($redis->del($key)) {
                            $deleted++;
                        }
                    }
                }
            } else {
                if ($redis->del($pattern)) {
                    $deleted++;
                }
            }
        }
        
    } catch (Exception $e) {
        return ['success' => false, 'message' => 'Помилка: ' . $e->getMessage()];
    }
    
    return [
        'success' => true,
        'message' => "Видалено $deleted записів статистики пошукових ботів",
        'deleted' => $deleted
    ];
}

function getSearchBotLog($logFile, $lines = 100) {
    $result = [
        'file' => $logFile,
        'exists' => file_exists($logFile),
        'size' => 0,
        'lines' => [],
        'total_lines' => 0,
        'stats' => [],
        'hosts' => [],
    ];
    
    if (!$result['exists']) {
        return $result;
    }
    
    $result['size'] = filesize($logFile);
    
    // Читаємо файл
    $content = @file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    
    if (!$content) {
        return $result;
    }
    
    $result['total_lines'] = count($content);
    
    // Парсимо рядки та збираємо статистику
    $stats = [];
    $hosts = [];
    $parsed = [];
    
    foreach ($content as $line) {
        $parts = explode(' | ', $line);
        if (count($parts) >= 4) {
            // Новий формат: time | bot | ip | method | host | url | ua
            // Старий формат: time | bot | ip | method | url | ua
            $entry = [
                'time' => isset($parts[0]) ? trim($parts[0]) : '',
                'bot' => isset($parts[1]) ? trim($parts[1]) : '',
                'ip' => isset($parts[2]) ? trim($parts[2]) : '',
                'method' => isset($parts[3]) ? trim($parts[3]) : '',
            ];
            
            // Визначаємо формат (новий чи старий) по кількості частин
            if (count($parts) >= 7) {
                // Новий формат з доменом
                $entry['host'] = isset($parts[4]) ? trim($parts[4]) : '-';
                $entry['url'] = isset($parts[5]) ? trim($parts[5]) : '';
                $entry['ua'] = isset($parts[6]) ? trim($parts[6]) : '';
            } elseif (count($parts) >= 5) {
                // Старий формат без домену
                $entry['host'] = '-';
                $entry['url'] = isset($parts[4]) ? trim($parts[4]) : '';
                $entry['ua'] = isset($parts[5]) ? trim($parts[5]) : '';
            } else {
                $entry['host'] = '-';
                $entry['url'] = '';
                $entry['ua'] = '';
            }
            
            $parsed[] = $entry;
            
            // Статистика по ботах
            $bot = $entry['bot'];
            if (!isset($stats[$bot])) {
                $stats[$bot] = 0;
            }
            $stats[$bot]++;
            
            // Статистика по доменах
            $host = $entry['host'];
            if ($host && $host !== '-') {
                if (!isset($hosts[$host])) {
                    $hosts[$host] = 0;
                }
                $hosts[$host]++;
            }
        }
    }
    
    // Сортуємо статистику за кількістю (DESC)
    arsort($stats);
    arsort($hosts);
    $result['stats'] = $stats;
    $result['hosts'] = $hosts;
    
    // Повертаємо останні N рядків (найновіші)
    $result['lines'] = array_slice(array_reverse($parsed), 0, $lines);
    
    return $result;
}

/**
 * Очищення логу пошукових систем
 */
function clearSearchBotLog($logFile) {
    if (file_exists($logFile)) {
        @unlink($logFile);
        return ['success' => true, 'message' => 'Лог очищено'];
    }
    return ['success' => true, 'message' => 'Лог вже порожній'];
}


/**
 * Отримання статистики JS Challenge
 */
function getJSChallengeStats($redis, $prefix) {
    if (!$redis) return null;
    
    $statsPrefix = $prefix . 'jsc_stats:';
    $today = date('Y-m-d');
    
    // Загальна статистика
    $stats = [
        'total' => [
            'shown' => (int)$redis->get($statsPrefix . 'total:shown') ?: 0,
            'passed' => (int)$redis->get($statsPrefix . 'total:passed') ?: 0,
            'failed' => (int)$redis->get($statsPrefix . 'total:failed') ?: 0,
            'expired' => (int)$redis->get($statsPrefix . 'total:expired') ?: 0,
        ],
        'today' => [
            'shown' => (int)$redis->get($statsPrefix . 'daily:' . $today . ':shown') ?: 0,
            'passed' => (int)$redis->get($statsPrefix . 'daily:' . $today . ':passed') ?: 0,
            'failed' => (int)$redis->get($statsPrefix . 'daily:' . $today . ':failed') ?: 0,
            'expired' => (int)$redis->get($statsPrefix . 'daily:' . $today . ':expired') ?: 0,
        ],
        'hourly' => [],
        'recent_logs' => [
            'shown' => [],
            'passed' => [],
            'failed' => [],
            'expired' => [],
        ],
    ];
    
    // Підраховуємо загальні показники
    $stats['total']['total'] = $stats['total']['shown'];
    $stats['total']['success_rate'] = $stats['total']['shown'] > 0 
        ? round(($stats['total']['passed'] / $stats['total']['shown']) * 100, 2) 
        : 0;
    
    $stats['today']['total'] = $stats['today']['shown'];
    $stats['today']['success_rate'] = $stats['today']['shown'] > 0 
        ? round(($stats['today']['passed'] / $stats['today']['shown']) * 100, 2) 
        : 0;
    
    // Погодинна статистика (останні 24 години)
    for ($i = 23; $i >= 0; $i--) {
        $hour = date('Y-m-d:H', strtotime("-$i hours"));
        $hourDisplay = date('H:00', strtotime("-$i hours"));
        
        $stats['hourly'][] = [
            'hour' => $hourDisplay,
            'shown' => (int)$redis->get($statsPrefix . 'hourly:' . $hour . ':shown') ?: 0,
            'passed' => (int)$redis->get($statsPrefix . 'hourly:' . $hour . ':passed') ?: 0,
            'failed' => (int)$redis->get($statsPrefix . 'hourly:' . $hour . ':failed') ?: 0,
            'expired' => (int)$redis->get($statsPrefix . 'hourly:' . $hour . ':expired') ?: 0,
        ];
    }
    
    // v1.5: Спочатку збираємо passed/failed/expired для визначення статусу shown
    $passedIndex = [];  // IP|UA => time
    $failedIndex = [];
    $expiredIndex = [];
    
    // Збираємо passed записи
    $passedLogs = $redis->lRange($statsPrefix . 'log:passed', 0, 99);
    if ($passedLogs) {
        foreach ($passedLogs as $log) {
            if (is_array($log) && isset($log['ip'])) {
                $key = $log['ip'] . '|' . ($log['ua'] ?? '');
                $passedIndex[$key] = $log['date'] ?? '';
            }
        }
    }
    
    // Збираємо failed записи
    $failedLogs = $redis->lRange($statsPrefix . 'log:failed', 0, 99);
    if ($failedLogs) {
        foreach ($failedLogs as $log) {
            if (is_array($log) && isset($log['ip'])) {
                $key = $log['ip'] . '|' . ($log['ua'] ?? '');
                $failedIndex[$key] = $log['date'] ?? '';
            }
        }
    }
    
    // Збираємо expired записи
    $expiredLogs = $redis->lRange($statsPrefix . 'log:expired', 0, 99);
    if ($expiredLogs) {
        foreach ($expiredLogs as $log) {
            if (is_array($log) && isset($log['ip'])) {
                $key = $log['ip'] . '|' . ($log['ua'] ?? '');
                $expiredIndex[$key] = $log['date'] ?? '';
            }
        }
    }
    
    // Останні логи (останні 20 записів для кожного типу)
    $logTypes = ['shown', 'passed', 'failed', 'expired'];
    foreach ($logTypes as $type) {
        $logKey = $statsPrefix . 'log:' . $type;
        $logs = $redis->lRange($logKey, 0, 19); // Отримуємо останні 20
        
        if ($logs) {
            foreach ($logs as $log) {
                if (is_array($log)) {
                    // v1.4: Додаємо rDNS до кожного запису
                    if (isset($log['ip']) && filter_var($log['ip'], FILTER_VALIDATE_IP)) {
                        $log['rdns'] = resolveRDNS($log['ip'], $redis);
                    }
                    
                    // v1.5: Для shown записів визначаємо статус
                    if ($type === 'shown' && isset($log['ip'])) {
                        $key = $log['ip'] . '|' . ($log['ua'] ?? '');
                        $shownTime = strtotime($log['date'] ?? 'now');
                        
                        // Перевіряємо passed (пріоритет)
                        if (isset($passedIndex[$key])) {
                            $passedTime = strtotime($passedIndex[$key]);
                            // Passed має бути після shown і не більше 10 хвилин
                            if ($passedTime >= $shownTime && ($passedTime - $shownTime) < 600) {
                                $log['status'] = 'passed';
                            }
                        }
                        
                        // Перевіряємо failed
                        if (!isset($log['status']) && isset($failedIndex[$key])) {
                            $failedTime = strtotime($failedIndex[$key]);
                            if ($failedTime >= $shownTime && ($failedTime - $shownTime) < 600) {
                                $log['status'] = 'failed';
                            }
                        }
                        
                        // Перевіряємо expired
                        if (!isset($log['status']) && isset($expiredIndex[$key])) {
                            $expiredTime = strtotime($expiredIndex[$key]);
                            if ($expiredTime >= $shownTime && ($expiredTime - $shownTime) < 600) {
                                $log['status'] = 'expired';
                            }
                        }
                        
                        // Якщо статус не визначено - pending
                        if (!isset($log['status'])) {
                            $log['status'] = 'pending';
                        }
                    }
                    
                    $stats['recent_logs'][$type][] = $log;
                }
            }
        }
    }
    
    return $stats;
}
// ============================================================================
// API ENDPOINTS
// ============================================================================

if (isset($_GET['api'])) {
    header('Content-Type: application/json; charset=utf-8');
    
    // Проверка авторизации для API
    if (!isLoggedIn()) {
        echo json_encode(['error' => 'Unauthorized']);
        exit;
    }
    
    $action = $_GET['api'];
    $prefix = $config['redis_prefix'];
    
    switch ($action) {
        case 'stats':
            echo json_encode(getStats($redis, $prefix));
            break;
            
        case 'memory':
            echo json_encode(getRedisMemoryInfo($redis));
            break;
            
        case 'blocked':
            $type = $_GET['type'] ?? 'all';
            $page = max(1, (int)($_GET['page'] ?? 1));
            $perPage = min(100, max(1, (int)($_GET['per_page'] ?? $config['items_per_page'])));
            $resolveRdns = isset($_GET['resolve_rdns']) && $_GET['resolve_rdns'] === '1';
            
            $result = getBlockedIPs($redis, $prefix, $type, $page, $perPage);
            
            // Если нужно резолвить rDNS
            if ($resolveRdns && !empty($result['items'])) {
                $ips = array_column($result['items'], 'ip');
                $rdnsResults = resolveMultipleRDNS($ips, $redis);
                
                foreach ($result['items'] as &$item) {
                    $item['rdns'] = $rdnsResults[$item['ip']] ?? null;
                }
                unset($item);
            }
            
            echo json_encode($result);
            break;
            
        case 'sessions':
            $page = max(1, (int)($_GET['page'] ?? 1));
            $perPage = min(100, max(1, (int)($_GET['per_page'] ?? $config['items_per_page'])));
            echo json_encode(getActiveSessions($redis, $prefix, $page, $perPage));
            break;
            
        case 'rdns':
            echo json_encode(getRDNSStats($redis, $prefix, $config['rdns_prefix']));
            break;
            
        case 'resolve_rdns':
            $ip = $_GET['ip'] ?? '';
            if ($ip && filter_var($ip, FILTER_VALIDATE_IP)) {
                $hostname = resolveRDNS($ip, $redis);
                echo json_encode(['ip' => $ip, 'rdns' => $hostname]);
            } else {
                echo json_encode(['error' => 'Invalid IP']);
            }
            break;
            
        case 'unblock':
            $ip = $_POST['ip'] ?? $_GET['ip'] ?? '';
            if ($ip) {
                echo json_encode(unblockIP($redis, $prefix, $ip));
            } else {
                echo json_encode(['error' => 'IP не вказано']);
            }
            break;
            
        case 'unblock_key':
            $key = $_POST['key'] ?? $_GET['key'] ?? '';
            if ($key) {
                echo json_encode(unblockByKey($redis, $key));
            } else {
                echo json_encode(['error' => 'Ключ не вказано']);
            }
            break;
            
        case 'clear_all':
            echo json_encode(clearAllBlocks($redis, $prefix));
            break;
            
        case 'ua_info':
            $ip = $_GET['ip'] ?? '';
            if ($ip) {
                echo json_encode(getUARotationInfo($redis, $prefix, $ip));
            } else {
                echo json_encode(['error' => 'IP не вказано']);
            }
            break;
            
        case 'search_log':
            $lines = min(500, max(10, (int)($_GET['lines'] ?? $config['search_log_lines'])));
            echo json_encode(getSearchBotLog($config['search_log_file'], $lines));
            break;
            
        case 'clear_search_log':
            echo json_encode(clearSearchBotLog($config['search_log_file']));
            break;
        
        // v1.3: Статистика пошукових ботів з Redis
        case 'search_stats':
            echo json_encode(getSearchBotStatsFromRedis($redis, $prefix));
            break;
        
        // v1.3: Очищення статистики пошукових ботів в Redis
        case 'clear_search_stats':
            echo json_encode(clearSearchBotStatsRedis($redis, $prefix));
            break;
            
        case 'jsc_stats':
            echo json_encode(getJSChallengeStats($redis, $prefix));
            break;
            break;
        
        // v1.3: IP Whitelist кеш статистика
        case 'ip_whitelist':
            echo json_encode(getIPWhitelistStats($redis, $prefix));
            break;
        
        // v1.3: Очистка IP Whitelist кешу
        case 'clear_ip_whitelist':
            echo json_encode(clearIPWhitelistCache($redis, $prefix));
            break;
            
        default:
            echo json_encode(['error' => 'Unknown action']);
    }
    exit;
}

// ============================================================================
// ОБРАБОТКА ФОРМ
// ============================================================================

$message = null;
$messageType = 'info';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['action'])) {
        switch ($_POST['action']) {
            case 'login':
                $result = login($_POST['password'] ?? '');
                if (!$result['success']) {
                    $message = $result['message'];
                    $messageType = 'error';
                }
                break;
                
            case 'logout':
                logout();
                header('Location: ' . $_SERVER['PHP_SELF']);
                exit;
                
            case 'unblock':
                if (isLoggedIn()) {
                    $ip = $_POST['ip'] ?? '';
                    if ($ip) {
                        $result = unblockIP($redis, $config['redis_prefix'], $ip);
                        $message = $result['message'];
                        $messageType = $result['success'] ? 'success' : 'error';
                    }
                }
                break;
        }
    }
}

// ============================================================================
// ПОЛУЧЕНИЕ ДАННЫХ ДЛЯ ОТОБРАЖЕНИЯ
// ============================================================================

$stats = null;
$blockedData = ['items' => [], 'total' => 0, 'pages' => 0, 'page' => 1];
$sessionsData = ['items' => [], 'total' => 0, 'pages' => 0, 'page' => 1];
$rdnsStats = null;
$memoryInfo = null;

if (isLoggedIn() && $redis) {
    $stats = getStats($redis, $config['redis_prefix']);
    $blockedData = getBlockedIPs($redis, $config['redis_prefix'], 'all', 1, $config['items_per_page']);
    $sessionsData = getActiveSessions($redis, $config['redis_prefix'], 1, $config['items_per_page']);
    $rdnsStats = getRDNSStats($redis, $config['redis_prefix'], $config['rdns_prefix']);
    $memoryInfo = getRedisMemoryInfo($redis);
}

?>
<!DOCTYPE html>
<html lang="uk">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MurKir Security - Admin Panel</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            /* Cybersecurity Dark Theme */
            --bg-primary: #0a0e17;
            --bg-secondary: #111827;
            --bg-tertiary: #1a2332;
            --bg-card: #151d2e;
            --bg-hover: #1e293b;
            
            --accent-primary: #00f5d4;
            --accent-secondary: #00bbf9;
            --accent-warning: #f59e0b;
            --accent-danger: #ef4444;
            --accent-success: #10b981;
            --accent-purple: #8b5cf6;
            
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            
            --border-color: #1e293b;
            --border-glow: rgba(0, 245, 212, 0.3);
            
            --shadow-glow: 0 0 30px rgba(0, 245, 212, 0.1);
            --shadow-card: 0 4px 20px rgba(0, 0, 0, 0.3);
            
            --font-display: 'Outfit', sans-serif;
            --font-mono: 'JetBrains Mono', monospace;
            
            --radius-sm: 6px;
            --radius-md: 12px;
            --radius-lg: 16px;
            --radius-xl: 24px;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: var(--font-display);
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            line-height: 1.6;
        }
        
        /* Animated Background */
        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: 
                radial-gradient(ellipse at 20% 20%, rgba(0, 245, 212, 0.05) 0%, transparent 50%),
                radial-gradient(ellipse at 80% 80%, rgba(0, 187, 249, 0.05) 0%, transparent 50%),
                radial-gradient(ellipse at 50% 50%, rgba(139, 92, 246, 0.03) 0%, transparent 70%);
            pointer-events: none;
            z-index: 0;
        }
        
        /* Grid Pattern Overlay */
        body::after {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-image: 
                linear-gradient(rgba(0, 245, 212, 0.02) 1px, transparent 1px),
                linear-gradient(90deg, rgba(0, 245, 212, 0.02) 1px, transparent 1px);
            background-size: 50px 50px;
            pointer-events: none;
            z-index: 0;
        }
        
        .container {
            position: relative;
            z-index: 1;
            max-width: 1600px;
            margin: 0 auto;
            padding: 20px;
        }
        
        /* Header */
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px 30px;
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-lg);
            margin-bottom: 30px;
            box-shadow: var(--shadow-card);
        }
        
        .logo {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .logo-icon {
            width: 50px;
            height: 50px;
            background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary));
            border-radius: var(--radius-md);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            box-shadow: 0 0 20px rgba(0, 245, 212, 0.3);
        }
        
        .logo-text h1 {
            font-size: 1.5rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .logo-text span {
            font-size: 0.75rem;
            color: var(--text-muted);
            font-family: var(--font-mono);
        }
        
        .header-actions {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .status-badge {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 8px 16px;
            background: var(--bg-tertiary);
            border-radius: var(--radius-md);
            font-size: 0.85rem;
            font-family: var(--font-mono);
        }
        
        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            animation: pulse 2s infinite;
        }
        
        .status-dot.online {
            background: var(--accent-success);
            box-shadow: 0 0 10px var(--accent-success);
        }
        
        .status-dot.offline {
            background: var(--accent-danger);
            box-shadow: 0 0 10px var(--accent-danger);
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        /* Buttons */
        .btn {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 10px 20px;
            border: none;
            border-radius: var(--radius-md);
            font-family: var(--font-display);
            font-size: 0.9rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s ease;
            text-decoration: none;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary));
            color: var(--bg-primary);
        }
        
        .btn-primary:hover {
            box-shadow: 0 0 25px rgba(0, 245, 212, 0.4);
            transform: translateY(-2px);
        }
        
        .btn-secondary {
            background: var(--bg-tertiary);
            color: var(--text-primary);
            border: 1px solid var(--border-color);
        }
        
        .btn-secondary:hover {
            background: var(--bg-hover);
            border-color: var(--accent-primary);
        }
        
        .btn-danger {
            background: rgba(239, 68, 68, 0.1);
            color: var(--accent-danger);
            border: 1px solid rgba(239, 68, 68, 0.3);
        }
        
        .btn-danger:hover {
            background: rgba(239, 68, 68, 0.2);
            box-shadow: 0 0 15px rgba(239, 68, 68, 0.2);
        }
        
        .btn-sm {
            padding: 6px 12px;
            font-size: 0.8rem;
        }
        
        .btn-icon {
            width: 36px;
            height: 36px;
            padding: 0;
            justify-content: center;
        }
        
        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        /* Redis Memory Panel */
        .memory-panel {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-lg);
            padding: 20px 24px;
            margin-bottom: 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 30px;
            flex-wrap: wrap;
        }
        
        .memory-info {
            display: flex;
            align-items: center;
            gap: 20px;
            flex-wrap: wrap;
        }
        
        .memory-icon {
            width: 50px;
            height: 50px;
            background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary));
            border-radius: var(--radius-md);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            box-shadow: 0 0 20px rgba(0, 245, 212, 0.2);
        }
        
        .memory-details {
            display: flex;
            flex-direction: column;
            gap: 4px;
        }
        
        .memory-title {
            font-size: 0.85rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .memory-value {
            font-size: 1.5rem;
            font-weight: 700;
            font-family: var(--font-mono);
            color: var(--text-primary);
        }
        
        .memory-value span {
            color: var(--text-muted);
            font-weight: 400;
            font-size: 1rem;
        }
        
        .memory-bar-container {
            flex: 1;
            min-width: 200px;
            max-width: 400px;
        }
        
        .memory-bar-label {
            display: flex;
            justify-content: space-between;
            margin-bottom: 8px;
            font-size: 0.85rem;
            color: var(--text-secondary);
        }
        
        .memory-bar {
            height: 12px;
            background: var(--bg-tertiary);
            border-radius: 6px;
            overflow: hidden;
            position: relative;
        }
        
        .memory-bar-fill {
            height: 100%;
            border-radius: 6px;
            transition: width 0.5s ease;
            position: relative;
        }
        
        .memory-bar-fill.low {
            background: linear-gradient(90deg, var(--accent-success), #34d399);
        }
        
        .memory-bar-fill.medium {
            background: linear-gradient(90deg, var(--accent-warning), #fbbf24);
        }
        
        .memory-bar-fill.high {
            background: linear-gradient(90deg, var(--accent-danger), #f87171);
        }
        
        .memory-stats {
            display: flex;
            gap: 30px;
            flex-wrap: wrap;
        }
        
        .memory-stat {
            display: flex;
            flex-direction: column;
            gap: 2px;
        }
        
        .memory-stat-label {
            font-size: 0.75rem;
            color: var(--text-muted);
            text-transform: uppercase;
        }
        
        .memory-stat-value {
            font-size: 1rem;
            font-weight: 600;
            font-family: var(--font-mono);
            color: var(--accent-primary);
        }
        
        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-lg);
            padding: 24px;
            position: relative;
            overflow: hidden;
            transition: all 0.3s ease;
        }
        
        .stat-card:hover {
            border-color: var(--accent-primary);
            box-shadow: var(--shadow-glow);
            transform: translateY(-3px);
        }
        
        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, var(--accent-primary), var(--accent-secondary));
            opacity: 0;
            transition: opacity 0.3s ease;
        }
        
        .stat-card:hover::before {
            opacity: 1;
        }
        
        .stat-icon {
            width: 48px;
            height: 48px;
            border-radius: var(--radius-md);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            margin-bottom: 16px;
        }
        
        .stat-icon.blue {
            background: rgba(0, 187, 249, 0.1);
            color: var(--accent-secondary);
        }
        
        .stat-icon.green {
            background: rgba(16, 185, 129, 0.1);
            color: var(--accent-success);
        }
        
        .stat-icon.red {
            background: rgba(239, 68, 68, 0.1);
            color: var(--accent-danger);
        }
        
        .stat-icon.orange {
            background: rgba(245, 158, 11, 0.1);
            color: var(--accent-warning);
        }
        
        .stat-icon.purple {
            background: rgba(139, 92, 246, 0.1);
            color: var(--accent-purple);
        }
        
        .stat-icon.cyan {
            background: rgba(0, 245, 212, 0.1);
            color: var(--accent-primary);
        }
        
        .stat-value {
            font-size: 2.5rem;
            font-weight: 700;
            font-family: var(--font-mono);
            margin-bottom: 4px;
            background: linear-gradient(135deg, var(--text-primary), var(--text-secondary));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .stat-label {
            font-size: 0.85rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        /* Tabs */
        .tabs {
            display: flex;
            gap: 5px;
            background: var(--bg-secondary);
            padding: 6px;
            border-radius: var(--radius-lg);
            margin-bottom: 20px;
            border: 1px solid var(--border-color);
        }
        
        .tab {
            flex: 1;
            padding: 12px 20px;
            background: transparent;
            border: none;
            border-radius: var(--radius-md);
            color: var(--text-secondary);
            font-family: var(--font-display);
            font-size: 0.9rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
        }
        
        .tab:hover {
            color: var(--text-primary);
            background: var(--bg-tertiary);
        }
        
        .tab.active {
            background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary));
            color: var(--bg-primary);
            font-weight: 600;
        }
        
        .tab-badge {
            background: rgba(255, 255, 255, 0.2);
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 0.75rem;
            font-family: var(--font-mono);
        }
        
        .tab.active .tab-badge {
            background: rgba(0, 0, 0, 0.2);
        }
        
        /* Content Panels */
        .panel {
            display: none;
            animation: fadeIn 0.3s ease;
        }
        
        .panel.active {
            display: block;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        /* Cards */
        .card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-lg);
            overflow: hidden;
        }
        
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px 24px;
            border-bottom: 1px solid var(--border-color);
            background: var(--bg-tertiary);
        }
        
        .card-title {
            font-size: 1.1rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .card-title span {
            font-size: 1.2rem;
        }
        
        .card-body {
            padding: 0;
        }
        
        /* Table */
        .table-container {
            overflow-x: auto;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th, td {
            padding: 14px 20px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }
        
        th {
            background: var(--bg-secondary);
            font-weight: 600;
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-muted);
        }
        
        tr:hover {
            background: var(--bg-hover);
        }
        
        td {
            font-family: var(--font-mono);
            font-size: 0.85rem;
        }
        
        /* Badges */
        .badge {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 4px 10px;
            border-radius: var(--radius-sm);
            font-size: 0.75rem;
            font-weight: 500;
            font-family: var(--font-mono);
        }
        
        .badge-danger {
            background: rgba(239, 68, 68, 0.1);
            color: var(--accent-danger);
            border: 1px solid rgba(239, 68, 68, 0.2);
        }
        
        .badge-warning {
            background: rgba(245, 158, 11, 0.1);
            color: var(--accent-warning);
            border: 1px solid rgba(245, 158, 11, 0.2);
        }
        
        .badge-success {
            background: rgba(16, 185, 129, 0.1);
            color: var(--accent-success);
            border: 1px solid rgba(16, 185, 129, 0.2);
        }
        
        .badge-info {
            background: rgba(0, 187, 249, 0.1);
            color: var(--accent-secondary);
            border: 1px solid rgba(0, 187, 249, 0.2);
        }
        
        .badge-purple {
            background: rgba(139, 92, 246, 0.1);
            color: var(--accent-purple);
            border: 1px solid rgba(139, 92, 246, 0.2);
        }
        
        /* IP Display */
        .ip-display {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .ip-address {
            font-family: var(--font-mono);
            font-weight: 500;
            color: var(--accent-primary);
        }
        
        /* Progress Bars */
        .progress-bar {
            height: 6px;
            background: var(--bg-tertiary);
            border-radius: 3px;
            overflow: hidden;
            margin-top: 8px;
        }
        
        .progress-fill {
            height: 100%;
            border-radius: 3px;
            transition: width 0.5s ease;
        }
        
        .progress-fill.green { background: var(--accent-success); }
        .progress-fill.yellow { background: var(--accent-warning); }
        .progress-fill.red { background: var(--accent-danger); }
        
        /* Login Form */
        .login-container {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        .login-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-xl);
            padding: 50px;
            width: 100%;
            max-width: 420px;
            box-shadow: var(--shadow-card), var(--shadow-glow);
        }
        
        .login-header {
            text-align: center;
            margin-bottom: 40px;
        }
        
        .login-logo {
            width: 80px;
            height: 80px;
            background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary));
            border-radius: var(--radius-lg);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 40px;
            margin: 0 auto 20px;
            box-shadow: 0 0 40px rgba(0, 245, 212, 0.3);
        }
        
        .login-header h1 {
            font-size: 1.8rem;
            margin-bottom: 8px;
            background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .login-header p {
            color: var(--text-muted);
            font-size: 0.9rem;
        }
        
        .form-group {
            margin-bottom: 24px;
        }
        
        .form-label {
            display: block;
            margin-bottom: 8px;
            font-size: 0.85rem;
            font-weight: 500;
            color: var(--text-secondary);
        }
        
        .form-input {
            width: 100%;
            padding: 14px 18px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-md);
            color: var(--text-primary);
            font-family: var(--font-mono);
            font-size: 1rem;
            transition: all 0.3s ease;
        }
        
        .form-input:focus {
            outline: none;
            border-color: var(--accent-primary);
            box-shadow: 0 0 0 3px rgba(0, 245, 212, 0.1);
        }
        
        .form-input::placeholder {
            color: var(--text-muted);
        }
        
        .login-btn {
            width: 100%;
            padding: 16px;
            font-size: 1rem;
            font-weight: 600;
        }
        
        /* Alert Messages */
        .alert {
            padding: 16px 20px;
            border-radius: var(--radius-md);
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 0.9rem;
            animation: slideIn 0.3s ease;
        }
        
        @keyframes slideIn {
            from { opacity: 0; transform: translateX(-20px); }
            to { opacity: 1; transform: translateX(0); }
        }
        
        .alert-error {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.2);
            color: var(--accent-danger);
        }
        
        .alert-success {
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid rgba(16, 185, 129, 0.2);
            color: var(--accent-success);
        }
        
        .alert-info {
            background: rgba(0, 187, 249, 0.1);
            border: 1px solid rgba(0, 187, 249, 0.2);
            color: var(--accent-secondary);
        }
        
        /* Empty State */
        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: var(--text-muted);
        }
        
        .empty-state-icon {
            font-size: 4rem;
            margin-bottom: 20px;
            opacity: 0.5;
        }
        
        .empty-state h3 {
            font-size: 1.2rem;
            margin-bottom: 8px;
            color: var(--text-secondary);
        }
        
        /* Live Update Animations */
        @keyframes rowFadeIn {
            from {
                opacity: 0;
                background-color: rgba(16, 185, 129, 0.3);
                transform: translateX(-10px);
            }
            to {
                opacity: 1;
                background-color: transparent;
                transform: translateX(0);
            }
        }
        
        @keyframes rowFadeOut {
            from {
                opacity: 1;
                background-color: transparent;
                transform: translateX(0);
                max-height: 100px;
            }
            to {
                opacity: 0;
                background-color: rgba(239, 68, 68, 0.3);
                transform: translateX(10px);
                max-height: 0;
                padding: 0;
            }
        }
        
        @keyframes rowHighlight {
            0%, 100% { background-color: transparent; }
            50% { background-color: rgba(59, 130, 246, 0.15); }
        }
        
        .table tbody tr.row-new {
            animation: rowFadeIn 0.5s ease-out forwards;
        }
        
        .table tbody tr.row-removing {
            animation: rowFadeOut 0.4s ease-in forwards;
            overflow: hidden;
        }
        
        .table tbody tr.row-updated {
            animation: rowHighlight 1s ease-in-out;
        }
        
        /* Live indicator */
        .live-indicator {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            font-size: 0.75rem;
            color: var(--success);
            margin-left: 12px;
        }
        
        .live-dot {
            width: 8px;
            height: 8px;
            background: var(--success);
            border-radius: 50%;
            animation: livePulse 2s infinite;
        }
        
        @keyframes livePulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.5; transform: scale(0.8); }
        }
        
        .live-indicator.paused .live-dot {
            background: var(--text-muted);
            animation: none;
        }
        
        .live-indicator.paused {
            color: var(--text-muted);
        }

        /* Modal */
        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.7);
            backdrop-filter: blur(4px);
            display: none;
            align-items: center;
            justify-content: center;
            z-index: 1000;
            padding: 20px;
        }
        
        .modal-overlay.active {
            display: flex;
        }
        
        .modal {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-xl);
            width: 100%;
            max-width: 500px;
            box-shadow: var(--shadow-card);
            animation: modalIn 0.3s ease;
        }
        
        @keyframes modalIn {
            from { opacity: 0; transform: scale(0.9); }
            to { opacity: 1; transform: scale(1); }
        }
        
        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px 24px;
            border-bottom: 1px solid var(--border-color);
        }
        
        .modal-title {
            font-size: 1.2rem;
            font-weight: 600;
        }
        
        .modal-close {
            background: none;
            border: none;
            color: var(--text-muted);
            font-size: 1.5rem;
            cursor: pointer;
            transition: color 0.3s ease;
        }
        
        .modal-close:hover {
            color: var(--text-primary);
        }
        
        .modal-body {
            padding: 24px;
        }
        
        .modal-footer {
            display: flex;
            justify-content: flex-end;
            gap: 12px;
            padding: 16px 24px;
            border-top: 1px solid var(--border-color);
            background: var(--bg-tertiary);
        }
        
        /* Toast Notifications */
        .toast-container {
            position: fixed;
            bottom: 20px;
            right: 20px;
            z-index: 2000;
            display: flex;
            flex-direction: column;
            gap: 10px;
        }
        
        .toast {
            padding: 16px 20px;
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-md);
            box-shadow: var(--shadow-card);
            display: flex;
            align-items: center;
            gap: 12px;
            animation: toastIn 0.3s ease;
            min-width: 300px;
        }
        
        @keyframes toastIn {
            from { opacity: 0; transform: translateX(100px); }
            to { opacity: 1; transform: translateX(0); }
        }
        
        .toast.removing {
            animation: toastOut 0.3s ease forwards;
        }
        
        @keyframes toastOut {
            to { opacity: 0; transform: translateX(100px); }
        }
        
        .toast-success { border-left: 4px solid var(--accent-success); }
        .toast-error { border-left: 4px solid var(--accent-danger); }
        .toast-info { border-left: 4px solid var(--accent-secondary); }
        
        /* Refresh Indicator */
        .refresh-indicator {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 0.8rem;
            color: var(--text-muted);
        }
        
        .refresh-indicator.loading .spinner {
            animation: spin 1s linear infinite;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .header {
                flex-direction: column;
                gap: 20px;
                text-align: center;
            }
            
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            
            .tabs {
                flex-wrap: wrap;
            }
            
            .tab {
                flex: 1 1 auto;
                min-width: 120px;
            }
            
            th, td {
                padding: 10px 12px;
                font-size: 0.75rem;
            }
            
            .login-card {
                padding: 30px;
            }
        }
        
        /* Pagination */
        .pagination-wrapper {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 16px 20px;
            border-top: 1px solid var(--border-color);
            background: var(--bg-tertiary);
            flex-wrap: wrap;
            gap: 15px;
        }
        
        /* Toggle Switch */
        .toggle-switch {
            display: flex;
            align-items: center;
            gap: 8px;
            cursor: pointer;
            user-select: none;
        }
        
        .toggle-switch input {
            display: none;
        }
        
        .toggle-slider {
            width: 44px;
            height: 24px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            position: relative;
            transition: all 0.3s ease;
        }
        
        .toggle-slider::before {
            content: '';
            position: absolute;
            width: 18px;
            height: 18px;
            background: var(--text-muted);
            border-radius: 50%;
            top: 2px;
            left: 2px;
            transition: all 0.3s ease;
        }
        
        .toggle-switch input:checked + .toggle-slider {
            background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary));
            border-color: transparent;
        }
        
        .toggle-switch input:checked + .toggle-slider::before {
            transform: translateX(20px);
            background: var(--bg-primary);
        }
        
        .toggle-label {
            font-size: 0.85rem;
            font-weight: 500;
            color: var(--text-secondary);
        }
        
        .toggle-switch input:checked ~ .toggle-label {
            color: var(--accent-primary);
        }
        
        /* rDNS Badge */
        .rdns-hostname {
            font-family: var(--font-mono);
            font-size: 0.8rem;
            color: var(--accent-secondary);
            max-width: 200px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        
        .rdns-loading {
            color: var(--text-muted);
            font-style: italic;
        }
        
        .rdns-none {
            color: var(--text-muted);
            font-size: 0.8rem;
        }
        
        .pagination-info {
            font-size: 0.85rem;
            color: var(--text-muted);
            font-family: var(--font-mono);
        }
        
        .pagination-info strong {
            color: var(--accent-primary);
        }
        
        .pagination {
            display: flex;
            gap: 6px;
            align-items: center;
        }
        
        .pagination-btn {
            min-width: 36px;
            height: 36px;
            padding: 0 12px;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-sm);
            color: var(--text-secondary);
            font-family: var(--font-mono);
            font-size: 0.85rem;
            cursor: pointer;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .pagination-btn:hover:not(:disabled) {
            background: var(--bg-hover);
            border-color: var(--accent-primary);
            color: var(--text-primary);
        }
        
        .pagination-btn.active {
            background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary));
            border-color: transparent;
            color: var(--bg-primary);
            font-weight: 600;
        }
        
        .pagination-btn:disabled {
            opacity: 0.4;
            cursor: not-allowed;
        }
        
        .pagination-ellipsis {
            color: var(--text-muted);
            padding: 0 8px;
        }
        
        .per-page-select {
            padding: 8px 12px;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-sm);
            color: var(--text-primary);
            font-family: var(--font-mono);
            font-size: 0.85rem;
            cursor: pointer;
        }
        
        .per-page-select:focus {
            outline: none;
            border-color: var(--accent-primary);
        }
        
        /* Scrollbar */
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }
        
        ::-webkit-scrollbar-track {
            background: var(--bg-secondary);
        }
        
        ::-webkit-scrollbar-thumb {
            background: var(--bg-hover);
            border-radius: 4px;
        }
        
        ::-webkit-scrollbar-thumb:hover {
            background: var(--text-muted);
        }
        
        /* Action buttons in table */
        .action-buttons {
            display: flex;
            gap: 8px;
        }
        
        /* Time display */
        .time-ago {
            color: var(--text-muted);
            font-size: 0.8rem;
        }
        
        /* TTL Display */
        .ttl-display {
            display: flex;
            flex-direction: column;
            gap: 4px;
        }
        
        .ttl-time {
            font-weight: 500;
        }
        
        .ttl-remaining {
            font-size: 0.75rem;
            color: var(--text-muted);
        }
        
        /* Quick Actions Bar */
        .quick-actions {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        
        .quick-action-input {
            flex: 1;
            min-width: 200px;
            padding: 12px 16px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-md);
            color: var(--text-primary);
            font-family: var(--font-mono);
            font-size: 0.9rem;
        }
        
        .quick-action-input:focus {
            outline: none;
            border-color: var(--accent-primary);
        }
    </style>
</head>
<body>
<?php if (!isLoggedIn()): ?>
    <!-- LOGIN PAGE -->
    <div class="login-container">
        <div class="login-card">
            <div class="login-header">
                <div class="login-logo">🛡️</div>
                <h1>MurKir Security</h1>
                <p>Панель адміністратора</p>
            </div>
            
            <?php if ($message): ?>
                <div class="alert alert-<?= $messageType ?>">
                    <span><?= $messageType === 'error' ? '⚠️' : '✓' ?></span>
                    <?= htmlspecialchars($message) ?>
                </div>
            <?php endif; ?>
            
            <?php if ($redisError): ?>
                <div class="alert alert-error">
                    <span>⚠️</span>
                    Redis недоступний: <?= htmlspecialchars($redisError) ?>
                </div>
            <?php endif; ?>
            
            <form method="POST">
                <input type="hidden" name="action" value="login">
                
                <div class="form-group">
                    <label class="form-label">Пароль</label>
                    <input type="password" name="password" class="form-input" placeholder="Введіть пароль" required autofocus>
                </div>
                
                <button type="submit" class="btn btn-primary login-btn">
                    <span>🔓</span> Увійти
                </button>
            </form>
        </div>
    </div>
<?php else: ?>
    <!-- ADMIN PANEL -->
    <div class="container">
        <!-- Header -->
        <header class="header">
            <div class="logo">
                <div class="logo-icon">🛡️</div>
                <div class="logo-text">
                    <h1>MurKir Security</h1>
                    <span>Admin Panel v1.0</span>
                </div>
            </div>
            
            <div class="header-actions">
                <div class="status-badge">
                    <div class="status-dot <?= $redis ? 'online' : 'offline' ?>"></div>
                    Redis: <?= $redis ? 'Online' : 'Offline' ?>
                </div>
                
                <div class="refresh-indicator" id="refreshIndicator">
                    <span class="spinner">🔄</span>
                    <span id="refreshTimer">30s</span>
                </div>
                
                <form method="POST" style="margin: 0;">
                    <input type="hidden" name="action" value="logout">
                    <button type="submit" class="btn btn-secondary">
                        <span>🚪</span> Вийти
                    </button>
                </form>
            </div>
        </header>
        
        <?php if ($message): ?>
            <div class="alert alert-<?= $messageType ?>">
                <span><?= $messageType === 'error' ? '⚠️' : ($messageType === 'success' ? '✓' : 'ℹ️') ?></span>
                <?= htmlspecialchars($message) ?>
            </div>
        <?php endif; ?>
        
        <?php if (!$redis): ?>
            <div class="alert alert-error">
                <span>⚠️</span>
                Redis недоступний: <?= htmlspecialchars($redisError) ?>
            </div>
        <?php else: ?>
        
        <!-- Redis Memory Panel -->
        <div class="memory-panel" id="memoryPanel">
            <div class="memory-info">
                <div class="memory-icon">💾</div>
                <div class="memory-details">
                    <div class="memory-title">Redis Memory</div>
                    <div class="memory-value">
                        <span id="memoryUsed"><?= $memoryInfo['used_human'] ?? '0B' ?></span>
                        <span>/ <span id="memoryMax"><?= $memoryInfo['max_human'] ?? 'Unlimited' ?></span></span>
                    </div>
                </div>
            </div>
            
            <?php if ($memoryInfo && $memoryInfo['has_limit']): ?>
            <div class="memory-bar-container">
                <div class="memory-bar-label">
                    <span>Використано</span>
                    <span id="memoryPercent"><?= $memoryInfo['usage_percent'] ?>%</span>
                </div>
                <div class="memory-bar">
                    <div class="memory-bar-fill <?= $memoryInfo['usage_percent'] < 50 ? 'low' : ($memoryInfo['usage_percent'] < 80 ? 'medium' : 'high') ?>" 
                         id="memoryBarFill"
                         style="width: <?= $memoryInfo['usage_percent'] ?>%"></div>
                </div>
            </div>
            <?php else: ?>
            <div class="memory-bar-container">
                <div class="memory-bar-label">
                    <span>Ліміт не встановлено</span>
                    <span id="memoryPercent">—</span>
                </div>
                <div class="memory-bar">
                    <div class="memory-bar-fill low" id="memoryBarFill" style="width: 0%"></div>
                </div>
            </div>
            <?php endif; ?>
            
            <div class="memory-stats">
                <div class="memory-stat">
                    <span class="memory-stat-label">Пікове</span>
                    <span class="memory-stat-value" id="memoryPeak"><?= $memoryInfo['peak_human'] ?? '0B' ?></span>
                </div>
                <div class="memory-stat">
                    <span class="memory-stat-label">Вільно</span>
                    <span class="memory-stat-value" id="memoryFree"><?php 
                        if ($memoryInfo && $memoryInfo['has_limit']) {
                            $free = $memoryInfo['max'] - $memoryInfo['used'];
                            echo formatBytes($free);
                        } else {
                            echo '∞';
                        }
                    ?></span>
                </div>
            </div>
        </div>
        
        <!-- Stats Grid -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-icon cyan">👥</div>
                <div class="stat-value" id="statTracked"><?= number_format($stats['total_tracked'] ?? 0) ?></div>
                <div class="stat-label">Активні сесії</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-icon red">🚫</div>
                <div class="stat-value" id="statBlocked"><?= number_format($stats['total_blocked'] ?? 0) ?></div>
                <div class="stat-label">Заблоковано</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-icon orange">⚡</div>
                <div class="stat-value" id="statRateLimit"><?= number_format($stats['blocked_rate_limit'] ?? 0) ?></div>
                <div class="stat-label">Rate Limit</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-icon purple">🔄</div>
                <div class="stat-value" id="statUARotation"><?= number_format($stats['blocked_ua_rotation'] ?? 0) ?></div>
                <div class="stat-label">UA Rotation</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-icon blue">🌐</div>
                <div class="stat-value" id="statRDNS"><?= number_format($rdnsStats['cache_entries'] ?? 0) ?></div>
                <div class="stat-label">rDNS кеш</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-icon green">📊</div>
                <div class="stat-value" id="statRDNSMin"><?= number_format($rdnsStats['current_minute'] ?? 0) ?></div>
                <div class="stat-label">rDNS/хв</div>
            </div>
        </div>
        
        <!-- Quick Actions -->
        <div class="quick-actions">
            <input type="text" id="quickUnblockIP" class="quick-action-input" placeholder="Введіть IP для розблокування...">
            <button class="btn btn-primary" onclick="quickUnblock()">
                <span>🔓</span> Розблокувати IP
            </button>
            <button class="btn btn-danger" onclick="confirmClearAll()">
                <span>🗑️</span> Очистити всі блокування
            </button>
        </div>
        
        <!-- Tabs -->
        <div class="tabs">
            <button class="tab active" data-tab="blocked" onclick="switchTab('blocked')">
                <span>🚫</span> Заблоковані
                <span class="tab-badge" id="tabBlockedCount"><?= $blockedData['total'] ?></span>
            </button>
            <button class="tab" data-tab="sessions" onclick="switchTab('sessions')">
                <span>👥</span> Активні сесії
                <span class="tab-badge" id="tabSessionsCount"><?= $sessionsData['total'] ?></span>
            </button>
            <button class="tab" data-tab="logs" onclick="switchTab('logs')">
                <span>📋</span> Логи
            </button>
            <button class="tab" data-tab="searchbots" onclick="switchTab('searchbots'); loadSearchBotLog();">
                <span>🔍</span> Пошуковики
            </button>
            <button class="tab" data-tab="jschallenge" onclick="switchTab('jschallenge'); loadJSChallengeStats();">
                <span>🛡️</span> JS Challenge
            </button>
        </div>
        
        <!-- Blocked IPs Panel -->
        <div class="panel active" id="panel-blocked">
            <div class="card">
                <div class="card-header">
                    <div class="card-title">
                        <span>🚫</span> Заблоковані IP / Користувачі
                        <span class="live-indicator" id="liveIndicator">
                            <span class="live-dot"></span>
                            <span>Live Update</span>
                        </span>
                    </div>
                    <div style="display: flex; gap: 10px; align-items: center; flex-wrap: wrap;">
                        <label class="toggle-switch" title="Показувати rDNS (hostname) для IP">
                            <input type="checkbox" id="rdnsToggle" onchange="toggleRDNS()">
                            <span class="toggle-slider"></span>
                            <span class="toggle-label">rDNS</span>
                        </label>
                        <select id="filterType" class="form-input" style="width: auto; padding: 8px 12px;" onchange="loadBlockedPage(1)">
                            <option value="all">Всі типи</option>
                            <option value="rate_limit">Rate Limit</option>
                            <option value="ua_rotation">UA Rotation</option>
                        </select>
                        <select id="blockedPerPage" class="per-page-select" onchange="loadBlockedPage(1)">
                            <option value="10">10</option>
                            <option value="20" selected>20</option>
                            <option value="50">50</option>
                            <option value="100">100</option>
                        </select>
                    </div>
                </div>
                <div class="card-body">
                    <div class="table-container">
                        <table>
                            <thead>
                                <tr>
                                    <th>IP / User ID</th>
                                    <th id="rdnsHeader" style="display: none;">rDNS</th>
                                    <th>Тип</th>
                                    <th>Порушення</th>
                                    <th>Час</th>
                                    <th>Залишилось</th>
                                    <th>Дії</th>
                                </tr>
                            </thead>
                            <tbody id="blockedTable">
                                <!-- Загружается через AJAX -->
                            </tbody>
                        </table>
                    </div>
                    <div class="pagination-wrapper" id="blockedPagination">
                        <!-- Пагинация загружается через AJAX -->
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Sessions Panel -->
        <div class="panel" id="panel-sessions">
            <div class="card">
                <div class="card-header">
                    <div class="card-title">
                        <span>👥</span> Активні сесії (Rate Limit Tracking)
                    </div>
                    <div style="display: flex; gap: 10px; align-items: center;">
                        <button class="btn btn-secondary btn-sm" onclick="loadSessionsPage(currentSessionsPage)">
                            <span>🔄</span> Оновити
                        </button>
                        <select id="sessionsPerPage" class="per-page-select" onchange="loadSessionsPage(1)">
                            <option value="10">10</option>
                            <option value="20" selected>20</option>
                            <option value="50">50</option>
                            <option value="100">100</option>
                        </select>
                    </div>
                </div>
                <div class="card-body">
                    <div class="table-container">
                        <table>
                            <thead>
                                <tr>
                                    <th>IP / Session</th>
                                    <th>Запитів/хв</th>
                                    <th>Запитів/5хв</th>
                                    <th>Запитів/год</th>
                                    <th>Burst (10s)</th>
                                    <th>Останній запит</th>
                                </tr>
                            </thead>
                            <tbody id="sessionsTable">
                                <!-- Загружается через AJAX -->
                            </tbody>
                        </table>
                    </div>
                    <div class="pagination-wrapper" id="sessionsPagination">
                        <!-- Пагинация загружается через AJAX -->
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Logs Panel -->
        <div class="panel" id="panel-logs">
            <div class="card">
                <div class="card-header">
                    <div class="card-title">
                        <span>📋</span> Системні логи
                    </div>
                    <button class="btn btn-secondary btn-sm" onclick="refreshLogs()">
                        <span>🔄</span> Оновити
                    </button>
                </div>
                <div class="card-body" style="padding: 20px;">
                    <div id="logsContainer" style="font-family: var(--font-mono); font-size: 0.85rem; background: var(--bg-secondary); padding: 20px; border-radius: var(--radius-md); max-height: 500px; overflow-y: auto;">
                        <p style="color: var(--text-muted);">
                            Логи зберігаються в системному error_log.<br>
                            Для перегляду використовуйте команду:<br><br>
                            <code style="color: var(--accent-primary);">tail -f /var/log/nginx/error.log | grep "BOT PROTECTION"</code><br><br>
                            або<br><br>
                            <code style="color: var(--accent-primary);">tail -f /var/log/php-fpm/error.log | grep "BOT PROTECTION"</code>
                        </p>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Search Bots Panel -->
        <div class="panel" id="panel-searchbots">
            <div class="card">
                <div class="card-header">
                    <div class="card-title">
                        <span>🔍</span> Лог пошукових систем
                        <span id="searchBotsLastUpdate" style="font-size: 0.75rem; color: var(--text-muted); margin-left: 15px; font-weight: normal;"></span>
                    </div>
                    <div style="display: flex; gap: 10px; align-items: center;">
                        <span style="font-size: 0.8rem; color: var(--accent-success);">🔴 Live</span>
                        <select id="searchLogLines" class="form-input" style="width: auto; padding: 8px 12px;" onchange="loadSearchBotLog()">
                            <option value="50">50 записів</option>
                            <option value="100" selected>100 записів</option>
                            <option value="200">200 записів</option>
                            <option value="500">500 записів</option>
                        </select>
                        <button class="btn btn-secondary btn-sm" onclick="loadSearchBotLog()">
                            <span>🔄</span> Оновити
                        </button>
                        <button class="btn btn-danger btn-sm" onclick="confirmClearSearchLog()">
                            <span>🗑️</span> Очистити
                        </button>
                    </div>
                </div>
                <div class="card-body" style="padding: 15px;">
                    <!-- Stats -->
                    <div id="searchBotStats" class="stats-row" style="margin-bottom: 15px;">
                        <!-- Заповнюється JS -->
                    </div>
                    
                    <!-- Log Table -->
                    <div class="table-container">
                        <table class="data-table" id="searchBotTable">
                            <thead>
                                <tr>
                                    <th style="width: 140px;">Час</th>
                                    <th style="width: 110px;">Бот</th>
                                    <th style="width: 130px;">IP</th>
                                    <th style="width: 180px;">rDNS</th>
                                    <th style="width: 80px;">Метод</th>
                                    <th style="width: 150px;">Домен</th>
                                    <th>URL</th>
                                </tr>
                            </thead>
                            <tbody id="searchBotBody">
                                <tr><td colspan="7" style="text-align: center; color: var(--text-muted);">Натисніть "Оновити" для завантаження...</td></tr>
                            </tbody>
                        </table>
                    </div>
                    
                    <!-- Log info -->
                    <div id="searchLogInfo" style="margin-top: 15px; padding: 10px; background: var(--bg-secondary); border-radius: var(--radius-md); font-size: 0.85rem; color: var(--text-muted);">
                        <!-- Заповнюється JS -->
                    </div>
                </div>
            </div>
        </div>
        
        <!-- JS Challenge Panel -->
        <div class="panel" id="panel-jschallenge">
            <div class="card">
                <div class="card-header">
                    <div class="card-title">
                        <span>🛡️</span> JS Challenge Статистика
                        <span id="jscLastUpdate" style="font-size: 0.75rem; color: var(--text-muted); margin-left: 15px; font-weight: normal;"></span>
                    </div>
                    <div style="display: flex; gap: 10px; align-items: center;">
                        <span style="font-size: 0.8rem; color: var(--accent-success);">🔴 Live</span>
                        <button class="btn btn-secondary btn-sm" onclick="loadJSChallengeStats()">
                            <span>🔄</span> Оновити
                        </button>
                    </div>
                </div>
                <div class="card-body" style="padding: 20px;">
                    
                    <!-- Summary Stats -->
                    <div class="stats-row" style="margin-bottom: 30px;">
                        <div class="stat-card" style="border-left: 3px solid var(--accent-primary);">
                            <div class="stat-value" id="jsc-total-shown">-</div>
                            <div class="stat-label">Всього показано</div>
                        </div>
                        <div class="stat-card" style="border-left: 3px solid var(--accent-success);">
                            <div class="stat-value" id="jsc-total-passed">-</div>
                            <div class="stat-label">Пройдено</div>
                        </div>
						<div class="stat-card" style="border-left: 3px solid var(--accent-warning);">
                            <div class="stat-value" id="jsc-total-expired">-</div>
                            <div class="stat-label">Протерміновано</div>
                        </div>
                        <div class="stat-card" style="border-left: 3px solid var(--accent-danger);">
                            <div class="stat-value" id="jsc-total-failed">-</div>
                            <div class="stat-label">Провалено</div>
                        </div>
                        <div class="stat-card" style="border-left: 3px solid var(--accent-secondary);">
                            <div class="stat-value" id="jsc-success-rate">-</div>
                            <div class="stat-label">% успіху</div>
                        </div>
                    </div>
                    
                    <!-- Today Stats -->
                    <div class="card" style="background: var(--bg-secondary); padding: 15px; margin-bottom: 20px;">
                        <h3 style="margin-bottom: 15px; font-size: 1rem; color: var(--accent-primary);">📅 Сьогодні</h3>
                        <div class="stats-row">
                            <div class="stat-card" style="background: var(--bg-tertiary);">
                                <div class="stat-value" id="jsc-today-shown">-</div>
                                <div class="stat-label">Показано</div>
                            </div>
                            <div class="stat-card" style="background: var(--bg-tertiary);">
                                <div class="stat-value" id="jsc-today-passed">-</div>
                                <div class="stat-label">Пройдено</div>
                            </div>
                            <div class="stat-card" style="background: var(--bg-tertiary);">
                                <div class="stat-value" id="jsc-today-failed">-</div>
                                <div class="stat-label">Провалено</div>
                            </div>
                            <div class="stat-card" style="background: var(--bg-tertiary);">
                                <div class="stat-value" id="jsc-today-success-rate">-</div>
                                <div class="stat-label">% успіху</div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Hourly Chart -->
                    <div class="card" style="background: var(--bg-secondary); padding: 15px; margin-bottom: 20px;">
                        <h3 style="margin-bottom: 15px; font-size: 1rem; color: var(--accent-primary);">📊 Погодинна активність (останні 24 години)</h3>
                        <div id="jsc-hourly-chart" style="height: 300px; overflow-x: auto;">
                            <div style="text-align: center; padding: 80px 20px; color: var(--text-muted);">
                                Завантаження графіку...
                            </div>
                        </div>
                    </div>
                    
                    <!-- Recent Logs -->
                    <div class="card" style="background: var(--bg-secondary); padding: 15px;">
                        <h3 style="margin-bottom: 15px; font-size: 1rem; color: var(--accent-primary);">📋 Останні події</h3>
                        
                        <!-- Tabs for log types -->
                        <div style="display: flex; gap: 10px; margin-bottom: 15px; border-bottom: 1px solid var(--border-color); padding-bottom: 10px;">
                            <button class="btn btn-sm" id="jsc-log-tab-shown" onclick="switchJSCLogTab('shown')" style="background: var(--accent-primary); color: var(--bg-primary);">
                                🛡️ Показано
                            </button>
                            <button class="btn btn-sm" id="jsc-log-tab-passed" onclick="switchJSCLogTab('passed')" style="background: var(--bg-tertiary);">
                                ✅ Пройдено
                            </button>
							<button class="btn btn-sm" id="jsc-log-tab-expired" onclick="switchJSCLogTab('expired')" style="background: var(--bg-tertiary);">
                                ⏱️ Протерміновано
                            </button>
                            <button class="btn btn-sm" id="jsc-log-tab-failed" onclick="switchJSCLogTab('failed')" style="background: var(--bg-tertiary);">
                                ❌ Провалено
                            </button>
                        </div>
                        
                        <!-- Log Tables -->
                        <div class="table-container">
                            <table class="data-table" id="jsc-log-table-shown" style="display: table;">
                                <thead>
                                    <tr>
                                        <th style="width: 150px;">Час</th>
                                        <th style="width: 130px;">IP</th>
                                        <th style="width: 200px;">rDNS</th>
                                        <th>User Agent</th>
                                        <th style="width: 70px; text-align: center;">Статус</th>
                                    </tr>
                                </thead>
                                <tbody id="jsc-log-body-shown">
                                    <tr><td colspan="5" style="text-align: center; color: var(--text-muted);">Немає даних</td></tr>
                                </tbody>
                            </table>
                            
                            <table class="data-table" id="jsc-log-table-passed" style="display: none;">
                                <thead>
                                    <tr>
                                        <th style="width: 150px;">Час</th>
                                        <th style="width: 130px;">IP</th>
                                        <th style="width: 200px;">rDNS</th>
                                        <th>User Agent</th>
                                    </tr>
                                </thead>
                                <tbody id="jsc-log-body-passed">
                                    <tr><td colspan="4" style="text-align: center; color: var(--text-muted);">Немає даних</td></tr>
                                </tbody>
                            </table>
                            
                            <table class="data-table" id="jsc-log-table-failed" style="display: none;">
                                <thead>
                                    <tr>
                                        <th style="width: 150px;">Час</th>
                                        <th style="width: 130px;">IP</th>
                                        <th style="width: 200px;">rDNS</th>
                                        <th>User Agent</th>
                                    </tr>
                                </thead>
                                <tbody id="jsc-log-body-failed">
                                    <tr><td colspan="4" style="text-align: center; color: var(--text-muted);">Немає даних</td></tr>
                                </tbody>
                            </table>
                            
                            <table class="data-table" id="jsc-log-table-expired" style="display: none;">
                                <thead>
                                    <tr>
                                        <th style="width: 150px;">Час</th>
                                        <th style="width: 130px;">IP</th>
                                        <th style="width: 200px;">rDNS</th>
                                        <th>User Agent</th>
                                    </tr>
                                </thead>
                                <tbody id="jsc-log-body-expired">
                                    <tr><td colspan="4" style="text-align: center; color: var(--text-muted);">Немає даних</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                    
                </div>
            </div>
        </div>
        
        <?php endif; ?>
    </div>
    
    <!-- Toast Container -->
    <div class="toast-container" id="toastContainer"></div>
    
    <!-- Confirm Modal -->
    <div class="modal-overlay" id="confirmModal">
        <div class="modal">
            <div class="modal-header">
                <h3 class="modal-title" id="confirmModalTitle">Підтвердження</h3>
                <button class="modal-close" onclick="closeModal()">&times;</button>
            </div>
            <div class="modal-body">
                <p id="confirmModalMessage">Ви впевнені?</p>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeModal()">Скасувати</button>
                <button class="btn btn-danger" id="confirmModalBtn" onclick="confirmAction()">Підтвердити</button>
            </div>
        </div>
    </div>
    
    <script>
        // Configuration
        const REFRESH_INTERVAL = <?= $config['refresh_interval'] ?> * 1000;
        const DEFAULT_PER_PAGE = <?= $config['items_per_page'] ?>;
        let refreshTimer = <?= $config['refresh_interval'] ?>;
        let confirmCallback = null;
        
        // Pagination State
        let currentBlockedPage = 1;
        let currentSessionsPage = 1;
        
        // Tab Switching
        function switchTab(tabName) {
            document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
            document.querySelectorAll('.panel').forEach(panel => panel.classList.remove('active'));
            
            document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
            document.getElementById(`panel-${tabName}`).classList.add('active');
            
            // v1.4: Автозавантаження даних при перемиканні на вкладку
            if (tabName === 'searchbots') {
                loadSearchBotLog();
            } else if (tabName === 'jschallenge') {
                loadJSChallengeStats();
            }
        }
        
        // Toast Notifications
        function showToast(message, type = 'info') {
            const container = document.getElementById('toastContainer');
            const toast = document.createElement('div');
            toast.className = `toast toast-${type}`;
            toast.innerHTML = `
                <span>${type === 'success' ? '✓' : type === 'error' ? '⚠️' : 'ℹ️'}</span>
                <span>${message}</span>
            `;
            container.appendChild(toast);
            
            setTimeout(() => {
                toast.classList.add('removing');
                setTimeout(() => toast.remove(), 300);
            }, 4000);
        }
        
        // Modal
        function showModal(title, message, callback) {
            document.getElementById('confirmModalTitle').textContent = title;
            document.getElementById('confirmModalMessage').textContent = message;
            document.getElementById('confirmModal').classList.add('active');
            confirmCallback = callback;
        }
        
        function closeModal() {
            document.getElementById('confirmModal').classList.remove('active');
            confirmCallback = null;
        }
        
        function confirmAction() {
            if (confirmCallback) {
                confirmCallback();
            }
            closeModal();
        }
        
        // API Calls
        async function apiCall(action, params = {}) {
            const url = new URL(window.location.href);
            url.searchParams.set('api', action);
            
            for (const [key, value] of Object.entries(params)) {
                url.searchParams.set(key, value);
            }
            
            try {
                const response = await fetch(url);
                return await response.json();
            } catch (error) {
                console.error('API Error:', error);
                showToast('Помилка з\'єднання з сервером', 'error');
                return null;
            }
        }
        
        // ==================== BLOCKED TABLE WITH PAGINATION ====================
        
        let rdnsEnabled = false;
        let currentBlockedData = []; // Store current items for comparison
        let liveUpdateEnabled = true;
        let liveUpdateInterval = null;
        
        // Toggle live updates
        function toggleLiveUpdate(enabled) {
            liveUpdateEnabled = enabled;
            const indicator = document.getElementById('liveIndicator');
            if (indicator) {
                indicator.classList.toggle('paused', !enabled);
            }
        }
        
        function toggleRDNS() {
            rdnsEnabled = document.getElementById('rdnsToggle').checked;
            const rdnsHeader = document.getElementById('rdnsHeader');
            
            if (rdnsEnabled) {
                rdnsHeader.style.display = '';
            } else {
                rdnsHeader.style.display = 'none';
            }
            
            // Перезагружаем таблицу
            loadBlockedPage(currentBlockedPage);
        }
        
        async function loadBlockedPage(page = 1, isLiveUpdate = false) {
            currentBlockedPage = page;
            const type = document.getElementById('filterType').value;
            const perPage = document.getElementById('blockedPerPage').value;
            
            const params = { type, page, per_page: perPage };
            if (rdnsEnabled) {
                params.resolve_rdns = '1';
            }
            
            const data = await apiCall('blocked', params);
            
            if (!data) return;
            
            // Live update with animation or full render
            if (isLiveUpdate) {
                smartUpdateBlockedTable(data);
            } else {
                renderBlockedTable(data);
            }
            
            renderBlockedPagination(data);
            
            // Update tab badge
            document.getElementById('tabBlockedCount').textContent = data.total || 0;
        }
        
        function renderBlockedTable(data) {
            const tbody = document.getElementById('blockedTable');
            const items = data.items || [];
            const showRdns = rdnsEnabled;
            const colspan = showRdns ? 7 : 6;
            
            // Update stored data for live updates
            currentBlockedData = items;
            
            if (items.length === 0) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="${colspan}">
                            <div class="empty-state">
                                <div class="empty-state-icon">✨</div>
                                <h3>Немає заблокованих</h3>
                                <p>Всі IP та користувачі активні</p>
                            </div>
                        </td>
                    </tr>
                `;
                return;
            }
            
            tbody.innerHTML = items.map(item => {
                const itemKey = item.key || (item.ip + ':' + item.type);
                return `
                <tr data-type="${item.type}" data-ip="${escapeHtml(item.ip)}" data-key="${escapeHtml(itemKey)}">
                    <td>
                        <div class="ip-display">
                            <span class="ip-address">${escapeHtml(item.ip)}</span>
                            ${item.has_cookie ? '<span class="badge badge-info">🍪 Cookie</span>' : ''}
                        </div>
                        ${item.user_id ? `<div class="time-ago">${escapeHtml(item.user_id.substring(0, 30))}...</div>` : ''}
                    </td>
                    ${showRdns ? `
                    <td>
                        ${item.rdns 
                            ? `<span class="rdns-hostname" title="${escapeHtml(item.rdns)}">${escapeHtml(item.rdns)}</span>`
                            : '<span class="rdns-none">—</span>'}
                    </td>
                    ` : ''}
                    <td>
                        ${item.type === 'rate_limit' 
                            ? '<span class="badge badge-danger">⚡ Rate Limit</span>'
                            : '<span class="badge badge-purple">🔄 UA Rotation</span>'}
                    </td>
                    <td>
                        ${(item.violations || []).map(v => `<span class="badge badge-warning">${escapeHtml(v)}</span>`).join(' ')}
                        ${item.type === 'ua_rotation' ? `<div class="time-ago">UA 5m: ${item.unique_ua_5min || 0}, 1h: ${item.unique_ua_hour || 0}</div>` : ''}
                    </td>
                    <td>${item.time ? formatTime(item.time) : 'N/A'}</td>
                    <td>
                        <div class="ttl-display">
                            <span class="ttl-time">${formatTTL(item.ttl)}</span>
                            <span class="ttl-remaining">${escapeHtml(item.expires)}</span>
                        </div>
                    </td>
                    <td>
                        <div class="action-buttons">
                            <button class="btn btn-danger btn-sm" onclick="unblockIP('${escapeHtml(item.ip)}')">
                                🔓 Розблокувати
                            </button>
                        </div>
                    </td>
                </tr>
            `}).join('');
        }
        
        function renderBlockedPagination(data) {
            const container = document.getElementById('blockedPagination');
            const { page, pages, total, per_page } = data;
            
            if (total === 0) {
                container.innerHTML = '';
                return;
            }
            
            const start = (page - 1) * per_page + 1;
            const end = Math.min(page * per_page, total);
            
            container.innerHTML = `
                <div class="pagination-info">
                    Показано <strong>${start}-${end}</strong> з <strong>${total}</strong>
                </div>
                <div class="pagination">
                    ${renderPaginationButtons(page, pages, 'loadBlockedPage')}
                </div>
            `;
        }
        
        // ==================== SMART LIVE UPDATE ====================
        
        function getItemKey(item) {
            // Use Redis key which is guaranteed unique
            return item.key || (item.ip + ':' + item.type);
        }
        
        function smartUpdateBlockedTable(data) {
            const tbody = document.getElementById('blockedTable');
            const newItems = data.items || [];
            const showRdns = rdnsEnabled;
            const colspan = showRdns ? 7 : 6;
            
            // Create sets for comparison
            const oldKeys = new Set(currentBlockedData.map(item => getItemKey(item)));
            const newKeys = new Set(newItems.map(item => getItemKey(item)));
            
            // Find what changed
            const added = newItems.filter(item => !oldKeys.has(getItemKey(item)));
            const removed = currentBlockedData.filter(item => !newKeys.has(getItemKey(item)));
            
            // If nothing changed, just update TTL values
            if (added.length === 0 && removed.length === 0) {
                // But if count differs, force full re-render (duplicate keys issue)
                if (currentBlockedData.length !== newItems.length) {
                    renderBlockedTable(data);
                    return;
                }
                
                // Update TTL for existing items
                newItems.forEach(item => {
                    const key = getItemKey(item);
                    const row = Array.from(tbody.querySelectorAll('tr[data-key]')).find(r => r.dataset.key === key);
                    if (row) {
                        const ttlTime = row.querySelector('.ttl-time');
                        const ttlRemaining = row.querySelector('.ttl-remaining');
                        if (ttlTime) ttlTime.textContent = formatTTL(item.ttl);
                        if (ttlRemaining) ttlRemaining.textContent = item.expires || '';
                    }
                });
                currentBlockedData = newItems;
                return;
            }
            
            // Something changed - animate removed rows first
            removed.forEach(item => {
                const key = getItemKey(item);
                const row = Array.from(tbody.querySelectorAll('tr[data-key]')).find(r => r.dataset.key === key);
                if (row) {
                    row.classList.add('row-removing');
                }
            });
            
            // After removal animation, re-render and animate new rows
            setTimeout(() => {
                // Store which keys are new
                const addedKeys = new Set(added.map(item => getItemKey(item)));
                
                // Re-render table
                renderBlockedTable(data);
                
                // Animate new rows
                newItems.forEach(item => {
                    if (addedKeys.has(getItemKey(item))) {
                        const key = getItemKey(item);
                        const row = Array.from(tbody.querySelectorAll('tr[data-key]')).find(r => r.dataset.key === key);
                        if (row) {
                            row.classList.add('row-new');
                        }
                    }
                });
            }, removed.length > 0 ? 400 : 0);
        }
        
        // ==================== SESSIONS TABLE WITH PAGINATION ====================
        
        async function loadSessionsPage(page = 1) {
            currentSessionsPage = page;
            const perPage = document.getElementById('sessionsPerPage').value;
            
            const data = await apiCall('sessions', { page, per_page: perPage });
            
            if (!data) return;
            
            renderSessionsTable(data);
            renderSessionsPagination(data);
            
            // Update tab badge
            document.getElementById('tabSessionsCount').textContent = data.total || 0;
        }
        
        function renderSessionsTable(data) {
            const tbody = document.getElementById('sessionsTable');
            const items = data.items || [];
            
            if (items.length === 0) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="6">
                            <div class="empty-state">
                                <div class="empty-state-icon">👻</div>
                                <h3>Немає активних сесій</h3>
                                <p>Поки що немає відстежуваних користувачів</p>
                            </div>
                        </td>
                    </tr>
                `;
                return;
            }
            
            tbody.innerHTML = items.map(session => `
                <tr>
                    <td>
                        ${session.ip ? `
                            <div class="ip-display">
                                <span class="ip-address">${escapeHtml(session.ip)}</span>
                                ${session.session_type === 'user' 
                                    ? '<span class="badge badge-info">👤 User</span>'
                                    : '<span class="badge badge-purple">🌐 IP</span>'}
                            </div>
                        ` : '<span class="badge badge-info">👤 User</span>'}
                        <div class="time-ago" title="${escapeHtml(session.key || '')}">
                            ${escapeHtml((session.key_hash || '').substring(0, 16))}...
                        </div>
                    </td>
                    <td>
                        <span class="${session.requests_minute > 50 ? 'badge badge-warning' : ''}">
                            ${session.requests_minute}/60
                        </span>
                        <div class="progress-bar">
                            <div class="progress-fill ${getProgressColorJS(session.requests_minute, 60)}" 
                                 style="width: ${Math.min(100, (session.requests_minute / 60) * 100)}%"></div>
                        </div>
                    </td>
                    <td>
                        <span class="${session.requests_5min > 180 ? 'badge badge-warning' : ''}">
                            ${session.requests_5min}/200
                        </span>
                        <div class="progress-bar">
                            <div class="progress-fill ${getProgressColorJS(session.requests_5min, 200)}" 
                                 style="width: ${Math.min(100, (session.requests_5min / 200) * 100)}%"></div>
                        </div>
                    </td>
                    <td>
                        <span class="${session.requests_hour > 450 ? 'badge badge-warning' : ''}">
                            ${session.requests_hour}/500
                        </span>
                        <div class="progress-bar">
                            <div class="progress-fill ${getProgressColorJS(session.requests_hour, 500)}" 
                                 style="width: ${Math.min(100, (session.requests_hour / 500) * 100)}%"></div>
                        </div>
                    </td>
                    <td>
                        <span class="${session.burst > 15 ? 'badge badge-danger' : ''}">
                            ${session.burst}/20
                        </span>
                        <div class="progress-bar">
                            <div class="progress-fill ${getProgressColorJS(session.burst, 20)}" 
                                 style="width: ${Math.min(100, (session.burst / 20) * 100)}%"></div>
                        </div>
                    </td>
                    <td>${escapeHtml(session.last_request || 'N/A')}</td>
                </tr>
            `).join('');
        }
        
        function renderSessionsPagination(data) {
            const container = document.getElementById('sessionsPagination');
            const { page, pages, total, per_page } = data;
            
            if (total === 0) {
                container.innerHTML = '';
                return;
            }
            
            const start = (page - 1) * per_page + 1;
            const end = Math.min(page * per_page, total);
            
            container.innerHTML = `
                <div class="pagination-info">
                    Показано <strong>${start}-${end}</strong> з <strong>${total}</strong>
                </div>
                <div class="pagination">
                    ${renderPaginationButtons(page, pages, 'loadSessionsPage')}
                </div>
            `;
        }
        
        // ==================== PAGINATION HELPER ====================
        
        function renderPaginationButtons(currentPage, totalPages, callback) {
            if (totalPages <= 1) return '';
            
            let html = '';
            
            // Previous button
            html += `<button class="pagination-btn" onclick="${callback}(${currentPage - 1})" ${currentPage <= 1 ? 'disabled' : ''}>◀</button>`;
            
            // Page numbers with ellipsis
            const pages = getPaginationRange(currentPage, totalPages);
            
            pages.forEach((p, idx) => {
                if (p === '...') {
                    html += `<span class="pagination-ellipsis">...</span>`;
                } else {
                    html += `<button class="pagination-btn ${p === currentPage ? 'active' : ''}" onclick="${callback}(${p})">${p}</button>`;
                }
            });
            
            // Next button
            html += `<button class="pagination-btn" onclick="${callback}(${currentPage + 1})" ${currentPage >= totalPages ? 'disabled' : ''}>▶</button>`;
            
            return html;
        }
        
        function getPaginationRange(current, total) {
            if (total <= 7) {
                return Array.from({ length: total }, (_, i) => i + 1);
            }
            
            if (current <= 3) {
                return [1, 2, 3, 4, '...', total];
            }
            
            if (current >= total - 2) {
                return [1, '...', total - 3, total - 2, total - 1, total];
            }
            
            return [1, '...', current - 1, current, current + 1, '...', total];
        }
        
        // ==================== ACTIONS ====================
        
        async function unblockIP(ip) {
            showModal('Розблокування IP', `Розблокувати IP ${ip}?`, async () => {
                const result = await apiCall('unblock', { ip });
                if (result && result.success) {
                    showToast(result.message, 'success');
                    await loadBlockedPage(currentBlockedPage);
                    refreshData();
                } else {
                    showToast(result?.message || 'Помилка', 'error');
                }
            });
        }
        
        async function quickUnblock() {
            const ip = document.getElementById('quickUnblockIP').value.trim();
            if (!ip) {
                showToast('Введіть IP адресу', 'error');
                return;
            }
            
            const result = await apiCall('unblock', { ip });
            if (result && result.success) {
                showToast(result.message, 'success');
                document.getElementById('quickUnblockIP').value = '';
                await loadBlockedPage(1);
                refreshData();
            } else {
                showToast(result?.message || 'Помилка', 'error');
            }
        }
        
        function confirmClearAll() {
            showModal(
                'Очистити всі блокування',
                'Ви впевнені що хочете розблокувати ВСІ IP? Це дія не може бути скасована.',
                async () => {
                    const result = await apiCall('clear_all');
                    if (result && result.success) {
                        showToast(result.message, 'success');
                        await loadBlockedPage(1);
                        refreshData();
                    } else {
                        showToast(result?.message || 'Помилка', 'error');
                    }
                }
            );
        }
        
        // ==================== HELPERS ====================
        
        function escapeHtml(text) {
            if (!text) return '';
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        function formatTime(timestamp) {
            const date = new Date(timestamp * 1000);
            return date.toLocaleDateString('uk-UA', { day: '2-digit', month: '2-digit' }) + ' ' +
                   date.toLocaleTimeString('uk-UA', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        }
        
        function formatTTL(seconds) {
            if (seconds < 0) return 'Permanent';
            if (seconds < 60) return seconds + 's';
            if (seconds < 3600) return Math.floor(seconds / 60) + 'хв';
            return Math.floor(seconds / 3600) + 'год ' + Math.floor((seconds % 3600) / 60) + 'хв';
        }
        
        function getProgressColorJS(value, max) {
            const percent = (value / max) * 100;
            if (percent < 50) return 'green';
            if (percent < 80) return 'yellow';
            return 'red';
        }
        
        // ==================== REFRESH DATA ====================
        
        async function refreshData() {
            const indicator = document.getElementById('refreshIndicator');
            indicator.classList.add('loading');
            
            // Stats
            const stats = await apiCall('stats');
            if (stats) {
                document.getElementById('statTracked').textContent = stats.total_tracked?.toLocaleString() || '0';
                document.getElementById('statBlocked').textContent = stats.total_blocked?.toLocaleString() || '0';
                document.getElementById('statRateLimit').textContent = stats.blocked_rate_limit?.toLocaleString() || '0';
                document.getElementById('statUARotation').textContent = stats.blocked_ua_rotation?.toLocaleString() || '0';
            }
            
            // Memory
            const memory = await apiCall('memory');
            if (memory) {
                updateMemoryDisplay(memory);
            }
            
            // rDNS
            const rdns = await apiCall('rdns');
            if (rdns) {
                document.getElementById('statRDNS').textContent = rdns.cache_entries?.toLocaleString() || '0';
                document.getElementById('statRDNSMin').textContent = rdns.current_minute?.toLocaleString() || '0';
            }
            
            // Live update blocked table if panel is visible
            if (liveUpdateEnabled && document.getElementById('panel-blocked')?.classList.contains('active')) {
                await loadBlockedPage(currentBlockedPage, true);
            } else {
                // Just update totals
                const blocked = await apiCall('blocked', { page: 1, per_page: 1 });
                if (blocked) {
                    document.getElementById('tabBlockedCount').textContent = blocked.total || 0;
                }
            }
            
            // Live update sessions table if panel is visible
            if (liveUpdateEnabled && document.getElementById('panel-sessions')?.classList.contains('active')) {
                await loadSessionsPage(currentSessionsPage);
            } else {
                const sessions = await apiCall('sessions', { page: 1, per_page: 1 });
                if (sessions) {
                    document.getElementById('tabSessionsCount').textContent = sessions.total || 0;
                }
            }
            
            // v1.4: Live update Search Bots log if panel is visible
            if (liveUpdateEnabled && document.getElementById('panel-searchbots')?.classList.contains('active')) {
                await loadSearchBotLog();
            }
            
            // v1.4: Live update JS Challenge stats if panel is visible
            if (liveUpdateEnabled && document.getElementById('panel-jschallenge')?.classList.contains('active')) {
                await loadJSChallengeStats();
            }
            
            indicator.classList.remove('loading');
            refreshTimer = <?= $config['refresh_interval'] ?>;
        }
        
        function updateMemoryDisplay(memory) {
            document.getElementById('memoryUsed').textContent = memory.used_human || '0B';
            document.getElementById('memoryMax').textContent = memory.max_human || 'Unlimited';
            document.getElementById('memoryPeak').textContent = memory.peak_human || '0B';
            
            const percentEl = document.getElementById('memoryPercent');
            const barFill = document.getElementById('memoryBarFill');
            const freeEl = document.getElementById('memoryFree');
            
            if (memory.has_limit) {
                const percent = memory.usage_percent || 0;
                percentEl.textContent = percent + '%';
                barFill.style.width = percent + '%';
                
                // Update color class
                barFill.className = 'memory-bar-fill';
                if (percent < 50) {
                    barFill.classList.add('low');
                } else if (percent < 80) {
                    barFill.classList.add('medium');
                } else {
                    barFill.classList.add('high');
                }
                
                // Calculate free
                const free = memory.max - memory.used;
                freeEl.textContent = formatBytesJS(free);
            } else {
                percentEl.textContent = '—';
                barFill.style.width = '0%';
                freeEl.textContent = '∞';
            }
        }
        
        function formatBytesJS(bytes, precision = 2) {
            if (bytes === 0) return '0B';
            const units = ['B', 'KB', 'MB', 'GB', 'TB'];
            const pow = Math.floor(Math.log(bytes) / Math.log(1024));
            const value = bytes / Math.pow(1024, pow);
            return value.toFixed(precision) + units[pow];
        }
        
        function updateRefreshTimer() {
            refreshTimer--;
            document.getElementById('refreshTimer').textContent = refreshTimer + 's';
            
            if (refreshTimer <= 0) {
                refreshData();
            }
        }
        
        function refreshLogs() {
            showToast('Логи доступні через системний error_log', 'info');
        }
        
        // ==================== SEARCH BOTS LOG ====================
        
        async function loadSearchBotLog() {
            const lines = document.getElementById('searchLogLines')?.value || 100;
            
            // v1.3: Завантажуємо статистику з Redis
            const redisStats = await apiCall('search_stats');
            // Також завантажуємо з файлу (fallback)
            const fileResult = await apiCall('search_log', { lines });
            
            const tbody = document.getElementById('searchBotBody');
            const statsDiv = document.getElementById('searchBotStats');
            const infoDiv = document.getElementById('searchLogInfo');
            
            // Кольори для ботів
            const botColors = {
                'google': '#4285F4',
                'yandex': '#FF0000',
                'bing': '#00809D',
                'duckduckgo': '#DE5833',
                'baidu': '#2319DC',
                'facebook': '#1877F2',
                'apple': '#555555',
                'yahoo': '#720e9e',
                'test': '#00FF00',
                'other': '#6c757d'
            };
            
            const botIcons = {
                'google': '🔵',
                'yandex': '🔴',
                'bing': '🟢',
                'duckduckgo': '🟠',
                'baidu': '🟣',
                'facebook': '🔷',
                'apple': '🍎',
                'yahoo': '🟪',
                'test': '🧪',
                'other': '🤖'
            };
            
            let statsHtml = '';
            
            // v1.3: Статистика з Redis (пріоритет)
            if (redisStats && redisStats.stats && Object.keys(redisStats.stats).length > 0) {
                // Загальна статистика
                statsHtml += `
                    <div class="stat-card" style="border-left: 3px solid var(--accent-primary); background: linear-gradient(135deg, var(--bg-secondary), var(--bg-tertiary));">
                        <div class="stat-value">${redisStats.total_visits || 0}</div>
                        <div class="stat-label">📊 Всього візитів</div>
                    </div>
                    <div class="stat-card" style="border-left: 3px solid var(--accent-success);">
                        <div class="stat-value">${redisStats.today_visits || 0}</div>
                        <div class="stat-label">📅 Сьогодні</div>
                    </div>
                `;
                
                // Боти
                for (const [bot, count] of Object.entries(redisStats.stats)) {
                    const color = botColors[bot.toLowerCase()] || '#6c757d';
                    const icon = botIcons[bot.toLowerCase()] || '🤖';
                    statsHtml += `
                        <div class="stat-card" style="border-left: 3px solid ${color};">
                            <div class="stat-value">${count}</div>
                            <div class="stat-label">${icon} ${escapeHtml(bot)}</div>
                        </div>
                    `;
                }
                
                // Методи верифікації
                if (redisStats.methods && Object.keys(redisStats.methods).length > 0) {
                    statsHtml += '<div style="width: 100%; border-top: 1px solid var(--border-color); margin: 10px 0; padding-top: 10px;"><strong style="color: var(--text-muted); font-size: 0.8rem;">🔐 Методи верифікації:</strong></div>';
                    for (const [method, count] of Object.entries(redisStats.methods)) {
                        const methodColor = method === 'IP' || method === 'IP-CACHED' ? '#17a2b8' : 
                                           method === 'RDNS' ? '#28a745' : '#6c757d';
                        statsHtml += `
                            <div class="stat-card" style="border-left: 3px solid ${methodColor};">
                                <div class="stat-value">${count}</div>
                                <div class="stat-label" style="font-size: 0.75rem;">${escapeHtml(method)}</div>
                            </div>
                        `;
                    }
                }
                
                // Хости
                if (redisStats.hosts && Object.keys(redisStats.hosts).length > 0) {
                    statsHtml += '<div style="width: 100%; border-top: 1px solid var(--border-color); margin: 10px 0; padding-top: 10px;"><strong style="color: var(--text-muted); font-size: 0.8rem;">🌐 Домени:</strong></div>';
                    for (const [host, count] of Object.entries(redisStats.hosts)) {
                        statsHtml += `
                            <div class="stat-card" style="border-left: 3px solid #20c997;">
                                <div class="stat-value">${count}</div>
                                <div class="stat-label" style="font-size: 0.75rem;">${escapeHtml(host)}</div>
                            </div>
                        `;
                    }
                }
            } else if (fileResult && fileResult.stats && Object.keys(fileResult.stats).length > 0) {
                // Fallback: статистика з файлу
                for (const [bot, count] of Object.entries(fileResult.stats)) {
                    const color = botColors[bot.toLowerCase()] || '#6c757d';
                    statsHtml += `
                        <div class="stat-card" style="border-left: 3px solid ${color};">
                            <div class="stat-value">${count}</div>
                            <div class="stat-label">${escapeHtml(bot)}</div>
                        </div>
                    `;
                }
            }
            
            statsDiv.innerHTML = statsHtml || '<div style="color: var(--text-muted);">📭 Немає статистики. Дані з\'являться після першого візиту бота.</div>';
            
            // Таблиця логу - спочатку з Redis, потім з файлу
            let logEntries = [];
            
            if (redisStats && redisStats.lines && redisStats.lines.length > 0) {
                logEntries = redisStats.lines;
            } else if (fileResult && fileResult.lines && fileResult.lines.length > 0) {
                logEntries = fileResult.lines;
            }
            
            if (logEntries.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-muted);">📭 Лог порожній. Дані з\'являться після першого візиту бота.</td></tr>';
            } else {
                tbody.innerHTML = logEntries.map(entry => {
                    const engine = (entry.engine || entry.bot || 'unknown').toLowerCase();
                    const icon = botIcons[engine] || '🤖';
                    const method = entry.method || 'unknown';
                    const methodBadge = method.toUpperCase().includes('RDNS') ? 
                        '<span style="background: #28a745; color: white; padding: 2px 6px; border-radius: 3px; font-size: 0.75rem;">rDNS</span>' :
                        method.toUpperCase().includes('IP') ?
                        '<span style="background: #17a2b8; color: white; padding: 2px 6px; border-radius: 3px; font-size: 0.75rem;">' + escapeHtml(method) + '</span>' :
                        '<span style="background: #6c757d; color: white; padding: 2px 6px; border-radius: 3px; font-size: 0.75rem;">' + escapeHtml(method) + '</span>';
                    
                    // v1.4: rDNS відображення
                    const rdns = entry.rdns || null;
                    const rdnsHtml = rdns 
                        ? `<span style="font-size: 0.8rem; color: var(--accent-success);" title="${escapeHtml(rdns)}">${escapeHtml(rdns.length > 55 ? rdns.substring(0, 55) + '...' : rdns)}</span>`
                        : '<span style="color: var(--text-muted); font-size: 0.8rem;">—</span>';
                    
                    return `
                        <tr>
                            <td style="font-family: var(--font-mono); font-size: 0.85rem;">${escapeHtml(entry.time)}</td>
                            <td>${icon} ${escapeHtml(entry.engine || entry.bot || '-')}</td>
                            <td style="font-family: var(--font-mono);">${escapeHtml(entry.ip)}</td>
                            <td>${rdnsHtml}</td>
                            <td>${methodBadge}</td>
                            <td style="font-size: 0.85rem; color: var(--accent-primary);">${escapeHtml(entry.host || '-')}</td>
                            <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(entry.url || '')}">${escapeHtml(entry.url || '-')}</td>
                        </tr>
                    `;
                }).join('');
            }
            
            // Інформація
            let infoHtml = '';
            if (redisStats && redisStats.total_visits > 0) {
                infoHtml = `
                    💾 Джерело: <strong>Redis</strong> | 
                    📊 Всього в базі: <strong>${redisStats.total_visits}</strong> візитів | 
                    📝 Останніх записів: <strong>${logEntries.length}</strong>
                `;
            } else if (fileResult && fileResult.exists) {
                const sizeKB = (fileResult.size / 1024).toFixed(2);
                infoHtml = `
                    📁 Джерело: Файл <code>${escapeHtml(fileResult.file)}</code> | 
                    📊 Розмір: <strong>${sizeKB} KB</strong> | 
                    📝 Всього записів: <strong>${fileResult.total_lines}</strong>
                `;
            } else {
                infoHtml = '📭 Статистика поки відсутня';
            }
            infoDiv.innerHTML = infoHtml;
            
            // v1.4: Оновлюємо timestamp
            const lastUpdateEl = document.getElementById('searchBotsLastUpdate');
            if (lastUpdateEl) {
                lastUpdateEl.textContent = '⏱ ' + new Date().toLocaleTimeString('uk-UA');
            }
        }
        
        function confirmClearSearchLog() {
            showModal(
                'Очистити статистику пошуковиків',
                'Ви впевнені що хочете очистити ВСЮ статистику пошукових систем (Redis + файл)? Цю дію не можна скасувати.',
                async () => {
                    // Очищаємо і Redis і файл
                    const redisResult = await apiCall('clear_search_stats');
                    const fileResult = await apiCall('clear_search_log');
                    
                    if ((redisResult && redisResult.success) || (fileResult && fileResult.success)) {
                        const msg = [];
                        if (redisResult?.deleted) msg.push(`Redis: ${redisResult.deleted}`);
                        if (fileResult?.success) msg.push('Файл очищено');
                        showToast('Очищено: ' + msg.join(', '), 'success');
                        await loadSearchBotLog();
                    } else {
                        showToast('Помилка очищення', 'error');
                    }
                }
            );
        }
        
        
        // ==================== JS CHALLENGE STATS ====================
        
        let currentJSCLogTab = 'shown';
        
        async function loadJSChallengeStats() {
            const result = await apiCall('jsc_stats');
            
            if (!result) {
                showToast('Помилка завантаження статистики JS Challenge', 'error');
                return;
            }
            
            // Update total stats
            document.getElementById('jsc-total-shown').textContent = result.total.shown || 0;
            document.getElementById('jsc-total-passed').textContent = result.total.passed || 0;
            document.getElementById('jsc-total-failed').textContent = result.total.failed || 0;
            document.getElementById('jsc-total-expired').textContent = result.total.expired || 0;
            document.getElementById('jsc-success-rate').textContent = (result.total.success_rate || 0) + '%';
            
            // Update today stats
            document.getElementById('jsc-today-shown').textContent = result.today.shown || 0;
            document.getElementById('jsc-today-passed').textContent = result.today.passed || 0;
            document.getElementById('jsc-today-failed').textContent = result.today.failed || 0;
            document.getElementById('jsc-today-success-rate').textContent = (result.today.success_rate || 0) + '%';
            
            // Render hourly chart
            renderJSCHourlyChart(result.hourly);
            
            // Load ALL log tabs (not just current one)
            ['shown', 'passed', 'failed', 'expired'].forEach(type => {
                loadJSCLog(type, result.recent_logs);
            });
            
            // v1.4: Оновлюємо timestamp
            const lastUpdateEl = document.getElementById('jscLastUpdate');
            if (lastUpdateEl) {
                lastUpdateEl.textContent = '⏱ ' + new Date().toLocaleTimeString('uk-UA');
            }
        }
        
        function renderJSCHourlyChart(hourlyData) {
            const container = document.getElementById('jsc-hourly-chart');
            
            if (!hourlyData || hourlyData.length === 0) {
                container.innerHTML = '<div style="text-align: center; padding: 80px 20px; color: var(--text-muted);">Немає даних для відображення</div>';
                return;
            }
            
            // Calculate max value for scaling
            let maxValue = 1;
            hourlyData.forEach(hour => {
                const total = hour.shown + hour.passed + hour.failed + hour.expired;
                if (total > maxValue) maxValue = total;
            });
            
            // Create chart HTML
            let chartHTML = '<div style="display: flex; align-items: flex-end; gap: 4px; height: 250px; padding: 10px;">';
            
            hourlyData.forEach((hour, index) => {
                const shownHeight = (hour.shown / maxValue) * 200;
                const passedHeight = (hour.passed / maxValue) * 200;
                const failedHeight = (hour.failed / maxValue) * 200;
                const expiredHeight = (hour.expired / maxValue) * 200;
                
                chartHTML += `
                    <div style="flex: 1; display: flex; flex-direction: column; align-items: center; gap: 2px;">
                        <div style="display: flex; flex-direction: column-reverse; width: 100%; gap: 1px; height: 200px; justify-content: flex-start;">
                            ${hour.shown > 0 ? `<div style="background: var(--accent-primary); height: ${shownHeight}px; border-radius: 2px; transition: all 0.3s;" title="Показано: ${hour.shown}"></div>` : ''}
                            ${hour.passed > 0 ? `<div style="background: var(--accent-success); height: ${passedHeight}px; border-radius: 2px; transition: all 0.3s;" title="Пройдено: ${hour.passed}"></div>` : ''}
                            ${hour.failed > 0 ? `<div style="background: var(--accent-danger); height: ${failedHeight}px; border-radius: 2px; transition: all 0.3s;" title="Провалено: ${hour.failed}"></div>` : ''}
                            ${hour.expired > 0 ? `<div style="background: var(--accent-warning); height: ${expiredHeight}px; border-radius: 2px; transition: all 0.3s;" title="Протерміновано: ${hour.expired}"></div>` : ''}
                        </div>
                        <div style="font-size: 0.7rem; color: var(--text-muted); writing-mode: vertical-rl; transform: rotate(180deg); margin-top: 5px;">
                            ${hour.hour}
                        </div>
                    </div>
                `;
            });
            
            chartHTML += '</div>';
            
            // Add legend
            chartHTML += `
                <div style="display: flex; justify-content: center; gap: 15px; margin-top: 15px; flex-wrap: wrap; font-size: 0.85rem;">
                    <div style="display: flex; align-items: center; gap: 5px;">
                        <div style="width: 12px; height: 12px; background: var(--accent-primary); border-radius: 2px;"></div>
                        <span>Показано</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 5px;">
                        <div style="width: 12px; height: 12px; background: var(--accent-success); border-radius: 2px;"></div>
                        <span>Пройдено</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 5px;">
                        <div style="width: 12px; height: 12px; background: var(--accent-danger); border-radius: 2px;"></div>
                        <span>Провалено</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 5px;">
                        <div style="width: 12px; height: 12px; background: var(--accent-warning); border-radius: 2px;"></div>
                        <span>Протерміновано</span>
                    </div>
                </div>
            `;
            
            container.innerHTML = chartHTML;
        }
        
        function switchJSCLogTab(tabName) {
            currentJSCLogTab = tabName;
            
            // Update buttons
            ['shown', 'passed', 'failed', 'expired'].forEach(type => {
                const btn = document.getElementById(`jsc-log-tab-${type}`);
                if (type === tabName) {
                    btn.style.background = 'var(--accent-primary)';
                    btn.style.color = 'var(--bg-primary)';
                } else {
                    btn.style.background = 'var(--bg-tertiary)';
                    btn.style.color = 'var(--text-primary)';
                }
            });
            
            // Show/hide tables
            ['shown', 'passed', 'failed', 'expired'].forEach(type => {
                const table = document.getElementById(`jsc-log-table-${type}`);
                table.style.display = type === tabName ? 'table' : 'none';
            });
        }
        
        function loadJSCLog(type, logsData) {
            const tbody = document.getElementById(`jsc-log-body-${type}`);
            const logs = logsData[type] || [];
            
            // v1.5: Для shown потрібно 5 колонок, для інших - 4
            const colSpan = type === 'shown' ? 5 : 4;
            
            if (logs.length === 0) {
                tbody.innerHTML = `<tr><td colspan="${colSpan}" style="text-align: center; color: var(--text-muted);">Немає даних</td></tr>`;
                return;
            }
            
            tbody.innerHTML = logs.map(log => {
                // v1.4: rDNS відображення
                const rdns = log.rdns || null;
                const rdnsHtml = rdns 
                    ? `<span style="font-size: 0.8rem; color: var(--accent-success);" title="${escapeHtml(rdns)}">${escapeHtml(rdns.length > 55 ? rdns.substring(0, 55) + '...' : rdns)}</span>`
                    : '<span style="color: var(--text-muted); font-size: 0.8rem;">—</span>';
                
                // v1.5: Статус для shown
                let statusHtml = '';
                if (type === 'shown') {
                    const status = log.status || 'pending';
                    if (status === 'passed') {
                        statusHtml = '<td style="text-align: center;"><span style="color: var(--accent-success); font-size: 1.2rem;" title="Пройдено">✓</span></td>';
                    } else if (status === 'failed') {
                        statusHtml = '<td style="text-align: center;"><span style="color: var(--accent-danger); font-size: 1.2rem;" title="Провалено">✗</span></td>';
                    } else if (status === 'expired') {
                        statusHtml = '<td style="text-align: center;"><span style="color: var(--accent-warning); font-size: 1.1rem;" title="Протерміновано">⏱</span></td>';
                    } else {
                        statusHtml = '<td style="text-align: center;"><span style="color: var(--text-muted); font-size: 1rem;" title="Очікування">⋯</span></td>';
                    }
                }
                
                return `
                    <tr>
                        <td style="font-family: var(--font-mono); font-size: 0.85rem;">${escapeHtml(log.date || '-')}</td>
                        <td style="font-family: var(--font-mono); color: var(--accent-secondary);">${escapeHtml(log.ip || '-')}</td>
                        <td>${rdnsHtml}</td>
                        <td style="font-size: 0.8rem; word-break: break-all; max-width: 450px;">${escapeHtml(log.ua || '-')}</td>
                        ${statusHtml}
                    </tr>
                `;
            }).join('');
        }
        // ==================== INITIALIZATION ====================
        
        document.addEventListener('DOMContentLoaded', async () => {
            // Load initial data
            loadBlockedPage(1);
            loadSessionsPage(1);
            
            // Load memory info
            const memory = await apiCall('memory');
            if (memory) {
                updateMemoryDisplay(memory);
            }
            
            // Start refresh timer
            setInterval(updateRefreshTimer, 1000);
            
            // Quick unblock on Enter
            document.getElementById('quickUnblockIP')?.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') quickUnblock();
            });
        });
        
        // Close modal on Escape
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') closeModal();
        });
        
        // Close modal on overlay click
        document.getElementById('confirmModal')?.addEventListener('click', (e) => {
            if (e.target.classList.contains('modal-overlay')) closeModal();
        });
    </script>
<?php endif; ?>
</body>
</html>
<?php

// Helper Functions
function formatTTL($seconds) {
    if ($seconds < 0) return 'Permanent';
    if ($seconds < 60) return $seconds . 's';
    if ($seconds < 3600) return floor($seconds / 60) . 'хв';
    return floor($seconds / 3600) . 'год ' . floor(($seconds % 3600) / 60) . 'хв';
}

function getProgressColor($value, $max) {
    $percent = ($value / $max) * 100;
    if ($percent < 50) return 'green';
    if ($percent < 80) return 'yellow';
    return 'red';
}

?>
