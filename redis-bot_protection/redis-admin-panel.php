<?php
// admin_panel.php - Административная панель для управления системой защиты от ботов
session_start();

// ==================== КОНФИГУРАЦИЯ ====================
define('ADMIN_USERNAME', 'murkir');
define('ADMIN_PASSWORD', 'murkir.pp.ua'); // Временно без хеша для отладки
define('ITEMS_PER_PAGE', 20);

// Настройки rDNS
define('ENABLE_RDNS', false);
define('RDNS_TIMEOUT', 1);
define('RDNS_CACHE_TTL', 86400);

// ВАЖНО: После входа сгенерируйте хеш пароля, выполнив в PHP:
// echo password_hash('murkir.pp.ua', PASSWORD_DEFAULT);
// И замените ADMIN_PASSWORD на полученный хеш

// Подключение к системе защиты
require_once 'inline_check.php';

// ==================== ФУНКЦИИ АВТОРИЗАЦИИ ====================
function isLoggedIn() {
    return isset($_SESSION['admin_logged_in']) && $_SESSION['admin_logged_in'] === true;
}

function login($username, $password) {
    // Проверка через bcrypt хеш
    if ($username === ADMIN_USERNAME && password_verify($password, ADMIN_PASSWORD)) {
        $_SESSION['admin_logged_in'] = true;
        $_SESSION['admin_username'] = $username;
        $_SESSION['login_time'] = time();
        return true;
    }
    
    return false;
}

function logout() {
    session_destroy();
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// ==================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ====================

// Функция rDNS
function getRDNSFast($redis, $ip) {
    $rdnsEnabled = $redis->get('bot_protection:config:rdns_enabled');
    if ($rdnsEnabled === false) {
        $rdnsEnabled = ENABLE_RDNS;
    }
    
    if (!$rdnsEnabled) {
        return 'rDNS disabled';
    }
    
    if (empty($ip) || $ip === 'unknown') {
        return 'N/A';
    }
    
    $cacheKey = 'bot_protection:rdns:cache:' . $ip;
    $cached = $redis->get($cacheKey);
    if ($cached !== false) {
        return $cached;
    }
    
    $start = microtime(true);
    $hostname = @gethostbyaddr($ip);
    $duration = microtime(true) - $start;
    
    if ($duration > RDNS_TIMEOUT || $hostname === $ip || $hostname === false) {
        $hostname = 'Timeout/N/A';
    }
    
    $redis->setex($cacheKey, RDNS_CACHE_TTL, $hostname);
    return $hostname;
}

// Новая функция для получения логов
function getLogs($redis, $limit = 100) {
    if (!$redis) return [];

    $logs = [];
    $today = date('Y-m-d');
    
    // Ключи, где хранятся логи
    $logKeys = [
        'bot_protection:logs:legitimate_bots:' . $today,
        'bot_protection:logs:search_engines:' . $today
    ];
    
    foreach ($logKeys as $logKey) {
        // Получаем последние N записей
        $logEntries = $redis->lrange($logKey, 0, $limit - 1);
        foreach ($logEntries as $entryJson) {
            // Redis-PHP с SERIALIZER_JSON может не декодировать данные из списков
            $entry = is_string($entryJson) ? json_decode($entryJson, true) : $entryJson;
            if ($entry) {
                // Добавляем тип лога для удобства отображения
                $entry['log_type'] = strpos($logKey, 'legitimate_bots') !== false ? 'bot' : 'search_engine';
                $logs[] = $entry;
            }
        }
    }
    
    // Сортируем все логи по времени в обратном порядке
    usort($logs, function($a, $b) {
        $timeA = strtotime($a['timestamp'] ?? '1970-01-01');
        $timeB = strtotime($b['timestamp'] ?? '1970-01-01');
        return $timeB - $timeA;
    });
    
    // Ограничиваем общее количество логов
    return array_slice($logs, 0, $limit);
}


// ==================== ОБРАБОТКА ДЕЙСТВИЙ ====================
$message = '';
$messageType = 'info';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['action'])) {
        try {
            $protection = new RedisBotProtectionNoSessions();
            
            switch ($_POST['action']) {
                case 'login':
                    if (login($_POST['username'] ?? '', $_POST['password'] ?? '')) {
                        header('Location: ' . $_SERVER['PHP_SELF']);
                        exit;
                    } else {
                        $message = 'Неверные учетные данные';
                        $messageType = 'error';
                    }
                    break;
                    
                case 'logout':
                    logout();
                    break;
                    
                case 'unblock_ip':
                    if (isLoggedIn() && !empty($_POST['ip'])) {
                        $result = $protection->unblockIP($_POST['ip']);
                        $protection->resetRateLimit($_POST['ip']);
                        $message = 'IP адрес разблокирован';
                        $messageType = 'success';
                    }
                    break;
                    
                case 'unblock_hash':
                    if (isLoggedIn() && !empty($_POST['hash'])) {
                        $result = $protection->unblockUserHash($_POST['hash']);
                        $message = 'User Hash разблокирован';
                        $messageType = 'success';
                    }
                    break;
                    
                case 'unblock_cookie':
                    if (isLoggedIn() && !empty($_POST['key'])) {
                        $tempRedis = new Redis();
                        $tempRedis->connect('127.0.0.1', 6379);
                        $tempRedis->select(0);
                        $deleted = $tempRedis->del($_POST['key']);
                        $tempRedis->close();
                        $message = $deleted ? 'Cookie разблокирована' : 'Ошибка разблокировки';
                        $messageType = $deleted ? 'success' : 'error';
                    }
                    break;
                    
                case 'reset_rate_limit':
                    if (isLoggedIn() && !empty($_POST['key'])) {
                        $tempRedis = new Redis();
                        $tempRedis->connect('127.0.0.1', 6379);
                        $tempRedis->select(0);
                        $deleted = $tempRedis->del($_POST['key']);
                        $tempRedis->close();
                        $message = $deleted ? 'Rate limit сброшен' : 'Ошибка сброса';
                        $messageType = $deleted ? 'success' : 'error';
                    }
                    break;
                    
                case 'block_ip_from_rate_limit':
                    if (isLoggedIn() && !empty($_POST['ip'])) {
                        $tempRedis = new Redis();
                        $tempRedis->connect('127.0.0.1', 6379);
                        $tempRedis->select(0);
                        $tempRedis->setOption(Redis::OPT_SERIALIZER, Redis::SERIALIZER_JSON);
                        
                        $ip = $_POST['ip'];
                        $blockKey = 'bot_protection:blocked:ip:' . hash('md5', $ip);
                        $blockData = [
                            'ip' => $ip,
                            'blocked_at' => time(),
                            'blocked_reason' => 'Manual block from Rate Limit (admin)',
                            'blocked_by' => 'admin',
                            'admin_action' => true,
                            'user_agent' => 'Rate Limit violation',
                            'session_id' => 'admin_block',
                            'repeat_offender' => false
                        ];
                        
                        $tempRedis->setex($blockKey, 7200, $blockData);
                        $tempRedis->close();
                        
                        $message = "IP $ip заблокирован вручную";
                        $messageType = 'success';
                    }
                    break;
                    
                case 'remove_extended_tracking':
                    if (isLoggedIn() && !empty($_POST['key'])) {
                        $tempRedis = new Redis();
                        $tempRedis->connect('127.0.0.1', 6379);
                        $tempRedis->select(0);
                        $deleted = $tempRedis->del($_POST['key']);
                        $tempRedis->close();
                        $message = $deleted ? 'Расширенный трекинг удален' : 'Ошибка удаления';
                        $messageType = $deleted ? 'success' : 'error';
                    }
                    break;
                    
                case 'clear_rdns_cache':
                    if (isLoggedIn()) {
                        $tempRedis = new Redis();
                        $tempRedis->connect('127.0.0.1', 6379);
                        $tempRedis->select(0);
                        
                        $keys = $tempRedis->keys('bot_protection:rdns:cache:*');
                        $deleted = 0;
                        if (is_array($keys)) {
                            foreach ($keys as $key) {
                                $tempRedis->del($key);
                                $deleted++;
                            }
                        }
                        $tempRedis->close();
                        
                        $message = "Очищено записей R-DNS кеша: $deleted";
                        $messageType = 'success';
                    }
                    break;
                    
                case 'reset_rdns_limit':
                    if (isLoggedIn()) {
                        $protection->resetRDNSRateLimit();
                        $message = 'R-DNS rate limit сброшен';
                        $messageType = 'success';
                    }
                    break;
                    
                case 'force_cleanup':
                    if (isLoggedIn()) {
                        $tempRedis = new Redis();
                        $tempRedis->connect('127.0.0.1', 6379);
                        $tempRedis->select(0);
                        
                        $cleaned = 0;
                        $allKeys = $tempRedis->keys('bot_protection:*');
                        
                        if (is_array($allKeys)) {
                            foreach ($allKeys as $key) {
                                $ttl = $tempRedis->ttl($key);
                                if (($ttl > 0 && $ttl < 300) || $ttl === -2) {
                                    $tempRedis->del($key);
                                    $cleaned++;
                                }
                            }
                        }
                        
                        $trackingKeys = $tempRedis->keys('bot_protection:tracking:ip:*');
                        if (is_array($trackingKeys)) {
                            foreach ($trackingKeys as $key) {
                                $data = $tempRedis->get($key);
                                if ($data && is_array($data)) {
                                    if (isset($data['first_seen']) && (time() - $data['first_seen']) > 7200) {
                                        $tempRedis->del($key);
                                        $cleaned++;
                                    }
                                }
                            }
                        }
                        
                        $tempRedis->close();
                        
                        $message = "Очищено ключей: $cleaned";
                        $messageType = 'success';
                    }
                    break;
                    
                case 'deep_cleanup':
                    if (isLoggedIn()) {
                        $tempRedis = new Redis();
                        $tempRedis->connect('127.0.0.1', 6379);
                        $tempRedis->select(0);
                        
                        $cleaned = 0;
                        $patterns = [
                            'bot_protection:tracking:ip:*',
                            'bot_protection:tracking:ratelimit:*',
                            'bot_protection:tracking:extended:*',
                            'bot_protection:blocked:history:*'
                        ];
                        
                        foreach ($patterns as $pattern) {
                            $keys = $tempRedis->keys($pattern);
                            if (is_array($keys)) {
                                foreach ($keys as $key) {
                                    $tempRedis->del($key);
                                    $cleaned++;
                                }
                            }
                        }
                        $tempRedis->close();
                        
                        $message = "Глубокая очистка выполнена. Удалено записей: $cleaned";
                        $messageType = 'success';
                    }
                    break;
                    
                case 'toggle_rdns':
                    if (isLoggedIn()) {
                        $redis = new Redis();
                        $redis->connect('127.0.0.1', 6379);
                        $currentState = $redis->get('bot_protection:config:rdns_enabled');
                        $newState = ($currentState === null) ? !ENABLE_RDNS : !$currentState;
                        $redis->set('bot_protection:config:rdns_enabled', $newState);
                        $message = 'rDNS переключен: ' . ($newState ? 'включен' : 'выключен');
                        $messageType = 'success';
                        $redis->close();
                    }
                    break;
                
                // Новый case для очистки логов
                case 'flush_logs':
                    if (isLoggedIn()) {
                        $tempRedis = new Redis();
                        $tempRedis->connect('127.0.0.1', 6379);
                        $tempRedis->select(0);

                        $flushed = 0;
                        $logKeys = $tempRedis->keys('bot_protection:logs:*');
                        if (is_array($logKeys)) {
                            foreach ($logKeys as $key) {
                                $tempRedis->del($key);
                                $flushed++;
                            }
                        }
                        $tempRedis->close();

                        $message = "Удалено контейнеров логов: $flushed";
                        $messageType = 'success';
                    }
                    break;
            }
        } catch (Exception $e) {
            $message = 'Ошибка: ' . $e->getMessage();
            $messageType = 'error';
        }
    }
}

// ==================== ПРОВЕРКА АВТОРИЗАЦИИ ====================
if (!isLoggedIn()) {
    ?>
    <!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Вход - Redis MurKir Security - Admin Panel</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .login-container {
                background: white;
                padding: 40px;
                border-radius: 10px;
                box-shadow: 0 10px 40px rgba(0,0,0,0.2);
                width: 100%;
                max-width: 400px;
            }
            h1 {
                text-align: center;
                color: #333;
                margin-bottom: 30px;
                font-size: 24px;
            }
            .form-group {
                margin-bottom: 20px;
            }
            label {
                display: block;
                margin-bottom: 5px;
                color: #555;
                font-size: 14px;
            }
            input {
                width: 100%;
                padding: 12px;
                border: 1px solid #ddd;
                border-radius: 5px;
                font-size: 14px;
            }
            input:focus {
                outline: none;
                border-color: #667eea;
            }
            button {
                width: 100%;
                padding: 12px;
                background: #667eea;
                color: white;
                border: none;
                border-radius: 5px;
                font-size: 16px;
                cursor: pointer;
                transition: background 0.3s;
            }
            button:hover {
                background: #5568d3;
            }
            .error {
                background: #fee;
                color: #c33;
                padding: 10px;
                border-radius: 5px;
                margin-bottom: 20px;
                font-size: 14px;
            }
        </style>
    </head>
    <body>
        <div class="login-container">
            <h1>🛡️ Redis MurKir Security - Admin Panel</h1>
            <?php if ($message): ?>
                <div class="error"><?php echo htmlspecialchars($message); ?></div>
            <?php endif; ?>
			<a href="redis_test.php" target="_blank" rel="noopener noreferrer" class="btn btn-primary">📊 Test Page</a>
            <form method="POST">
                <input type="hidden" name="action" value="login">
                <div class="form-group">
                    <label>Имя пользователя</label>
                    <input type="text" name="username" required autofocus>
                </div>
                <div class="form-group">
                    <label>Пароль</label>
                    <input type="password" name="password" required>
                </div>
                <button type="submit">Войти</button>
            </form>
        </div>
    </body>
    </html>
    <?php
    exit;
}

// ==================== ПОЛУЧЕНИЕ ДАННЫХ ====================
$protection = new RedisBotProtectionNoSessions();
$page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
$section = $_GET['section'] ?? 'dashboard';

$stats = $protection->getStats();
$rdnsStats = $protection->getRDNSRateLimitStats();
$memInfo = $protection->getRedisMemoryInfo();

// Подключение к Redis для дополнительных данных
$redis = new Redis();
$redis->connect('127.0.0.1', 6379);
$redis->select(0);
$redis->setOption(Redis::OPT_SERIALIZER, Redis::SERIALIZER_JSON);

$rdnsCurrentState = $redis->get('bot_protection:config:rdns_enabled');
if ($rdnsCurrentState === false) $rdnsCurrentState = ENABLE_RDNS;

// Подсчет нарушений rate limit напрямую
$totalViolations = 0;
$rateLimitKeys = $redis->keys('bot_protection:tracking:ratelimit:*');
if (is_array($rateLimitKeys)) {
    foreach ($rateLimitKeys as $key) {
        $data = $redis->get($key);
        if ($data && isset($data['violations'])) {
            $totalViolations += $data['violations'];
        }
    }
}
$stats['rate_limit_violations'] = $totalViolations;

// Подсчет верифицированных и не верифицированных R-DNS записей
$verifiedCount = 0;
$notVerifiedCount = 0;
$rdnsCacheKeys = $redis->keys('bot_protection:rdns:cache:*');
if (is_array($rdnsCacheKeys)) {
    foreach ($rdnsCacheKeys as $key) {
        $data = $redis->get($key);
        if ($data && is_array($data)) {
            if (isset($data['verified']) && $data['verified'] === true) {
                $verifiedCount++;
            } else {
                $notVerifiedCount++;
            }
        }
    }
}
$rdnsStats['verified_in_cache'] = $verifiedCount;
$rdnsStats['not_verified_in_cache'] = $notVerifiedCount;

// Получаем логи если активна соответствующая секция
if ($section === 'logs') {
    $logs = getLogs($redis);
}

?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Redis MurKir Security - Admin Panel</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: #f5f7fa;
            color: #333;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .header-content {
            max-width: 1400px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .header h1 {
            font-size: 24px;
        }
        
        .user-info {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .container {
            max-width: 1400px;
            margin: 20px auto;
            padding: 0 20px;
        }
        
        .nav {
            background: white;
            border-radius: 10px;
            padding: 15px;
            margin-bottom: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        
        .nav a {
            padding: 10px 20px;
            text-decoration: none;
            color: #667eea;
            border-radius: 5px;
            transition: all 0.3s;
        }
        
        .nav a:hover {
            background: #f0f0f0;
        }
        
        .nav a.active {
            background: #667eea;
            color: white;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
        }
        
        .stat-card h3 {
            font-size: 14px;
            color: #888;
            margin-bottom: 10px;
        }
        
        .stat-card .value {
            font-size: 32px;
            font-weight: bold;
            color: #667eea;
        }
        
        .stat-card.warning .value { color: #f59e0b; }
        .stat-card.danger .value { color: #ef4444; }
        .stat-card.success .value { color: #10b981; }
        
        .card {
            background: white;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
        }
        
        .card h2 {
            margin-bottom: 20px;
            color: #333;
            font-size: 20px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #eee;
        }
        
        th {
            background: #f9fafb;
            font-weight: 600;
            color: #555;
        }
        
        tr:hover {
            background: #f9fafb;
        }
        
        .btn {
            padding: 8px 16px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            transition: all 0.3s;
            text-decoration: none;
            display: inline-block;
        }
        
        .btn-primary {
            background: #667eea;
            color: white;
        }
        
        .btn-primary:hover {
            background: #5568d3;
        }
        
        .btn-danger {
            background: #ef4444;
            color: white;
        }
        
        .btn-danger:hover {
            background: #dc2626;
        }
        
        .btn-success {
            background: #10b981;
            color: white;
        }
        
        .btn-success:hover {
            background: #059669;
        }
        
        .btn-warning {
            background: #f59e0b;
            color: white;
        }
        
        .btn-warning:hover {
            background: #d97706;
        }
        
        .btn-small {
            padding: 5px 10px;
            font-size: 12px;
        }
        
        .message {
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        
        .message.success {
            background: #d1fae5;
            color: #065f46;
        }
        
        .message.error {
            background: #fee2e2;
            color: #991b1b;
        }
        
        .message.info {
            background: #dbeafe;
            color: #1e40af;
        }
        
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
        }
        
        .badge-success { background: #d1fae5; color: #065f46; }
        .badge-danger { background: #fee2e2; color: #991b1b; }
        .badge-warning { background: #fef3c7; color: #92400e; }
        .badge-info { background: #dbeafe; color: #1e40af; }
        
        .ip-info {
            font-family: monospace;
            background: #f8f9fa;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.9em;
        }
        
        .copyable {
            cursor: pointer;
            padding: 2px 6px;
            border-radius: 4px;
            transition: all 0.2s ease;
            border: 1px solid transparent;
            display: inline-block;
            word-break: break-all;
            max-width: 100%;
        }
        
        .copyable:hover {
            background-color: #e9ecef;
            border-color: #667eea;
        }
        
        .copyable:active {
            background-color: #667eea;
            color: white;
        }
        
        .pagination {
            display: flex;
            gap: 5px;
            justify-content: center;
            margin-top: 20px;
        }
        
        .pagination a {
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 5px;
            text-decoration: none;
            color: #667eea;
        }
        
        .pagination a:hover {
            background: #f0f0f0;
        }
        
        .pagination a.active {
            background: #667eea;
            color: white;
            border-color: #667eea;
        }
        
        .grid-2 {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }
        
        .progress-bar {
            width: 100%;
            height: 20px;
            background: #e5e7eb;
            border-radius: 10px;
            overflow: hidden;
            margin-top: 10px;
        }
        
        .progress-fill {
            height: 100%;
            background: #667eea;
            transition: width 0.3s;
        }
        
        .progress-fill.warning { background: #f59e0b; }
        .progress-fill.danger { background: #ef4444; }
        
        code {
            background: #f3f4f6;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
        }
        
        .actions {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            margin-bottom: 20px;
        }
        
        .search-box {
            width: 100%;
            max-width: 300px;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 8px;
            margin-bottom: 15px;
        }
        
        /* Цветовая индикация опасности */
        tr.danger-critical {
            background-color: #fee2e2 !important;
        }
        
        tr.danger-warning {
            background-color: #fef3c7 !important;
        }
        
        tr.danger-normal:hover {
            background: #f9fafb;
        }
        
        @media (max-width: 768px) {
            .grid-2 {
                grid-template-columns: 1fr;
            }
            
            .stats-grid {
                grid-template-columns: 1fr;
            }
            
            .header-content {
                flex-direction: column;
                gap: 15px;
            }
            
            table {
                font-size: 12px;
            }
            
            th, td {
                padding: 8px;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <h1>🛡️ Redis MurKir Security - Admin Panel</h1>
            <div class="user-info">
			<a href="redis_test.php" target="_blank" rel="noopener noreferrer" class="btn btn-primary">📊 Test Page</a>
                <span>👤 <?php echo htmlspecialchars($_SESSION['admin_username'] ?? 'Admin'); ?></span>
                <form method="POST" style="display: inline;">
                    <input type="hidden" name="action" value="logout">
                    <button type="submit" class="btn btn-small btn-danger">Выход</button>
                </form>
            </div>
        </div>
    </div>
    
    <div class="container">
        <?php if ($message): ?>
            <div class="message <?php echo $messageType; ?>">
                <?php echo htmlspecialchars($message); ?>
            </div>
        <?php endif; ?>
        
        <div class="nav">
            <a href="?section=dashboard" class="<?php echo $section === 'dashboard' ? 'active' : ''; ?>">Dashboard</a>
            <a href="?section=blocked_ips" class="<?php echo $section === 'blocked_ips' ? 'active' : ''; ?>">Blocked IPs</a>
            <a href="?section=blocked_hashes" class="<?php echo $section === 'blocked_hashes' ? 'active' : ''; ?>">Blocked Hashes</a>
            <a href="?section=cookies" class="<?php echo $section === 'cookies' ? 'active' : ''; ?>">Cookies</a>
            <a href="?section=rate_limits" class="<?php echo $section === 'rate_limits' ? 'active' : ''; ?>">Rate Limits</a>
            <a href="?section=extended_tracking" class="<?php echo $section === 'extended_tracking' ? 'active' : ''; ?>">Extended Tracking</a>
            <a href="?section=rdns" class="<?php echo $section === 'rdns' ? 'active' : ''; ?>">R-DNS</a>
            <a href="?section=user_hashes" class="<?php echo $section === 'user_hashes' ? 'active' : ''; ?>">User Hashes</a>
            <a href="?section=logs" class="<?php echo $section === 'logs' ? 'active' : ''; ?>">📝 Logs</a>
            <a href="?section=settings" class="<?php echo $section === 'settings' ? 'active' : ''; ?>">Settings</a>
        </div>
        
        <?php if ($section === 'dashboard'): ?>
            <div class="stats-grid">
                <div class="stat-card <?php echo $stats['blocked_ips'] > 100 ? 'warning' : ''; ?>">
                    <h3>Заблокировано IP</h3>
                    <div class="value"><?php echo number_format($stats['blocked_ips']); ?></div>
                </div>
                
                <div class="stat-card <?php echo $stats['blocked_user_hashes'] > 50 ? 'warning' : ''; ?>">
                    <h3>Заблокировано Hashes</h3>
                    <div class="value"><?php echo number_format($stats['blocked_user_hashes']); ?></div>
                </div>
                
                <div class="stat-card <?php echo $stats['blocked_cookies'] > 50 ? 'warning' : ''; ?>">
                    <h3>Заблокировано Cookies</h3>
                    <div class="value"><?php echo number_format($stats['blocked_cookies']); ?></div>
                </div>
                
                <div class="stat-card">
                    <h3>Отслеживаемых IP</h3>
                    <div class="value"><?php echo number_format($stats['tracking_records']); ?></div>
                </div>
                
                <div class="stat-card <?php echo $stats['extended_tracking_active'] > 20 ? 'warning' : ''; ?>">
                    <h3>Extended Tracking</h3>
                    <div class="value"><?php echo number_format($stats['extended_tracking_active']); ?></div>
                </div>
                
                <div class="stat-card <?php echo $stats['rate_limit_violations'] > 50 ? 'danger' : ''; ?>">
                    <h3>Нарушений Rate Limit</h3>
                    <div class="value"><?php echo number_format($stats['rate_limit_violations']); ?></div>
                </div>
                
                <div class="stat-card <?php echo $stats['total_keys'] > 5000 ? 'warning' : ''; ?>">
                    <h3>Всего ключей Redis</h3>
                    <div class="value"><?php echo number_format($stats['total_keys']); ?></div>
                </div>
                
                <div class="stat-card success">
                    <h3>Память Redis</h3>
                    <div class="value" style="font-size: 24px;"><?php echo $memInfo['used_memory']; ?></div>
                </div>
            </div>
            
            <div class="grid-2">
                <div class="card">
                    <h2>R-DNS Статистика</h2>
                    <table>
                        <tr>
                            <td>Запросов в минуту</td>
                            <td><strong><?php echo $rdnsStats['current_minute_requests']; ?> / <?php echo $rdnsStats['limit_per_minute']; ?></strong></td>
                        </tr>
                        <tr>
                            <td>Записей в кеше</td>
                            <td><strong><?php echo number_format($rdnsStats['cache_entries']); ?></strong></td>
                        </tr>
                        <tr>
                            <td>Верифицировано</td>
                            <td><span class="badge badge-success"><?php echo $rdnsStats['verified_in_cache']; ?></span></td>
                        </tr>
                        <tr>
                            <td>Не верифицировано</td>
                            <td><span class="badge badge-danger"><?php echo $rdnsStats['not_verified_in_cache']; ?></span></td>
                        </tr>
                        <tr>
                            <td>Статус лимита</td>
                            <td>
                                <?php if ($rdnsStats['limit_reached']): ?>
                                    <span class="badge badge-danger">Превышен</span>
                                <?php else: ?>
                                    <span class="badge badge-success">Норма</span>
                                <?php endif; ?>
                            </td>
                        </tr>
                    </table>
                </div>
                
                <div class="card">
                    <h2>Быстрые действия</h2>
                    <div class="actions">
                        <form method="POST" style="display: inline;">
                            <input type="hidden" name="action" value="force_cleanup">
                            <button type="submit" class="btn btn-primary">🧹 Очистить Redis</button>
                        </form>
                        
                        <form method="POST" style="display: inline;">
                            <input type="hidden" name="action" value="clear_rdns_cache">
                            <button type="submit" class="btn btn-warning">🌐 Очистить R-DNS</button>
                        </form>
                        
                        <form method="POST" style="display: inline;">
                            <input type="hidden" name="action" value="reset_rdns_limit">
                            <button type="submit" class="btn btn-success">♻️ Сброс R-DNS лимита</button>
                        </form>
                        
                        <form method="POST" style="display: inline;">
                            <input type="hidden" name="action" value="toggle_rdns">
                            <button type="submit" class="btn btn-primary">
                                🌐 rDNS: <?php echo $rdnsCurrentState ? 'ON' : 'OFF'; ?>
                            </button>
                        </form>
                        
                        <form method="POST" style="display: inline;" onsubmit="return confirm('Это удалит старые записи. Продолжить?');">
                            <input type="hidden" name="action" value="deep_cleanup">
                            <button type="submit" class="btn btn-danger">🔥 Глубокая очистка</button>
                        </form>
                    </div>
                </div>
            </div>
            
        <?php elseif ($section === 'blocked_ips'): ?>
            <div class="card">
                <h2>Заблокированные IP адреса</h2>
                <?php
                $allIPs = [];
                
                $iterator = null;
                do {
                    $keys = $redis->scan($iterator, 'bot_protection:blocked:ip:*', 100);
                    if ($keys !== false) {
                        foreach ($keys as $key) {
                            $data = $redis->get($key);
                            if ($data && is_array($data)) {
                                $allIPs[] = [
                                    'type' => 'blocked',
                                    'ip' => $data['ip'] ?? 'N/A',
                                    'data' => $data,
                                    'ttl' => $redis->ttl($key),
                                    'key' => $key
                                ];
                            }
                        }
                    }
                } while ($iterator > 0);
                
                usort($allIPs, function($a, $b) {
                    return ($b['data']['blocked_at'] ?? 0) - ($a['data']['blocked_at'] ?? 0);
                });
                
                $total = count($allIPs);
                $offset = ($page - 1) * ITEMS_PER_PAGE;
                $pageIPs = array_slice($allIPs, $offset, ITEMS_PER_PAGE);
                
                foreach ($pageIPs as &$ipData) {
                    if ($ipData['ip'] !== 'N/A' && !empty($ipData['ip'])) {
                        $ipData['hostname'] = getRDNSFast($redis, $ipData['ip']);
                    } else {
                        $ipData['hostname'] = 'N/A';
                    }
                }
                unset($ipData);
                
                if ($total > 0):
                ?>
                    <input type="text" class="search-box" placeholder="🔍 Поиск по IP или hostname..." onkeyup="filterTable(this, 'blocked-ips-table')">
                    <p style="margin-bottom: 15px;">Всего заблокированных IP: <strong><?php echo $total; ?></strong></p>
                    <div class="table-wrapper">
                    <table id="blocked-ips-table">
                        <thead>
                            <tr>
                                <th>IP адрес</th>
                                <th>Hostname (rDNS)</th>
                                <th>Заблокирован</th>
                                <th>TTL</th>
                                <th>User-Agent</th>
                                <th>Причина</th>
                                <th>Действия</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($pageIPs as $ipData): $data = $ipData['data']; ?>
                                <tr>
                                    <td>
                                        <span class="ip-info copyable" onclick="copyToClipboard('<?php echo addslashes($ipData['ip']); ?>', this)" title="Нажмите для копирования">
                                            <?php echo htmlspecialchars($ipData['ip']); ?>
                                        </span>
                                    </td>
                                    <td>
                                        <?php if ($ipData['hostname'] !== 'N/A' && $ipData['hostname'] !== 'Timeout/N/A' && $ipData['hostname'] !== 'rDNS disabled'): ?>
                                            <span class="copyable" onclick="copyToClipboard('<?php echo addslashes($ipData['hostname']); ?>', this)" title="Нажмите для копирования">
                                                <?php echo htmlspecialchars($ipData['hostname']); ?>
                                            </span>
                                        <?php else: ?>
                                            <span style="color: #6c757d;"><?php echo htmlspecialchars($ipData['hostname']); ?></span>
                                        <?php endif; ?>
                                    </td>
                                    <td><?php echo date('d.m H:i', $data['blocked_at'] ?? 0); ?></td>
                                    <td>
                                        <?php $ttl = $ipData['ttl'];
                                        if ($ttl > 0) {
                                            echo '<span class="badge badge-danger">' . floor($ttl / 3600) . 'h ' . floor(($ttl % 3600) / 60) . 'm</span>';
                                        } else {
                                            echo '<span class="badge badge-success">Постоянно</span>';
                                        } ?>
                                    </td>
                                    <td style="max-width: 200px; overflow: hidden; font-size: 11px;">
                                        <span class="copyable" onclick="copyToClipboard('<?php echo addslashes($data['user_agent'] ?? ''); ?>', this)">
                                            <?php echo htmlspecialchars(substr($data['user_agent'] ?? '', 0, 50)); ?>
                                        </span>
                                    </td>
                                    <td style="max-width: 150px; overflow: hidden; font-size: 11px;">
                                        <?php echo htmlspecialchars(substr($data['blocked_reason'] ?? 'N/A', 0, 40)); ?>
                                    </td>
                                    <td>
                                        <form method="POST" style="display: inline;">
                                            <input type="hidden" name="action" value="unblock_ip">
                                            <input type="hidden" name="ip" value="<?php echo htmlspecialchars($ipData['ip']); ?>">
                                            <button type="submit" class="btn btn-small btn-success">Unlock</button>
                                        </form>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                    </div>
                    <?php $totalPages = ceil($total / ITEMS_PER_PAGE); if ($totalPages > 1): ?>
                        <div class="pagination">
                            <?php for ($i = 1; $i <= min($totalPages, 10); $i++): ?>
                                <a href="?section=blocked_ips&page=<?php echo $i; ?>" class="<?php echo $i === $page ? 'active' : ''; ?>"><?php echo $i; ?></a>
                            <?php endfor; ?>
                        </div>
                    <?php endif; ?>
                <?php else: ?>
                    <p>Нет заблокированных IP адресов</p>
                <?php endif; ?>
            </div>
            
        <?php elseif ($section === 'blocked_hashes'): ?>
            <div class="card">
                <h2>Заблокированные User Hashes</h2>
                <?php
                $allBlockedHashes = [];
                $iterator = null;
                do {
                    $keys = $redis->scan($iterator, 'bot_protection:user_hash:blocked:*', 100);
                    if ($keys !== false) {
                        foreach ($keys as $key) {
                            $data = $redis->get($key);
                            if ($data && is_array($data)) {
                                $hashPart = str_replace('bot_protection:user_hash:blocked:', '', $key);
                                $allBlockedHashes[] = [
                                    'hash' => $data['user_hash'] ?? $hashPart,
                                    'data' => $data,
                                    'ttl' => $redis->ttl($key),
                                    'key' => $key
                                ];
                            }
                        }
                    }
                } while ($iterator > 0);
                
                usort($allBlockedHashes, function($a, $b) {
                    return ($b['data']['blocked_at'] ?? 0) - ($a['data']['blocked_at'] ?? 0);
                });
                
                $total = count($allBlockedHashes);
                $offset = ($page - 1) * ITEMS_PER_PAGE;
                $pageHashes = array_slice($allBlockedHashes, $offset, ITEMS_PER_PAGE);
                
                foreach ($pageHashes as &$hashData) {
                    if (isset($hashData['data']['ip']) && !empty($hashData['data']['ip'])) {
                        $hashData['hostname'] = getRDNSFast($redis, $hashData['data']['ip']);
                    } else {
                        $hashData['hostname'] = 'N/A';
                    }
                }
                unset($hashData);
                
                if ($total > 0):
                ?>
                    <input type="text" class="search-box" placeholder="🔍 Поиск по hash или IP..." onkeyup="filterTable(this, 'blocked-hashes-table')">
                    <p style="margin-bottom: 15px;">Всего заблокированных хешей: <strong><?php echo $total; ?></strong></p>
                    <div class="table-wrapper">
                    <table id="blocked-hashes-table">
                        <thead>
                            <tr>
                                <th>User Hash</th>
                                <th>IP адрес</th>
                                <th>Hostname (rDNS)</th>
                                <th>Заблокирован</th>
                                <th>TTL</th>
                                <th>User-Agent</th>
                                <th>Причина</th>
                                <th>Действия</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($pageHashes as $hashData): $data = $hashData['data']; ?>
                                <tr>
                                    <td>
                                        <span class="ip-info copyable" onclick="copyToClipboard('<?php echo addslashes($hashData['hash']); ?>', this)" title="Нажмите для копирования">
                                            <?php echo substr($hashData['hash'], 0, 16); ?>...
                                        </span>
                                    </td>
                                    <td>
                                        <?php if (isset($data['ip']) && $data['ip'] !== 'N/A'): ?>
                                            <span class="ip-info copyable" onclick="copyToClipboard('<?php echo addslashes($data['ip']); ?>', this)" title="Нажмите для копирования">
                                                <?php echo htmlspecialchars($data['ip']); ?>
                                            </span>
                                        <?php else: ?>
                                            <span style="color: #6c757d;">N/A</span>
                                        <?php endif; ?>
                                    </td>
                                    <td style="font-size: 11px; max-width: 200px; overflow: hidden;">
                                        <?php if ($hashData['hostname'] !== 'N/A' && $hashData['hostname'] !== 'Timeout/N/A' && $hashData['hostname'] !== 'rDNS disabled'): ?>
                                            <span class="copyable" onclick="copyToClipboard('<?php echo addslashes($hashData['hostname']); ?>', this)" title="Нажмите для копирования">
                                                <?php echo htmlspecialchars($hashData['hostname']); ?>
                                            </span>
                                        <?php else: ?>
                                            <span style="color: #6c757d;"><?php echo htmlspecialchars($hashData['hostname']); ?></span>
                                        <?php endif; ?>
                                    </td>
                                    <td><?php echo date('d.m H:i', $data['blocked_at'] ?? 0); ?></td>
                                    <td>
                                        <?php $ttl = $hashData['ttl'];
                                        if ($ttl > 0) {
                                            echo '<span class="badge badge-danger">' . floor($ttl / 3600) . 'h ' . floor(($ttl % 3600) / 60) . 'm</span>';
                                        } else {
                                            echo '<span class="badge badge-success">Постоянно</span>';
                                        } ?>
                                    </td>
                                    <td style="max-width: 200px; overflow: hidden; font-size: 11px;">
                                        <?php if (isset($data['user_agent'])): ?>
                                            <span class="copyable" onclick="copyToClipboard('<?php echo addslashes($data['user_agent']); ?>', this)">
                                                <?php echo htmlspecialchars(substr($data['user_agent'], 0, 50)); ?>
                                            </span>
                                        <?php else: ?>
                                            <span style="color: #6c757d;">N/A</span>
                                        <?php endif; ?>
                                    </td>
                                    <td style="max-width: 180px; overflow: hidden; font-size: 11px;">
                                        <?php echo htmlspecialchars(substr($data['blocked_reason'] ?? 'N/A', 0, 40)); ?>
                                    </td>
                                    <td>
                                        <form method="POST" style="display: inline;">
                                            <input type="hidden" name="action" value="unblock_hash">
                                            <input type="hidden" name="hash" value="<?php echo htmlspecialchars($hashData['hash']); ?>">
                                            <button type="submit" class="btn btn-small btn-success" onclick="return confirm('Разблокировать hash?');">🔓 Unlock</button>
                                        </form>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                    </div>
                    <?php $totalPages = ceil($total / ITEMS_PER_PAGE); if ($totalPages > 1): ?>
                        <div class="pagination">
                            <?php for ($i = 1; $i <= min($totalPages, 10); $i++): ?>
                                <a href="?section=blocked_hashes&page=<?php echo $i; ?>" class="<?php echo $i === $page ? 'active' : ''; ?>"><?php echo $i; ?></a>
                            <?php endfor; ?>
                        </div>
                    <?php endif; ?>
                <?php else: ?>
                    <p>Нет заблокированных user hashes</p>
                <?php endif; ?>
            </div>

        <?php elseif ($section === 'cookies'): ?>
            <div class="card">
                <h2>Заблокированные Cookies</h2>
                <?php
                $allCookies = [];
                
                $iterator = null;
                do {
                    $keys = $redis->scan($iterator, 'bot_protection:cookie:blocked:*', 100);
                    if ($keys !== false) {
                        foreach ($keys as $key) {
                            $data = $redis->get($key);
                            if ($data && is_array($data)) {
                                $allCookies[] = [
                                    'type' => 'blocked',
                                    'data' => $data,
                                    'ttl' => $redis->ttl($key),
                                    'key' => $key
                                ];
                            }
                        }
                    }
                } while ($iterator > 0);
                
                usort($allCookies, function($a, $b) {
                    return ($b['data']['blocked_at'] ?? 0) - ($a['data']['blocked_at'] ?? 0);
                });
                
                $total = count($allCookies);
                $offset = ($page - 1) * ITEMS_PER_PAGE;
                $pageCookies = array_slice($allCookies, $offset, ITEMS_PER_PAGE);
                
                foreach ($pageCookies as &$cookieData) {
                    if (isset($cookieData['data']['ip']) && !empty($cookieData['data']['ip'])) {
                        $cookieData['hostname'] = getRDNSFast($redis, $cookieData['data']['ip']);
                    } else {
                        $cookieData['hostname'] = 'N/A';
                    }
                }
                unset($cookieData);
                
                if ($total > 0):
                ?>
                    <input type="text" class="search-box" placeholder="🔍 Поиск по IP или hash..." onkeyup="filterTable(this, 'blocked-cookies-table')">
                    <p style="margin-bottom: 15px;">Всего заблокированных cookies: <strong><?php echo $total; ?></strong></p>
                    <div class="table-wrapper">
                    <table id="blocked-cookies-table">
                        <thead>
                            <tr>
                                <th>Cookie Hash</th>
                                <th>IP адрес</th>
                                <th>Hostname (rDNS)</th>
                                <th>User Agent</th>
                                <th>URI</th>
                                <th>Заблокирован</th>
                                <th>TTL</th>
                                <th>Действия</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($pageCookies as $cookieData): $data = $cookieData['data']; ?>
                                <tr>
                                    <td>
                                        <span class="ip-info copyable" onclick="copyToClipboard('<?php echo addslashes($data['cookie_hash'] ?? ''); ?>', this)" title="Нажмите для копирования">
                                            <?php echo htmlspecialchars(substr($data['cookie_hash'] ?? 'N/A', 0, 16)) . '...'; ?>
                                        </span>
                                    </td>
                                    <td>
                                        <span class="ip-info copyable" onclick="copyToClipboard('<?php echo addslashes($data['ip'] ?? ''); ?>', this)" title="Нажмите для копирования">
                                            <?php echo htmlspecialchars($data['ip'] ?? 'N/A'); ?>
                                        </span>
                                    </td>
                                    <td style="font-size: 11px; max-width: 200px; overflow: hidden;">
                                        <?php if ($cookieData['hostname'] !== 'N/A' && $cookieData['hostname'] !== 'Timeout/N/A' && $cookieData['hostname'] !== 'rDNS disabled'): ?>
                                            <span class="copyable" onclick="copyToClipboard('<?php echo addslashes($cookieData['hostname']); ?>', this)" title="Нажмите для копирования">
                                                <?php echo htmlspecialchars($cookieData['hostname']); ?>
                                            </span>
                                        <?php else: ?>
                                            <span style="color: #6c757d;"><?php echo htmlspecialchars($cookieData['hostname']); ?></span>
                                        <?php endif; ?>
                                    </td>
                                    <td style="max-width: 200px; overflow: hidden; font-size: 11px;">
                                        <span class="copyable" onclick="copyToClipboard('<?php echo addslashes($data['user_agent'] ?? ''); ?>', this)">
                                            <?php echo htmlspecialchars(substr($data['user_agent'] ?? 'N/A', 0, 50)); ?>
                                        </span>
                                    </td>
                                    <td style="max-width: 150px; overflow: hidden; font-size: 11px;">
                                        <span class="copyable" onclick="copyToClipboard('<?php echo addslashes($data['uri'] ?? ''); ?>', this)">
                                            <?php echo htmlspecialchars(substr($data['uri'] ?? 'N/A', 0, 40)); ?>
                                        </span>
                                    </td>
                                    <td><?php echo date('d.m H:i', $data['blocked_at'] ?? 0); ?></td>
                                    <td>
                                        <?php $ttl = $cookieData['ttl'];
                                        if ($ttl > 0) {
                                            echo '<span class="badge badge-danger">' . floor($ttl / 3600) . 'h ' . floor(($ttl % 3600) / 60) . 'm</span>';
                                        } else {
                                            echo '<span class="badge badge-success">—</span>';
                                        } ?>
                                    </td>
                                    <td>
                                        <form method="POST" style="display: inline;">
                                            <input type="hidden" name="action" value="unblock_cookie">
                                            <input type="hidden" name="key" value="<?php echo htmlspecialchars($cookieData['key']); ?>">
                                            <button type="submit" class="btn btn-small btn-success" onclick="return confirm('Разблокировать cookie?');">Unlock</button>
                                        </form>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                    </div>
                    <?php $totalPages = ceil($total / ITEMS_PER_PAGE); if ($totalPages > 1): ?>
                        <div class="pagination">
                            <?php for ($i = 1; $i <= min($totalPages, 10); $i++): ?>
                                <a href="?section=cookies&page=<?php echo $i; ?>" class="<?php echo $i === $page ? 'active' : ''; ?>"><?php echo $i; ?></a>
                            <?php endfor; ?>
                        </div>
                    <?php endif; ?>
                <?php else: ?>
                    <p>Нет заблокированных cookies</p>
                <?php endif; ?>
            </div>

        <?php elseif ($section === 'rate_limits'): ?>
    <div class="card">
        <h2>Rate Limit нарушения и отслеживание</h2>
        <?php
        $allRateLimits = [];
        $iterator = null;
        do {
            $keys = $redis->scan($iterator, 'bot_protection:tracking:ratelimit:*', 100);
            if ($keys !== false && is_array($keys)) {
                foreach ($keys as $key) {
                    $data = $redis->get($key);
                    if ($data && is_array($data)) {
                        $hashPart = str_replace('bot_protection:tracking:ratelimit:', '', $key);
                        $allRateLimits[] = [ 'hash' => $hashPart, 'data' => $data, 'ttl' => $redis->ttl($key), 'key' => $key ];
                    }
                }
            }
        } while ($iterator > 0 && $iterator !== null);
        
        usort($allRateLimits, function($a, $b) {
            return ($b['data']['violations'] ?? 0) - ($a['data']['violations'] ?? 0);
        });
        
        $total = count($allRateLimits);
        $offset = ($page - 1) * ITEMS_PER_PAGE;
        $pageRateLimits = array_slice($allRateLimits, $offset, ITEMS_PER_PAGE);
        
        foreach ($pageRateLimits as &$rlData) {
            $trackingKey = 'bot_protection:tracking:ip:' . $rlData['hash'];
            $trackingData = $redis->get($trackingKey);
            
            if ($trackingData && is_array($trackingData) && isset($trackingData['real_ip'])) {
                $rlData['ip'] = $trackingData['real_ip'];
                $rlData['hostname'] = getRDNSFast($redis, $rlData['ip']);
            } else {
                $rlData['ip'] = 'N/A';
                $rlData['hostname'] = 'N/A';
            }
        }
        unset($rlData);
        
        if ($total > 0):
        ?>
            <input type="text" class="search-box" placeholder="🔍 Поиск..." onkeyup="filterTable(this, 'rate-limits-table')">
            <p style="margin-bottom: 15px;">Всего записей: <strong><?php echo $total; ?></strong></p>
            <div class="table-wrapper" style="overflow-x: auto;">
            <table id="rate-limits-table">
                <thead>
                    <tr>
                        <th>IP адрес</th>
                        <th>Hostname (rDNS)</th>
                        <th>IP Hash</th>
                        <th>Нарушений</th>
                        <th>Запросов/мин</th>
                        <th>Запросов/5 мин</th>
                        <th>Запросов/в час</th>
                        <th>Последний запрос</th>
                        <th>TTL</th>
                        <th>Действия</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($pageRateLimits as $rlData): 
                        $data = $rlData['data'];
                        $violations = $data['violations'] ?? 0;
                        
                        $rowClass = 'danger-normal';
                        if ($violations > 10) $rowClass = 'danger-critical';
                        elseif ($violations > 5) $rowClass = 'danger-warning';
                        
                        // Получаем лимиты из настроек для сравнения
                        $rateLimitSettings = $protection->getRateLimitSettings();
                        $limit1min = $rateLimitSettings['max_requests_per_minute'] ?? 60;
                        $limit5min = $rateLimitSettings['max_requests_per_5min'] ?? 200;
                        $limit1hour = $rateLimitSettings['max_requests_per_hour'] ?? 1000;
                        
                        $req1min = $data['requests_1min'] ?? 0;
                        $req5min = $data['requests_5min'] ?? 0;
                        $req1hour = $data['requests_1hour'] ?? 0;
                    ?>
                        <tr class="<?php echo $rowClass; ?>">
                            <td>
                                <?php if ($rlData['ip'] !== 'N/A'): ?>
                                    <span class="ip-info copyable" onclick="copyToClipboard('<?php echo addslashes($rlData['ip']); ?>', this)" title="Нажмите для копирования"><?php echo htmlspecialchars($rlData['ip']); ?></span>
                                <?php else: ?>
                                    <span style="color: #6c757d;">N/A</span>
                                <?php endif; ?>
                            </td>
                            <td style="font-size: 11px; max-width: 200px; overflow: hidden;">
                                <?php if ($rlData['hostname'] !== 'N/A' && $rlData['hostname'] !== 'Timeout/N/A' && $rlData['hostname'] !== 'rDNS disabled'): ?>
                                    <span class="copyable" onclick="copyToClipboard('<?php echo addslashes($rlData['hostname']); ?>', this)" title="Нажмите для копирования"><?php echo htmlspecialchars($rlData['hostname']); ?></span>
                                <?php else: ?>
                                    <span style="color: #6c757d;"><?php echo htmlspecialchars($rlData['hostname']); ?></span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <span class="ip-info copyable" onclick="copyToClipboard('<?php echo addslashes($rlData['hash']); ?>', this)" title="Нажмите для копирования"><?php echo substr($rlData['hash'], 0, 12); ?>...</span>
                            </td>
                            <td>
                                <?php if ($violations > 10) echo '<span class="badge badge-danger">🔥 ' . $violations . '</span>';
                                elseif ($violations > 5) echo '<span class="badge badge-warning">⚠️ ' . $violations . '</span>';
                                else echo '<span class="badge badge-info">👀 ' . $violations . '</span>'; ?>
                            </td>
                            <td>
                                <strong><?php echo $req1min; ?></strong>
                                <?php if ($req1min > $limit1min * 0.8): ?>
                                    <span class="badge badge-warning" style="font-size: 10px;">⚠️ <?php echo round(($req1min / $limit1min) * 100); ?>%</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <strong><?php echo $req5min; ?></strong>
                                <?php if ($req5min > $limit5min * 0.8): ?>
                                    <span class="badge badge-warning" style="font-size: 10px;">⚠️ <?php echo round(($req5min / $limit5min) * 100); ?>%</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <strong><?php echo $req1hour; ?></strong>
                                <?php if ($req1hour > $limit1hour * 0.8): ?>
                                    <span class="badge badge-warning" style="font-size: 10px;">⚠️ <?php echo round(($req1hour / $limit1hour) * 100); ?>%</span>
                                <?php endif; ?>
                            </td>
                            <td style="font-size: 11px;"><?php echo date('d.m H:i:s', $data['last_request'] ?? 0); ?></td>
                            <td><?php $ttl = $rlData['ttl']; if ($ttl > 0) echo floor($ttl / 60) . 'm'; else echo '—'; ?></td>
                            <td>
                                <form method="POST" style="display: inline;">
                                    <input type="hidden" name="action" value="reset_rate_limit">
                                    <input type="hidden" name="key" value="<?php echo htmlspecialchars($rlData['key']); ?>">
                                    <button type="submit" class="btn btn-small btn-success" onclick="return confirm('Сбросить rate limit?');" title="Сбросить счетчики">🔄 Reset</button>
                                </form>
                                <?php if ($rlData['ip'] !== 'N/A'): ?>
                                    <form method="POST" style="display: inline; margin-left: 5px;">
                                        <input type="hidden" name="action" value="block_ip_from_rate_limit">
                                        <input type="hidden" name="ip" value="<?php echo htmlspecialchars($rlData['ip']); ?>">
                                        <button type="submit" class="btn btn-small btn-danger" onclick="return confirm('Заблокировать IP <?php echo htmlspecialchars($rlData['ip']); ?>?');" title="Заблокировать IP">🚫 Block</button>
                                    </form>
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            </div>
            <?php $totalPages = ceil($total / ITEMS_PER_PAGE); if ($totalPages > 1): ?>
                <div class="pagination">
                    <?php for ($i = 1; $i <= min($totalPages, 10); $i++): ?>
                        <a href="?section=rate_limits&page=<?php echo $i; ?>" class="<?php echo $i === $page ? 'active' : ''; ?>"><?php echo $i; ?></a>
                    <?php endfor; ?>
                </div>
            <?php endif; ?>
        <?php else: ?>
            <div class="message info">Нет записей rate limit в Redis.</div>
        <?php endif; ?>
    </div>

        <?php elseif ($section === 'extended_tracking'): ?>
             <div class="card">
                <h2>🔍 Расширенный трекинг (Extended Tracking)</h2>
                <p style="margin-bottom: 20px; color: #666;">
                    Расширенный трекинг включается для подозрительных IP адресов.
                </p>
                <?php
                $allExtended = [];
                $iterator = null;
                do {
                    $keys = $redis->scan($iterator, 'bot_protection:tracking:extended:*', 100);
                    if ($keys !== false) {
                        foreach ($keys as $key) {
                            $data = $redis->get($key);
                            if ($data && is_array($data)) {
                                $allExtended[] = [ 'data' => $data, 'ttl' => $redis->ttl($key), 'key' => $key ];
                            }
                        }
                    }
                } while ($iterator > 0);
                
                usort($allExtended, function($a, $b) {
                    return ($b['data']['enabled_at'] ?? 0) - ($a['data']['enabled_at'] ?? 0);
                });
                
                $total = count($allExtended);
                $offset = ($page - 1) * ITEMS_PER_PAGE;
                $pageExtended = array_slice($allExtended, $offset, ITEMS_PER_PAGE);
                
                foreach ($pageExtended as &$extData) {
                    if (isset($extData['data']['ip']) && !empty($extData['data']['ip'])) {
                        $extData['hostname'] = getRDNSFast($redis, $extData['data']['ip']);
                    } else {
                        $extData['hostname'] = 'N/A';
                    }
                }
                unset($extData);
                
                if ($total > 0):
                ?>
                    <input type="text" class="search-box" placeholder="🔍 Поиск по IP или hostname..." onkeyup="filterTable(this, 'extended-tracking-table')">
                    <p style="margin-bottom: 15px;">Всего активных трекингов: <strong><?php echo $total; ?></strong></p>
                    <div class="table-wrapper">
                    <table id="extended-tracking-table">
                        <thead>
                            <tr>
                                <th>IP адрес</th>
                                <th>Hostname (rDNS)</th>
                                <th>Включен</th>
                                <th>Причина</th>
                                <th>Запросов</th>
                                <th>TTL</th>
                                <th>Действия</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($pageExtended as $extData): $data = $extData['data']; ?>
                                <tr>
                                    <td><span class="ip-info copyable" onclick="copyToClipboard('<?php echo addslashes($data['ip'] ?? ''); ?>', this)"><?php echo htmlspecialchars($data['ip'] ?? 'N/A'); ?></span></td>
                                    <td style="font-size: 11px; max-width: 200px; overflow: hidden;">
                                        <?php if ($extData['hostname'] !== 'N/A' && $extData['hostname'] !== 'Timeout/N/A' && $extData['hostname'] !== 'rDNS disabled'): ?>
                                            <span class="copyable" onclick="copyToClipboard('<?php echo addslashes($extData['hostname']); ?>', this)"><?php echo htmlspecialchars($extData['hostname']); ?></span>
                                        <?php else: ?>
                                            <span style="color: #6c757d;"><?php echo htmlspecialchars($extData['hostname']); ?></span>
                                        <?php endif; ?>
                                    </td>
                                    <td><?php echo date('d.m H:i', $data['enabled_at'] ?? 0); ?></td>
                                    <td style="font-size: 11px;"><span class="badge badge-warning"><?php echo htmlspecialchars(substr($data['reason'] ?? 'N/A', 0, 40)); ?></span></td>
                                    <td><strong><?php echo $data['extended_requests'] ?? 1; ?></strong></td>
                                    <td>
                                        <?php $ttl = $extData['ttl'];
                                        if ($ttl > 0) echo '<span class="badge badge-info">' . floor($ttl / 3600) . 'h ' . floor(($ttl % 3600) / 60) . 'm</span>';
                                        else echo '<span class="badge badge-success">Постоянно</span>'; ?>
                                    </td>
                                    <td>
                                        <form method="POST" style="display: inline;">
                                            <input type="hidden" name="action" value="remove_extended_tracking">
                                            <input type="hidden" name="key" value="<?php echo htmlspecialchars($extData['key']); ?>">
                                            <button type="submit" class="btn btn-small btn-danger" onclick="return confirm('Удалить?');">🗑️ Remove</button>
                                        </form>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                    </div>
                    <?php $totalPages = ceil($total / ITEMS_PER_PAGE); if ($totalPages > 1): ?>
                        <div class="pagination">
                            <?php for ($i = 1; $i <= min($totalPages, 10); $i++): ?>
                                <a href="?section=extended_tracking&page=<?php echo $i; ?>" class="<?php echo $i === $page ? 'active' : ''; ?>"><?php echo $i; ?></a>
                            <?php endfor; ?>
                        </div>
                    <?php endif; ?>
                <?php else: ?>
                    <div class="message info">Нет активных расширенных трекингов.</div>
                <?php endif; ?>
            </div>
            
        <?php elseif ($section === 'rdns'): ?>
            <div class="card">
                <h2>R-DNS Кеш и статистика</h2>
                <div class="stats-grid" style="margin-bottom: 30px;">
                    <div class="stat-card"><h3>Запросов/мин</h3><div class="value"><?php echo $rdnsStats['current_minute_requests']; ?> / <?php echo $rdnsStats['limit_per_minute']; ?></div></div>
                    <div class="stat-card success"><h3>Записей в кеше</h3><div class="value"><?php echo number_format($rdnsStats['cache_entries']); ?></div></div>
                    <div class="stat-card"><h3>Верифицировано</h3><div class="value" style="color: #10b981;"><?php echo $rdnsStats['verified_in_cache']; ?></div></div>
                </div>
                <?php
                $allRDNS = [];
                $iterator = null;
                do {
                    $keys = $redis->scan($iterator, 'bot_protection:rdns:cache:*', 100);
                    if ($keys !== false && is_array($keys)) {
                        foreach ($keys as $key) {
                            $data = $redis->get($key);
                            if ($data && is_array($data)) {
                                $allRDNS[] = [ 'data' => $data, 'ttl' => $redis->ttl($key), 'key' => $key ];
                            }
                        }
                    }
                } while ($iterator > 0 && $iterator !== null);
                
                usort($allRDNS, function($a, $b) {
                    return ($b['data']['timestamp'] ?? 0) - ($a['data']['timestamp'] ?? 0);
                });
                
                $total = count($allRDNS);
                $offset = ($page - 1) * ITEMS_PER_PAGE;
                $pageRDNS = array_slice($allRDNS, $offset, ITEMS_PER_PAGE);
                
                if ($total > 0):
                ?>
                    <h3 style="margin-bottom: 15px;">Кеш R-DNS записей (<?php echo $total; ?>)</h3>
                    <input type="text" class="search-box" placeholder="🔍 Поиск..." onkeyup="filterTable(this, 'rdns-table')">
                    <div class="table-wrapper">
                    <table id="rdns-table">
                        <thead><tr><th>IP адрес</th><th>Hostname</th><th>Статус</th><th>Проверено</th><th>TTL</th></tr></thead>
                        <tbody>
                            <?php foreach ($pageRDNS as $rdnsData): $data = $rdnsData['data']; ?>
                                <tr>
                                    <td><span class="ip-info copyable" onclick="copyToClipboard('<?php echo addslashes($data['ip'] ?? ''); ?>', this)"><?php echo htmlspecialchars($data['ip'] ?? 'N/A'); ?></span></td>
                                    <td style="font-size: 11px;"><span class="copyable" onclick="copyToClipboard('<?php echo addslashes($data['hostname'] ?? ''); ?>', this)"><?php echo htmlspecialchars($data['hostname'] ?? 'N/A'); ?></span></td>
                                    <td>
                                        <?php if ($data['verified'] ?? false): ?><span class="badge badge-success">✓ Verified</span>
                                        <?php else: ?><span class="badge badge-danger">✗ Not Verified</span><?php endif; ?>
                                    </td>
                                    <td style="font-size: 11px;"><?php echo date('d.m H:i:s', $data['timestamp'] ?? 0); ?></td>
                                    <td><?php $ttl = $rdnsData['ttl']; if ($ttl > 0) echo floor($ttl / 60) . 'm'; else echo '—'; ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                    </div>
                    <?php $totalPages = ceil($total / ITEMS_PER_PAGE); if ($totalPages > 1): ?>
                        <div class="pagination">
                            <?php for ($i = 1; $i <= min($totalPages, 10); $i++): ?><a href="?section=rdns&page=<?php echo $i; ?>" class="<?php echo $i === $page ? 'active' : ''; ?>"><?php echo $i; ?></a><?php endfor; ?>
                        </div>
                    <?php endif; ?>
                <?php else: ?>
                    <div class="message info">Кеш R-DNS пуст.</div>
                <?php endif; ?>
            </div>

        <?php elseif ($section === 'user_hashes'): ?>
            <div class="card">
                <h2>Все User Hashes в системе</h2>
                <?php
                $allHashes = [];
                // Blocked Hashes
                $iterator = null;
                do {
                    $keys = $redis->scan($iterator, 'bot_protection:user_hash:blocked:*', 100);
                    if ($keys !== false) {
                        foreach ($keys as $key) {
                            $data = $redis->get($key);
                            if ($data && is_array($data)) { $allHashes[] = [ 'type' => 'blocked', 'hash' => $data['user_hash'] ?? substr($key, -16), 'data' => $data, 'ttl' => $redis->ttl($key), 'key' => $key ]; }
                        }
                    }
                } while ($iterator > 0);
                
                // Tracking Hashes
                $iterator = null;
                do {
                    $keys = $redis->scan($iterator, 'bot_protection:user_hash:tracking:*', 100);
                    if ($keys !== false) {
                        foreach ($keys as $key) {
                            $data = $redis->get($key);
                            if ($data && is_array($data)) { $allHashes[] = [ 'type' => 'tracking', 'hash' => $data['user_hash'] ?? substr($key, -16), 'data' => $data, 'ttl' => $redis->ttl($key), 'key' => $key ]; }
                        }
                    }
                } while ($iterator > 0);
                
                usort($allHashes, function($a, $b) {
                    $aTime = ($a['type'] === 'blocked') ? ($a['data']['blocked_at'] ?? 0) : ($a['data']['last_activity'] ?? 0);
                    $bTime = ($b['type'] === 'blocked') ? ($b['data']['blocked_at'] ?? 0) : ($b['data']['last_activity'] ?? 0);
                    return $bTime - $aTime;
                });
                
                $total = count($allHashes);
                $offset = ($page - 1) * ITEMS_PER_PAGE;
                $pageHashes = array_slice($allHashes, $offset, ITEMS_PER_PAGE);
                
                if ($total > 0):
                ?>
                    <input type="text" class="search-box" placeholder="🔍 Поиск..." onkeyup="filterTable(this, 'user-hashes-table')">
                    <p>Всего записей: <strong><?php echo $total; ?></strong></p>
                    <div class="table-wrapper">
                    <table id="user-hashes-table">
                        <thead><tr><th>Статус</th><th>Hash</th><th>IP</th><th>Запросов</th><th>Информация</th><th>Действия</th></tr></thead>
                        <tbody>
                            <?php foreach ($pageHashes as $hashData): $data = $hashData['data']; $type = $hashData['type']; ?>
                                <tr>
                                    <td><?php if ($type === 'blocked'): ?><span class="badge badge-danger">Blocked</span><?php else: ?><span class="badge badge-success">Tracking</span><?php endif; ?></td>
                                    <td><span class="ip-info copyable" onclick="copyToClipboard('<?php echo addslashes($hashData['hash']); ?>', this)"><?php echo substr($hashData['hash'], 0, 10); ?>...</span></td>
                                    <td style="font-size: 11px;"><?php if ($type === 'blocked') echo '<span class="ip-info">'.htmlspecialchars($data['ip'] ?? 'N/A').'</span>'; elseif ($type === 'tracking') echo (count($data['ips'] ?? []) . ' IP'); else echo '—'; ?></td>
                                    <td><strong><?php echo $data['requests'] ?? 0; ?></strong></td>
                                    <td style="font-size: 11px;"><?php if ($type === 'blocked') echo htmlspecialchars(substr($data['blocked_reason'] ?? 'N/A', 0, 30)); elseif ($type === 'tracking') echo 'First: ' . date('H:i', $data['first_seen'] ?? 0); ?></td>
                                    <td>
                                        <?php if ($type === 'blocked'): ?>
                                            <form method="POST" style="display: inline;"><input type="hidden" name="action" value="unblock_hash"><input type="hidden" name="hash" value="<?php echo htmlspecialchars($hashData['hash']); ?>"><button type="submit" class="btn btn-small btn-success">Unlock</button></form>
                                        <?php else: ?><span style="color: #888; font-size: 11px;">Active</span><?php endif; ?>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                    </div>
                    <?php $totalPages = ceil($total / ITEMS_PER_PAGE); if ($totalPages > 1): ?>
                        <div class="pagination">
                            <?php for ($i = 1; $i <= min($totalPages, 10); $i++): ?><a href="?section=user_hashes&page=<?php echo $i; ?>" class="<?php echo $i === $page ? 'active' : ''; ?>"><?php echo $i; ?></a><?php endfor; ?>
                        </div>
                    <?php endif; ?>
                <?php else: ?>
                    <p>Нет записей User Hashes в Redis</p>
                <?php endif; ?>
            </div>
            
        <?php elseif ($section === 'logs'): ?>
            <div class="card">
                <div class="card-header">
                    <h2>📝 Логи поисковых систем и ботов (сегодня)</h2>
                    <form method="POST" onsubmit="return confirm('Вы уверены, что хотите очистить все логи?');">
                        <input type="hidden" name="action" value="flush_logs">
                        <button type="submit" class="btn btn-danger">🗑️ Очистить логи</button>
                    </form>
                </div>
                <?php if (!empty($logs)): ?>
                    <input type="text" class="search-box" placeholder="🔍 Поиск в логах..." onkeyup="filterTable(this, 'logs-table')">
                    <p style="margin-bottom: 15px;">Показаны последние <strong><?php echo count($logs); ?></strong> записей.</p>
                    <div class="table-wrapper">
                        <table id="logs-table">
                            <thead>
                                <tr>
                                    <th>Время</th>
                                    <th>Тип</th>
                                    <th>IP адрес</th>
                                    <th>User-Agent</th>
                                    <th>URI</th>
                                    <th>Hostname</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($logs as $log): ?>
                                    <tr>
                                        <td><?php echo htmlspecialchars($log['timestamp'] ?? ''); ?></td>
                                        <td>
                                            <?php if ($log['log_type'] === 'bot'): ?>
                                                <span class="badge badge-bot">🤖 Bot</span>
                                            <?php else: ?>
                                                <span class="badge badge-search">🔍 Search Engine</span>
                                            <?php endif; ?>
                                        </td>
                                        <td>
                                            <span class="ip-info copyable" onclick="copyToClipboard('<?php echo addslashes($log['ip'] ?? ''); ?>', this)">
                                                <?php echo htmlspecialchars($log['ip'] ?? 'N/A'); ?>
                                            </span>
                                        </td>
                                        <td style="max-width: 250px; overflow: hidden; font-size: 11px;">
                                            <span class="copyable" onclick="copyToClipboard('<?php echo addslashes($log['user_agent'] ?? ''); ?>', this)">
                                                <?php echo htmlspecialchars($log['user_agent'] ?? 'N/A'); ?>
                                            </span>
                                        </td>
                                        <td style="max-width: 200px; overflow: hidden; font-size: 11px;">
                                            <span class="copyable" onclick="copyToClipboard('<?php echo addslashes($log['uri'] ?? ''); ?>', this)">
                                                <?php echo htmlspecialchars($log['uri'] ?? 'N/A'); ?>
                                            </span>
                                        </td>
                                        <td>
                                            <?php if (isset($log['hostname']) && !empty($log['hostname'])): ?>
                                                <span class="copyable" onclick="copyToClipboard('<?php echo addslashes($log['hostname']); ?>', this)">
                                                    <?php echo htmlspecialchars($log['hostname']); ?>
                                                </span>
                                            <?php else: ?>
                                                <span style="color: #6c757d;">N/A</span>
                                            <?php endif; ?>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php else: ?>
                    <div class="message info">
                        Нет записей в логах за сегодня.
                    </div>
                <?php endif; ?>
            </div>

        <?php elseif ($section === 'settings'): ?>
    <div class="grid-2">
        <div class="card">
            <h2>Rate Limit настройки</h2>
            <?php 
            $rateLimitSettings = $protection->getRateLimitSettings(); 
            if (!empty($rateLimitSettings)):
            ?>
            <div class="table-wrapper">
                <table>
                    <?php foreach ($rateLimitSettings as $key => $value): ?>
                        <tr>
                            <td><code><?php echo htmlspecialchars($key); ?></code></td>
                            <td><strong><?php echo htmlspecialchars($value); ?></strong></td>
                        </tr>
                    <?php endforeach; ?>
                </table>
            </div>
            <?php else: ?>
                <p style="color: #999;">Настройки не найдены</p>
            <?php endif; ?>
        </div>
        
        <div class="card">
            <h2>TTL настройки</h2>
            <?php 
            $ttlSettings = $protection->getTTLSettings(); 
            if (!empty($ttlSettings)):
            ?>
            <div class="table-wrapper">
                <table>
                    <?php foreach ($ttlSettings as $key => $value): ?>
                        <tr>
                            <td><code><?php echo htmlspecialchars($key); ?></code></td>
                            <td><strong><?php echo number_format($value); ?> сек</strong></td>
                        </tr>
                    <?php endforeach; ?>
                </table>
            </div>
            <?php else: ?>
                <p style="color: #999;">Настройки не найдены</p>
            <?php endif; ?>
        </div>
        
        <div class="card">
            <h2>Защита от переполнения</h2>
            <?php 
            $globalSettings = $protection->getGlobalProtectionSettings(); 
            if (!empty($globalSettings)):
            ?>
            <div class="table-wrapper">
                <table>
                    <?php foreach ($globalSettings as $key => $value): ?>
                        <tr>
                            <td><code><?php echo htmlspecialchars($key); ?></code></td>
                            <td><strong><?php echo htmlspecialchars($value); ?></strong></td>
                        </tr>
                    <?php endforeach; ?>
                </table>
            </div>
            <?php else: ?>
                <p style="color: #999;">Настройки не найдены</p>
            <?php endif; ?>
        </div>
        
        <div class="card">
            <h2>Slow Bot настройки</h2>
            <?php 
            $slowBotSettings = $protection->getSlowBotSettings(); 
            if (!empty($slowBotSettings)):
            ?>
            <div class="table-wrapper">
                <table>
                    <?php foreach ($slowBotSettings as $key => $value): ?>
                        <tr>
                            <td><code><?php echo htmlspecialchars($key); ?></code></td>
                            <td><strong><?php echo htmlspecialchars($value); ?></strong></td>
                        </tr>
                    <?php endforeach; ?>
                </table>
            </div>
            <?php else: ?>
                <p style="color: #999;">Настройки не найдены</p>
            <?php endif; ?>
        </div>
    </div>
    
    <div class="card">
        <h2>⚠️ Изменение настроек</h2>
        <p style="margin-bottom: 15px;">
            Для изменения настроек отредактируйте соответствующие методы в классе <code>RedisBotProtectionNoSessions</code>:
        </p>
        <ul style="line-height: 1.8;">
            <li><code>updateRateLimitSettings()</code> - настройки ограничения запросов</li>
            <li><code>updateTTLSettings()</code> - время жизни записей</li>
            <li><code>updateGlobalProtectionSettings()</code> - защита от переполнения</li>
            <li><code>updateSlowBotSettings()</code> - детекция медленных ботов</li>
            <li><code>updateRDNSSettings()</code> - настройки R-DNS верификации</li>
        </ul>
    </div>
        <?php endif; ?>
        
        <div style="text-align: center; padding: 20px; color: #888; font-size: 14px;">
            Redis MurKir Security - Admin Panel v3.1 | Работает на Redis
        </div>
    </div>
    
    <script>
        function copyToClipboard(text, element) {
            navigator.clipboard.writeText(text).then(() => {
                const originalBg = element.style.backgroundColor;
                const originalColor = element.style.color;
                element.style.backgroundColor = '#28a745';
                element.style.color = 'white';
                setTimeout(() => {
                    element.style.backgroundColor = originalBg;
                    element.style.color = originalColor;
                }, 500);
            }).catch(() => { alert('Ошибка копирования'); });
        }
        
        function filterTable(input, tableId) {
            const filter = input.value.toLowerCase();
            const table = document.getElementById(tableId);
            const rows = table.getElementsByTagName('tr');
            
            for (let i = 1; i < rows.length; i++) {
                const row = rows[i];
                let found = false;
                for (let j = 0; j < row.cells.length; j++) {
                    const cellText = row.cells[j].textContent || row.cells[j].innerText;
                    if (cellText.toLowerCase().indexOf(filter) > -1) {
                        found = true;
                        break;
                    }
                }
                row.style.display = found ? '' : 'none';
            }
        }
        
        <?php if ($section === 'dashboard'): ?>
        setTimeout(() => { location.reload(); }, 30000);
        <?php endif; ?>
    </script>
</body>
</html>
<?php
$redis->close();
?>
