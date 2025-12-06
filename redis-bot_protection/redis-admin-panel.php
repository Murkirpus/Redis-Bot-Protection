<?php
/**
 * ============================================================================
 * АДМИНИСТРАТИВНАЯ ПАНЕЛЬ ДЛЯ ЗАЩИТЫ ОТ БОТОВ
 * ============================================================================
 * 
 * Версия: v2.7.0 (оптимизированная)
 * Дата: 2025-12-04
 * Совместимость: inline_check.php v2.7.0 (оптимизированная версия)
 * 
 * СОВМЕСТИМОСТЬ:
 * ✅ Полностью совместима с оптимизированной версией inline_check.php
 * ✅ Все используемые методы присутствуют в оптимизированной версии
 * ✅ Не использует удалённые функции (testRateLimit, testBurst и др.)
 * 
 * ФУНКЦИИ:
 * ✅ Dashboard с основной статистикой
 * ✅ JS Challenge статистика
 * ✅ Управление заблокированными IP
 * ✅ Rate Limit мониторинг
 * ✅ RDNS статистика (RDNS модуль сохранён)
 * ✅ Настройки защиты
 * ✅ Логи активности
 * 
 * ============================================================================
 */
// admin_panel.php - Административная панель для управления системой защиты от ботов
session_start();

// ==================== КОНФИГУРАЦИЯ ====================
// Логин и пароль: murkir.pp.ua
define('ADMIN_USERNAME', 'murkir.pp.ua');
define('ADMIN_PASSWORD', '$2y$10$ii70/kOhru4UERa0hPRBhOw.hCrT92fLCrm6mW61QyMrnG7txfZDG'); // Временно без хеша для отладки
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

// Генерация токена для рекапчи
function generateCaptchaToken() {
    if (!isset($_SESSION['captcha_token'])) {
        $_SESSION['captcha_token'] = bin2hex(random_bytes(32));
        $_SESSION['captcha_time'] = time();
    }
    return $_SESSION['captcha_token'];
}

// Проверка рекапчи
function validateCaptcha() {
    if (!isset($_POST['captcha_token']) || !isset($_SESSION['captcha_token']) || 
        $_POST['captcha_token'] !== $_SESSION['captcha_token']) {
        return false;
    }
    if (!isset($_POST['human_check']) || $_POST['human_check'] !== 'verified') {
        return false;
    }
    if (!empty($_POST['website']) || !empty($_POST['email_confirm'])) {
        return false;
    }
    if (isset($_SESSION['captcha_time']) && (time() - $_SESSION['captcha_time']) < 2) {
        return false;
    }
    if (!isset($_POST['mouse_moved']) || $_POST['mouse_moved'] !== 'yes') {
        return false;
    }
    return true;
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
    if (!validateCaptcha()) {
        $message = 'Пожалуйста, подтвердите, что вы не робот';
        $messageType = 'error';
        break;
    }
    if (login($_POST['username'] ?? '', $_POST['password'] ?? '')) {
        unset($_SESSION['captcha_token'], $_SESSION['captcha_time']);
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
                
                case 'reset_rate_limit_new':
                    if (isLoggedIn() && !empty($_POST['ip_hash'])) {
                        $tempRedis = new Redis();
                        $tempRedis->connect('127.0.0.1', 6379);
                        $tempRedis->select(0);
                        
                        $ipHash = $_POST['ip_hash'];
                        $current = time();
                        $deleted = 0;
                        
                        // Удаляем ключ нарушений
                        $deleted += $tempRedis->del('bot_protection:tracking:rl:violations:' . $ipHash);
                        
                        // Удаляем все временные ключи через SCAN
                        $patterns = [
                            'bot_protection:tracking:rl:1m:*:' . $ipHash,
                            'bot_protection:tracking:rl:5m:*:' . $ipHash,
                            'bot_protection:tracking:rl:1h:*:' . $ipHash,
                        ];
                        
                        foreach ($patterns as $pattern) {
                            $iterator = null;
                            do {
                                $keys = $tempRedis->scan($iterator, $pattern, 100);
                                if ($keys !== false && is_array($keys)) {
                                    foreach ($keys as $key) {
                                        $tempRedis->del($key);
                                        $deleted++;
                                    }
                                }
                            } while ($iterator > 0);
                        }
                        
                        $tempRedis->close();
                        $message = "Rate limit сброшен. Удалено ключей: $deleted";
                        $messageType = 'success';
                    }
                    break;
                
                // v2.3.1: Сброс Rate Limit (новый формат)
                case 'reset_rate_limit_v2':
                    if (isLoggedIn() && !empty($_POST['key'])) {
                        $tempRedis = new Redis();
                        $tempRedis->connect('127.0.0.1', 6379);
                        $tempRedis->select(0);
                        $deleted = $tempRedis->del($_POST['key']);
                        $tempRedis->close();
                        $message = $deleted ? 'Rate limit v2.3.1 сброшен' : 'Ошибка сброса';
                        $messageType = $deleted ? 'success' : 'error';
                    }
                    break;
                
                // v2.3.1: Сброс Burst Detection
                case 'reset_burst_v2':
                    if (isLoggedIn() && !empty($_POST['key'])) {
                        $tempRedis = new Redis();
                        $tempRedis->connect('127.0.0.1', 6379);
                        $tempRedis->select(0);
                        $deleted = $tempRedis->del($_POST['key']);
                        $tempRedis->close();
                        $message = $deleted ? 'Burst сброшен' : 'Ошибка сброса';
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
                        
                        $deleted = 0;
                        $iterator = null;
                        do {
                            $keys = $tempRedis->scan($iterator, 'bot_protection:rdns:cache:*', 100);
                            if ($keys !== false && is_array($keys)) {
                                foreach ($keys as $key) {
                                    $tempRedis->del($key);
                                    $deleted++;
                                }
                            }
                        } while ($iterator > 0);
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
                        
                        // Используем SCAN вместо KEYS
                        $iterator = null;
                        do {
                            $keys = $tempRedis->scan($iterator, 'bot_protection:*', 100);
                            if ($keys !== false && is_array($keys)) {
                                foreach ($keys as $key) {
                                    $ttl = $tempRedis->ttl($key);
                                    if (($ttl > 0 && $ttl < 300) || $ttl === -2) {
                                        $tempRedis->del($key);
                                        $cleaned++;
                                    }
                                }
                            }
                        } while ($iterator > 0);
                        
                        // Очистка старых tracking записей
                        $iterator = null;
                        do {
                            $keys = $tempRedis->scan($iterator, 'bot_protection:tracking:ip:*', 100);
                            if ($keys !== false && is_array($keys)) {
                                foreach ($keys as $key) {
                                    $data = $tempRedis->get($key);
                                    if ($data && is_array($data)) {
                                        if (isset($data['first_seen']) && (time() - $data['first_seen']) > 7200) {
                                            $tempRedis->del($key);
                                            $cleaned++;
                                        }
                                    }
                                }
                            }
                        } while ($iterator > 0);
                        
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
                            'bot_protection:tracking:rl:*',           // Новые ключи rate limit
                            'bot_protection:tracking:extended:*',
                            'bot_protection:blocked:history:*'
                        ];
                        
                        foreach ($patterns as $pattern) {
                            $iterator = null;
                            do {
                                $keys = $tempRedis->scan($iterator, $pattern, 100);
                                if ($keys !== false && is_array($keys)) {
                                    foreach ($keys as $key) {
                                        $tempRedis->del($key);
                                        $cleaned++;
                                    }
                                }
                            } while ($iterator > 0);
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
                        $iterator = null;
                        do {
                            $keys = $tempRedis->scan($iterator, 'bot_protection:logs:*', 100);
                            if ($keys !== false && is_array($keys)) {
                                foreach ($keys as $key) {
                                    $tempRedis->del($key);
                                    $flushed++;
                                }
                            }
                        } while ($iterator > 0);
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
			.captcha-box {
    border: 2px solid #ddd;
    border-radius: 5px;
    padding: 15px;
    margin-bottom: 20px;
    background: #f9f9f9;
    transition: all 0.3s;
}
.captcha-box.verified {
    border-color: #10b981;
    background: #f0fff4;
}
.captcha-content {
    display: flex;
    align-items: center;
    gap: 12px;
}
.custom-checkbox {
    width: 28px;
    height: 28px;
    border: 2px solid #ccc;
    border-radius: 4px;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    background: white;
    transition: all 0.3s;
}
.custom-checkbox:hover {
    border-color: #667eea;
}
.custom-checkbox.checked {
    background: #10b981;
    border-color: #10b981;
}
.checkmark {
    display: none;
    color: white;
    font-size: 18px;
    font-weight: bold;
}
.custom-checkbox.checked .checkmark {
    display: block;
}
.spinner {
    display: none;
    width: 16px;
    height: 16px;
    border: 2px solid #eee;
    border-top: 2px solid #667eea;
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
}
.custom-checkbox.loading .spinner {
    display: block;
}
@keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
}
.hidden-field {
    position: absolute;
    left: -9999px;
}
        </style>
    </head>
    <body>
        <div class="login-container">
            <h1>🛡️ Redis MurKir Security - Admin Panel</h1>
            <?php if ($message): ?>
                <div class="error"><?php echo htmlspecialchars($message); ?></div>
            <?php endif; ?>
            <form method="POST">
			<?php $captchaToken = generateCaptchaToken(); ?>
                <input type="hidden" name="action" value="login">
				<input type="hidden" name="captcha_token" value="<?php echo $captchaToken; ?>">
<input type="hidden" name="human_check" id="humanCheck" value="">
<input type="hidden" name="mouse_moved" id="mouseMoved" value="no">
<input type="text" name="website" class="hidden-field" tabindex="-1" autocomplete="off">
<input type="email" name="email_confirm" class="hidden-field" tabindex="-1" autocomplete="off">

<div class="captcha-box" id="captchaBox">
    <div class="captcha-content">
        <div class="custom-checkbox" id="customCheckbox">
            <span class="checkmark">✓</span>
            <div class="spinner"></div>
        </div>
        <span>Я не робот</span>
    </div>
</div>
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
		<script>
let mouseMoved = false;
document.addEventListener('mousemove', function() {
    if (!mouseMoved) {
        mouseMoved = true;
        document.getElementById('mouseMoved').value = 'yes';
    }
});

const checkbox = document.getElementById('customCheckbox');
const captchaBox = document.getElementById('captchaBox');
const humanCheck = document.getElementById('humanCheck');
const loginBtn = document.querySelector('button[type="submit"]');

loginBtn.disabled = true;
loginBtn.style.opacity = '0.5';

checkbox.addEventListener('click', function() {
    if (this.classList.contains('checked')) return;
    this.classList.add('loading');
    setTimeout(function() {
        checkbox.classList.remove('loading');
        checkbox.classList.add('checked');
        captchaBox.classList.add('verified');
        humanCheck.value = 'verified';
        loginBtn.disabled = false;
        loginBtn.style.opacity = '1';
    }, 1500);
});
</script>
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

// v2.5.1: Получаем статистику запросов в реальном времени (RPM/RPS)
$requestStats = $protection->getRequestsPerMinute();

// JS Challenge статистика
$jsChallengeStats = $protection->getJSChallengeStats();

// Получаем полную статистику Redis напрямую
try {
    $redis = new Redis();
    $redis->connect('127.0.0.1', 6379);
    $redisInfo = $redis->info();
    
    // Память
    $memInfo['used_memory'] = $redisInfo['used_memory_human'] ?? 'N/A';
    $memInfo['used_memory_peak'] = $redisInfo['used_memory_peak_human'] ?? 'N/A';
    $memInfo['used_memory_bytes'] = $redisInfo['used_memory'] ?? 0;
    $memInfo['maxmemory'] = $redisInfo['maxmemory'] ?? 0;
    $memInfo['uptime_days'] = $redisInfo['uptime_in_days'] ?? 0;
    $memInfo['total_keys'] = $redisInfo['db0'] ?? '';
    
    // Парсим количество ключей из db0
    if (preg_match('/keys=(\d+)/', $memInfo['total_keys'], $m)) {
        $memInfo['total_keys'] = intval($m[1]);
    } else {
        $memInfo['total_keys'] = $redis->dbSize();
    }
    
    // Процент использования памяти
    if ($memInfo['maxmemory'] > 0) {
        $memInfo['memory_percent'] = round(($memInfo['used_memory_bytes'] / $memInfo['maxmemory']) * 100, 1);
    } else {
        // Если maxmemory не установлен, показываем относительно 100MB
        $memInfo['memory_percent'] = min(100, round(($memInfo['used_memory_bytes'] / (100 * 1024 * 1024)) * 100, 1));
    }
    
    $redis->close();
} catch (Exception $e) {
    $memInfo['used_memory'] = 'N/A';
    $memInfo['used_memory_peak'] = 'N/A';
    $memInfo['memory_percent'] = 0;
    $memInfo['uptime_days'] = 0;
    $memInfo['total_keys'] = 0;
}

// Подключение к Redis для дополнительных данных
$redis = new Redis();
$redis->connect('127.0.0.1', 6379);
$redis->select(0);
$redis->setOption(Redis::OPT_SERIALIZER, Redis::SERIALIZER_JSON);

$rdnsCurrentState = $redis->get('bot_protection:config:rdns_enabled');
if ($rdnsCurrentState === false) $rdnsCurrentState = ENABLE_RDNS;

// v2.3.1: Подсчет нарушений rate limit - ключи bot_protection:tracking:rl:{hash} с JSON данными
$totalViolations = 0;
$rateLimitCount = 0;  // Количество IP с нарушениями (violations > 0)
$iterator = null;
do {
    // v2.3.1 формат: bot_protection:tracking:rl:{hash} (без timestamps в ключе)
    $keys = $redis->scan($iterator, 'bot_protection:tracking:rl:*', 100);
    if ($keys !== false && is_array($keys)) {
        foreach ($keys as $key) {
            // Пропускаем старые ключи с timestamps (1m:, 5m:, 1h:, violations:)
            if (preg_match('/:(1m|5m|1h|violations):/', $key)) {
                continue;
            }
            $data = $redis->get($key);
            if ($data && is_array($data) && isset($data['violations'])) {
                $violations = intval($data['violations']);
                if ($violations > 0) {
                    $totalViolations += $violations;
                    $rateLimitCount++;  // Считаем только IP с нарушениями!
                }
            }
        }
    }
} while ($iterator != 0);
$stats['rate_limit_violations'] = $totalViolations;
$stats['rate_limit_tracking'] = $rateLimitCount;

// v2.3.2: Подсчет Burst Detection - IP близких к порогу или превысивших
$burstExceeded = 0;  // Превысили порог (>=100%)
$burstWarning = 0;   // Близко к порогу (50-99%)
$burstActive = 0;    // Активные (10-49%)
$burstTotal = 0;     // Всего отслеживается
$rateLimitSettings = $protection->getRateLimitSettings();
$burstThresholdDash = $rateLimitSettings['burst_threshold'] ?? 5;
$burstWindowDash = $rateLimitSettings['burst_window'] ?? 10;
$nowDash = time();
$iterator = null;
do {
    $keys = $redis->scan($iterator, 'bot_protection:tracking:burst:*', 100);
    if ($keys !== false && is_array($keys)) {
        foreach ($keys as $key) {
            // ВАЖНО: Используем полный ключ (OPT_PREFIX не установлен!)
            $data = $redis->get($key);
            if ($data && is_array($data) && isset($data['times'])) {
                $burstTotal++;
                $requestsInWindow = count(array_filter($data['times'], function($time) use ($nowDash, $burstWindowDash) {
                    return ($nowDash - $time) <= $burstWindowDash;
                }));
                $percent = round(($requestsInWindow / $burstThresholdDash) * 100);
                if ($percent >= 100) {
                    $burstExceeded++;
                } elseif ($percent >= 50) {
                    $burstWarning++;
                } elseif ($percent >= 10) {
                    $burstActive++;
                }
            }
        }
    }
} while ($iterator != 0);
$stats['burst_exceeded'] = $burstExceeded;
$stats['burst_warning'] = $burstWarning;
$stats['burst_active'] = $burstActive;
$stats['burst_total'] = $burstTotal;

// ИСПРАВЛЕНО: Подсчет верифицированных и не верифицированных R-DNS записей через SCAN
$verifiedCount = 0;
$notVerifiedCount = 0;
$rdnsCacheCount = 0;
$iterator = null;
do {
    $keys = $redis->scan($iterator, 'bot_protection:rdns:cache:*', 100);
    if ($keys !== false && is_array($keys)) {
        foreach ($keys as $key) {
            $rdnsCacheCount++;
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
} while ($iterator != 0);
$rdnsStats['verified_in_cache'] = $verifiedCount;
$rdnsStats['not_verified_in_cache'] = $notVerifiedCount;
$rdnsStats['cache_entries'] = $rdnsCacheCount;

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
        
        /* Memory Card - красивый стиль */
        .memory-card {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #e4e4e4;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .memory-card h3 {
            color: #00d9ff;
            margin-bottom: 15px;
            font-size: 16px;
        }
        .memory-bar {
            height: 30px;
            background: rgba(0,0,0,0.3);
            border-radius: 15px;
            overflow: hidden;
            margin: 15px 0;
        }
        .memory-bar-fill {
            height: 100%;
            background: linear-gradient(90deg, #4caf50, #00d9ff);
            border-radius: 15px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            font-size: 14px;
            color: #fff;
            min-width: 80px;
            transition: width 0.5s ease;
        }
        .memory-stats {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin-top: 15px;
        }
        .memory-stat {
            text-align: center;
            padding: 10px;
            background: rgba(255,255,255,0.05);
            border-radius: 8px;
        }
        .memory-stat-value {
            font-size: 20px;
            font-weight: bold;
            color: #00d9ff;
        }
        .memory-stat-label {
            font-size: 12px;
            color: #888;
            margin-top: 5px;
        }
        @media (max-width: 600px) {
            .memory-stats {
                grid-template-columns: repeat(2, 1fr);
            }
        }
        
        /* Стиль для длинных причин блокировки */
        td[title] {
            cursor: help;
        }
        .reason-text {
            max-width: 300px;
            word-wrap: break-word;
            white-space: normal;
            line-height: 1.3;
        }
        
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
			<a href="redis_test-gemini.php" target="_blank" rel="noopener noreferrer" class="btn btn-primary">📊 Test Page</a>
			<a href="https://blog.dj-x.info/redis-bot_protection/API/iptables.php?api_key=Asd12345" target="_blank" rel="noopener noreferrer" class="btn btn-primary">📊 IP</a>
			<a href="/counter-xyz/index.php" target="_blank" rel="noopener noreferrer" class="btn btn-primary">📊 Counter</a>
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
            <a href="?section=js_challenge" class="<?php echo $section === 'js_challenge' ? 'active' : ''; ?>">🛡️ JS Challenge</a>
            <a href="?section=extended_tracking" class="<?php echo $section === 'extended_tracking' ? 'active' : ''; ?>">Extended Tracking</a>
            <a href="?section=rdns" class="<?php echo $section === 'rdns' ? 'active' : ''; ?>">R-DNS</a>
            <a href="?section=user_hashes" class="<?php echo $section === 'user_hashes' ? 'active' : ''; ?>">User Hashes</a>
            <a href="?section=logs" class="<?php echo $section === 'logs' ? 'active' : ''; ?>">📝 Logs</a>
            <a href="?section=settings" class="<?php echo $section === 'settings' ? 'active' : ''; ?>">Settings</a>
        </div>
        
        <?php if ($section === 'dashboard'): ?>
            <!-- Красивая карточка памяти Redis -->
            <div class="memory-card">
                <h3>💾 Redis Память</h3>
                <div class="memory-bar">
                    <div class="memory-bar-fill" style="width: <?php echo min(100, max(5, $memInfo['memory_percent'])); ?>%">
                        <?php echo $memInfo['used_memory']; ?>
                    </div>
                </div>
                <div class="memory-stats">
                    <div class="memory-stat">
                        <div class="memory-stat-value"><?php echo $memInfo['used_memory']; ?></div>
                        <div class="memory-stat-label">Используется</div>
                    </div>
                    <div class="memory-stat">
                        <div class="memory-stat-value"><?php echo $memInfo['used_memory_peak']; ?></div>
                        <div class="memory-stat-label">Пик</div>
                    </div>
                    <div class="memory-stat">
                        <div class="memory-stat-value"><?php echo number_format($memInfo['total_keys']); ?></div>
                        <div class="memory-stat-label">Всего ключей</div>
                    </div>
                    <div class="memory-stat">
                        <div class="memory-stat-value"><?php echo $memInfo['uptime_days']; ?> дн</div>
                        <div class="memory-stat-label">Uptime</div>
                    </div>
                </div>
            </div>
            
            <!-- Карточка статистики запросов в реальном времени -->
            <div class="traffic-card" style="background: white; border-radius: 10px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.05);">
                <h3 style="margin: 0 0 15px 0; color: #333; font-size: 16px;">📊 Трафик в реальном времени</h3>
                <div style="display: flex; justify-content: space-around; flex-wrap: wrap; gap: 15px;">
                    <div style="text-align: center; min-width: 100px;">
                        <div style="font-size: 36px; font-weight: bold; color: <?php echo $requestStats['current_rps'] > 50 ? '#ef4444' : ($requestStats['current_rps'] > 20 ? '#f59e0b' : '#10b981'); ?>;">
                            <?php echo number_format($requestStats['current_rps']); ?>
                        </div>
                        <div style="font-size: 12px; color: #888;">RPS (текущий)</div>
                    </div>
                    <div style="text-align: center; min-width: 100px;">
                        <div style="font-size: 36px; font-weight: bold; color: <?php echo $requestStats['peak_rps'] > 100 ? '#ef4444' : ($requestStats['peak_rps'] > 50 ? '#f59e0b' : '#667eea'); ?>;">
                            <?php echo number_format($requestStats['peak_rps']); ?>
                        </div>
                        <div style="font-size: 12px; color: #888;">RPS (пик 10 сек)</div>
                    </div>
                    <div style="text-align: center; min-width: 100px;">
                        <div style="font-size: 36px; font-weight: bold; color: #667eea;">
                            <?php echo number_format($requestStats['previous_rpm']); ?>
                        </div>
                        <div style="font-size: 12px; color: #888;">RPM (прошлая мин)</div>
                    </div>
                    <div style="text-align: center; min-width: 100px;">
                        <div style="font-size: 36px; font-weight: bold; color: #764ba2;">
                            <?php echo number_format($requestStats['current_rpm']); ?>
                        </div>
                        <div style="font-size: 12px; color: #888;">RPM (текущая мин)</div>
                    </div>
                    <div style="text-align: center; min-width: 100px;">
                        <div style="font-size: 36px; font-weight: bold; color: #10b981;">
                            <?php echo $requestStats['avg_rps']; ?>
                        </div>
                        <div style="font-size: 12px; color: #888;">Средний RPS</div>
                    </div>
                </div>
            </div>
            
            <div class="stats-grid">
                <div class="stat-card <?php echo $stats['blocked_ips'] > 100 ? 'warning' : ''; ?>">
                    <h3>🚫 Заблокировано IP</h3>
                    <div class="value"><?php echo number_format($stats['blocked_ips']); ?></div>
                </div>
                
                <div class="stat-card <?php echo ($stats['user_hash_blocked'] ?? 0) > 50 ? 'warning' : ''; ?>">
                    <h3>🔒 Заблокировано Hashes</h3>
                    <div class="value"><?php echo number_format($stats['user_hash_blocked'] ?? 0); ?></div>
                </div>
                
                <div class="stat-card <?php echo $stats['blocked_cookies'] > 50 ? 'warning' : ''; ?>">
                    <h3>🍪 Заблокировано Cookies</h3>
                    <div class="value"><?php echo number_format($stats['blocked_cookies']); ?></div>
                </div>
                
                <div class="stat-card">
                    <h3>👁️ Отслеживаемых IP</h3>
                    <div class="value"><?php echo number_format($stats['tracking_records']); ?></div>
                </div>
                
                <div class="stat-card <?php echo $stats['extended_tracking_active'] > 20 ? 'warning' : ''; ?>">
                    <h3>🔍 Extended Tracking</h3>
                    <div class="value"><?php echo number_format($stats['extended_tracking_active']); ?></div>
                </div>
                
                <div class="stat-card <?php echo $stats['rate_limit_violations'] > 50 ? 'danger' : ''; ?>">
                    <h3>⚡ Rate Limit нарушений</h3>
                    <div class="value"><?php echo number_format($stats['rate_limit_violations']); ?></div>
                    <small style="color: #666;">от <?php echo number_format($stats['rate_limit_tracking']); ?> IP</small>
                </div>
                
                <div class="stat-card <?php echo $stats['burst_exceeded'] > 0 ? 'danger' : ($stats['burst_warning'] > 0 ? 'warning' : ''); ?>">
                    <h3>🔥 Burst Detection</h3>
                    <div class="value"><?php echo number_format($stats['burst_exceeded']); ?></div>
                    <small style="color: #666;">
                        ⚠️ <?php echo number_format($stats['burst_warning']); ?> близко (50-99%) | 
                        👁️ <?php echo number_format($stats['burst_active']); ?> активны (10-49%) | 
                        📊 <?php echo number_format($stats['burst_total']); ?> всего
                    </small>
                </div>
                
                <div class="stat-card <?php echo $jsChallengeStats['success_rate'] < 70 ? 'danger' : ($jsChallengeStats['success_rate'] < 90 ? 'warning' : ''); ?>">
                    <h3>🛡️ JS Challenge</h3>
                    <div class="value"><?php echo number_format($jsChallengeStats['total_shown']); ?></div>
                    <small style="color: #666;">✓ <?php echo number_format($jsChallengeStats['total_passed']); ?> прошло (<?php echo $jsChallengeStats['success_rate']; ?>%)</small>
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
                            <td>Верифицировано (поисковики)</td>
                            <td><span class="badge badge-success">✓ <?php echo $rdnsStats['verified_in_cache']; ?></span></td>
                        </tr>
                        <tr>
                            <td>Не верифицировано</td>
                            <td><span class="badge badge-danger"><?php echo $rdnsStats['not_verified_in_cache']; ?></span></td>
                        </tr>
                        <tr>
                            <td>Доверие по UA при лимите</td>
                            <td>
                                <?php 
                                $rdnsSettings = $protection->getRDNSSettings();
                                if (!empty($rdnsSettings['trust_search_engine_ua_on_limit'])): ?>
                                    <span class="badge badge-success">✓ Включено</span>
                                <?php else: ?>
                                    <span class="badge badge-warning">Выключено</span>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <tr>
                            <td>Статус лимита</td>
                            <td>
                                <?php if ($rdnsStats['limit_reached']): ?>
                                    <span class="badge badge-danger">⚠️ Превышен</span>
                                <?php else: ?>
                                    <span class="badge badge-success">✓ Норма</span>
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
                    
                    <h3 style="margin-top: 20px; margin-bottom: 10px;">Rate Limit Info</h3>
                    <table>
                        <?php $rateLimitSettings = $protection->getRateLimitSettings(); ?>
                        <tr>
                            <td>Лимит/мин</td>
                            <td><strong><?php echo $rateLimitSettings['max_requests_per_minute'] ?? 60; ?></strong></td>
                        </tr>
                        <tr>
                            <td>Лимит/5 мин</td>
                            <td><strong><?php echo $rateLimitSettings['max_requests_per_5min'] ?? 200; ?></strong></td>
                        </tr>
                        <tr>
                            <td>Лимит/час</td>
                            <td><strong><?php echo $rateLimitSettings['max_requests_per_hour'] ?? 1000; ?></strong></td>
                        </tr>
                    </table>
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
                                    <td style="max-width: 300px; font-size: 11px; word-wrap: break-word;" title="<?php echo htmlspecialchars($data['blocked_reason'] ?? 'N/A'); ?>">
                                        <?php echo htmlspecialchars($data['blocked_reason'] ?? 'N/A'); ?>
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
                                    <td style="max-width: 300px; font-size: 11px; word-wrap: break-word;" title="<?php echo htmlspecialchars($data['blocked_reason'] ?? 'N/A'); ?>">
                                        <?php echo htmlspecialchars($data['blocked_reason'] ?? 'N/A'); ?>
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
        <h2>⚡ Rate Limit и Burst Detection (v2.3.1)</h2>
        <p style="margin-bottom: 15px; color: #666;">
            <strong>Rate Limit</strong> — ограничение по количеству запросов.<br>
            <strong>Burst Detection</strong> — детекция быстрых всплесков.<br>
            <strong>Cookie Multiplier</strong> — пользователи с cookie получают увеличенные лимиты.
        </p>
        <?php
        // Получаем лимиты из настроек
        $rateLimitSettings = $protection->getRateLimitSettings();
        $limit1min = $rateLimitSettings['max_requests_per_minute'] ?? 60;
        $limit5min = $rateLimitSettings['max_requests_per_5min'] ?? 200;
        $limit1hour = $rateLimitSettings['max_requests_per_hour'] ?? 800;
        $burstThreshold = $rateLimitSettings['burst_threshold'] ?? 5;
        $burstWindow = $rateLimitSettings['burst_window'] ?? 10;
        $cookieMultiplier = $rateLimitSettings['cookie_multiplier'] ?? 2.0;
        ?>
        
        <!-- Информация о лимитах -->
        <div style="background: linear-gradient(135deg, #1a1a2e, #16213e); color: #e4e4e4; padding: 20px; border-radius: 12px; margin-bottom: 20px;">
            <h3 style="color: #00d9ff; margin-bottom: 15px;">📋 Текущие лимиты</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px;">
                <div style="background: rgba(255,255,255,0.05); padding: 10px; border-radius: 8px;">
                    <div style="color: #888; font-size: 12px;">🚫 Без cookie</div>
                    <div><code style="color: #ff6b6b;"><?php echo $limit1min; ?></code>/мин | <code style="color: #ffc107;"><?php echo $limit5min; ?></code>/5мин | <code style="color: #4caf50;"><?php echo $limit1hour; ?></code>/час</div>
                </div>
                <div style="background: rgba(255,255,255,0.05); padding: 10px; border-radius: 8px;">
                    <div style="color: #888; font-size: 12px;">🍪 С cookie (×<?php echo $cookieMultiplier; ?>)</div>
                    <div><code style="color: #ff6b6b;"><?php echo intval($limit1min * $cookieMultiplier); ?></code>/мин | <code style="color: #ffc107;"><?php echo intval($limit5min * $cookieMultiplier); ?></code>/5мин | <code style="color: #4caf50;"><?php echo intval($limit1hour * $cookieMultiplier); ?></code>/час</div>
                </div>
                <div style="background: rgba(255,255,255,0.05); padding: 10px; border-radius: 8px;">
                    <div style="color: #888; font-size: 12px;">🔥 Burst порог</div>
                    <div><code style="color: #00d9ff;"><?php echo $burstThreshold; ?></code> / <code style="color: #00d9ff;"><?php echo intval($burstThreshold * $cookieMultiplier); ?></code> запросов за <?php echo $burstWindow; ?> сек</div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Burst Detection Статистика -->
    <div class="stats-grid" style="margin-top: 20px;">
        <div class="stat-card <?php echo $stats['burst_exceeded'] > 0 ? 'danger' : ''; ?>">
            <h3>🔥 Burst Exceeded (≥100%)</h3>
            <div class="value"><?php echo number_format($stats['burst_exceeded']); ?></div>
            <small style="color: #666;">Превысили порог</small>
        </div>
        
        <div class="stat-card <?php echo $stats['burst_warning'] > 0 ? 'warning' : ''; ?>">
            <h3>⚠️ Burst Warning (50-99%)</h3>
            <div class="value"><?php echo number_format($stats['burst_warning']); ?></div>
            <small style="color: #666;">Близко к порогу</small>
        </div>
        
        <div class="stat-card">
            <h3>👁️ Burst Active (10-49%)</h3>
            <div class="value"><?php echo number_format($stats['burst_active']); ?></div>
            <small style="color: #666;">Активные</small>
        </div>
        
        <div class="stat-card">
            <h3>📊 Burst Total</h3>
            <div class="value"><?php echo number_format($stats['burst_total']); ?></div>
            <small style="color: #666;">Всего отслеживается</small>
        </div>
        
        <div class="stat-card <?php echo $stats['rate_limit_violations'] > 50 ? 'danger' : ($stats['rate_limit_violations'] > 10 ? 'warning' : ''); ?>">
            <h3>⚡ Rate Limit нарушений</h3>
            <div class="value"><?php echo number_format($stats['rate_limit_violations']); ?></div>
            <small style="color: #666;">от <?php echo number_format($stats['rate_limit_tracking']); ?> IP</small>
        </div>
    </div>

    <!-- Rate Limit Records -->
    <div class="card" style="margin-top: 20px;">
        <h2>🚫 Rate Limit нарушители</h2>
        <?php
        // v2.3.1: Сканируем ключи bot_protection:tracking:rl:{hash}
        $allRateLimits = [];
        $totalTracking = 0;
        $iterator = null;
        
        do {
            $keys = $redis->scan($iterator, 'bot_protection:tracking:rl:*', 100);
            if ($keys !== false && is_array($keys)) {
                foreach ($keys as $key) {
                    // Пропускаем старые ключи с timestamps
                    if (preg_match('/:(1m|5m|1h|violations):/', $key)) {
                        continue;
                    }
                    $data = $redis->get($key);
                    if ($data && is_array($data)) {
                        $totalTracking++;
                        $violations = intval($data['violations'] ?? 0);
                        
                        // Показываем ТОЛЬКО с нарушениями
                        if ($violations > 0) {
                            $ipHash = str_replace('bot_protection:tracking:rl:', '', $key);
                            
                            $allRateLimits[] = [
                                'hash' => $ipHash,
                                'violations' => $violations,
                                'requests_1min' => intval($data['min'] ?? 0),
                                'requests_5min' => intval($data['min5'] ?? 0),
                                'requests_1hour' => intval($data['hour'] ?? 0),
                                'ttl' => $redis->ttl($key),
                                'key' => $key,
                                'ip_from_data' => $data['ip'] ?? null  // IP из данных v2.3.2+
                            ];
                        }
                    }
                }
            }
        } while ($iterator != 0);
        
        // Сортируем по количеству нарушений
        usort($allRateLimits, function($a, $b) {
            if ($b['violations'] != $a['violations']) {
                return $b['violations'] - $a['violations'];
            }
            return $b['requests_1hour'] - $a['requests_1hour'];
        });
        
        $total = count($allRateLimits);
        $offset = ($page - 1) * ITEMS_PER_PAGE;
        $pageRateLimits = array_slice($allRateLimits, $offset, ITEMS_PER_PAGE);
        
        // Получаем IP для каждой записи (сначала из данных RL, потом из tracking:ip)
        foreach ($pageRateLimits as &$rlData) {
            // Сначала проверяем IP прямо в данных rate limit (v2.3.2+)
            if (isset($rlData['ip_from_data']) && $rlData['ip_from_data'] !== null) {
                $rlData['ip'] = $rlData['ip_from_data'];
            } else {
                // Fallback: ищем в tracking:ip
                $trackingKey = 'bot_protection:tracking:ip:' . $rlData['hash'];
                $trackingData = $redis->get($trackingKey);
                
                if ($trackingData && is_array($trackingData) && isset($trackingData['real_ip'])) {
                    $rlData['ip'] = $trackingData['real_ip'];
                } else {
                    $rlData['ip'] = 'N/A';
                }
            }
        }
        unset($rlData);
        ?>
        
        <p style="margin-bottom: 15px;">
            <span class="badge badge-danger" style="font-size: 14px;">🚫 Нарушителей: <?php echo $total; ?></span>
            <span class="badge badge-info" style="font-size: 14px; margin-left: 10px;">📊 Всего отслеживается: <?php echo $totalTracking; ?></span>
        </p>
        
        <?php if ($total > 0): ?>
            <div class="table-wrapper" style="overflow-x: auto;">
            <table>
                <thead>
                    <tr>
                        <th>IP адрес</th>
                        <th>Нарушений</th>
                        <th>Мин (<?php echo $limit1min; ?>)</th>
                        <th>5мин (<?php echo $limit5min; ?>)</th>
                        <th>Час (<?php echo $limit1hour; ?>)</th>
                        <th>TTL</th>
                        <th>Действия</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($pageRateLimits as $rlData): 
                        $violations = $rlData['violations'];
                        $rowClass = $violations > 0 ? ($violations > 5 ? 'danger-critical' : 'danger-warning') : '';
                    ?>
                        <tr class="<?php echo $rowClass; ?>">
                            <td><code><?php echo htmlspecialchars($rlData['ip']); ?></code></td>
                            <td>
                                <?php if ($violations > 0): ?>
                                    <span class="badge badge-danger"><?php echo $violations; ?></span>
                                <?php else: ?>
                                    <span style="color: #999;">0</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <strong><?php echo $rlData['requests_1min']; ?></strong>
                                <?php if ($rlData['requests_1min'] > $limit1min * 0.8): ?>
                                    <span class="badge badge-warning" style="font-size: 10px;">⚠️</span>
                                <?php endif; ?>
                            </td>
                            <td><strong><?php echo $rlData['requests_5min']; ?></strong></td>
                            <td><strong><?php echo $rlData['requests_1hour']; ?></strong></td>
                            <td><?php echo $rlData['ttl'] > 0 ? floor($rlData['ttl'] / 60) . 'м' : '—'; ?></td>
                            <td>
                                <form method="POST" style="display: inline;">
                                    <input type="hidden" name="action" value="reset_rate_limit_v2">
                                    <input type="hidden" name="key" value="<?php echo htmlspecialchars($rlData['key']); ?>">
                                    <button type="submit" class="btn btn-small btn-warning" onclick="return confirm('Сбросить?');">Reset</button>
                                </form>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            </div>
            <?php if (ceil($total / ITEMS_PER_PAGE) > 1): ?>
                <div class="pagination">
                    <?php for ($i = 1; $i <= min(ceil($total / ITEMS_PER_PAGE), 10); $i++): ?>
                        <a href="?section=rate_limits&page=<?php echo $i; ?>" class="<?php echo $i === $page ? 'active' : ''; ?>"><?php echo $i; ?></a>
                    <?php endfor; ?>
                </div>
            <?php endif; ?>
        <?php else: ?>
            <div class="message success">✅ Нет нарушителей Rate Limit!</div>
        <?php endif; ?>
    </div>
    
    <!-- Burst Detection -->
    <div class="card" style="margin-top: 20px;">
        <h2>🔥 Burst Detection</h2>
        <?php
        // v2.3.1: Сканируем ключи bot_protection:tracking:burst:{hash}
        $allBursts = [];
        $dangerousBursts = [];
        $totalBurstTracking = 0;
        $iterator = null;
        $now = time();
        
        do {
            $keys = $redis->scan($iterator, 'bot_protection:tracking:burst:*', 100);
            if ($keys !== false && is_array($keys)) {
                foreach ($keys as $key) {
                    // ВАЖНО: Используем полный ключ (OPT_PREFIX не установлен!)
                    $data = $redis->get($key);
                    if ($data && is_array($data) && isset($data['times'])) {
                        $totalBurstTracking++;
                        $ipHash = str_replace('bot_protection:tracking:burst:', '', $key);
                        
                        // Считаем запросы в текущем окне
                        $requestsInWindow = count(array_filter($data['times'], function($time) use ($now, $burstWindow) {
                            return ($now - $time) <= $burstWindow;
                        }));
                        
                        $percent = round(($requestsInWindow / $burstThreshold) * 100);
                        
                        // Показываем все активные (>=10% от порога) - было >=50%
                        if ($percent >= 10 || $requestsInWindow > 0) {
                            // Получаем IP - сначала из данных burst (v2.3.2+), потом fallback на tracking:ip
                            $ip = $data['ip'] ?? null;
                            if (!$ip) {
                                $trackingKey = 'bot_protection:tracking:ip:' . $ipHash;
                                $trackingData = $redis->get($trackingKey);
                                $ip = ($trackingData && isset($trackingData['real_ip'])) ? $trackingData['real_ip'] : 'N/A';
                            }
                            
                            // Проверяем заблокирован ли IP
                            $isBlocked = $redis->exists('bot_protection:blocked:ip:' . hash('md5', $ip));
                            $exceeded = $data['exceeded'] ?? false; // Маркер превышения порога
                            
                            $dangerousBursts[] = [
                                'hash' => $ipHash,
                                'ip' => $ip,
                                'requests_in_window' => $requestsInWindow,
                                'total_times' => count($data['times']),
                                'ttl' => $redis->ttl($key),
                                'key' => $key,
                                'percent' => $percent,
                                'is_blocked' => $isBlocked,
                                'exceeded' => $exceeded
                            ];
                        }
                    }
                }
            }
        } while ($iterator != 0);
        
        // Сортируем по активности
        usort($dangerousBursts, function($a, $b) {
            return $b['percent'] - $a['percent'];
        });
        
        $dangerousBursts = array_slice($dangerousBursts, 0, 100); // Было 30, стало 100
        $exceededCount = count(array_filter($dangerousBursts, function($b) { return $b['percent'] >= 100; }));
        $warningCount = count(array_filter($dangerousBursts, function($b) { return $b['percent'] >= 50 && $b['percent'] < 100; }));
        $activeCount = count(array_filter($dangerousBursts, function($b) { return $b['percent'] >= 10 && $b['percent'] < 50; }));
        ?>
        
        <p style="margin-bottom: 15px;">
            <?php if ($exceededCount > 0): ?>
                <span class="badge badge-danger" style="font-size: 14px;">🔥 Превысили порог (≥100%): <?php echo $exceededCount; ?></span>
            <?php endif; ?>
            <?php if ($warningCount > 0): ?>
                <span class="badge badge-warning" style="font-size: 14px; margin-left: 10px;">⚠️ Близко к порогу (50-99%): <?php echo $warningCount; ?></span>
            <?php endif; ?>
            <?php if ($activeCount > 0): ?>
                <span class="badge badge-info" style="font-size: 14px; margin-left: 10px;">👁️ Активные (10-49%): <?php echo $activeCount; ?></span>
            <?php endif; ?>
            <span class="badge badge-neutral" style="font-size: 14px; margin-left: 10px;">📊 Всего отслеживается: <?php echo $totalBurstTracking; ?></span>
            <span class="badge badge-neutral" style="font-size: 13px; margin-left: 10px;">💡 Показано топ-100</span>
        </p>
        
        <?php if (!empty($dangerousBursts)): ?>
            <div class="table-wrapper" style="overflow-x: auto;">
            <table>
                <thead>
                    <tr>
                        <th>IP адрес</th>
                        <th>Запросов/<?php echo $burstWindow; ?>с</th>
                        <th>% от порога</th>
                        <th>Статус</th>
                        <th>Всего записей</th>
                        <th>TTL</th>
                        <th>Действия</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($dangerousBursts as $burst): 
                        $badgeClass = $burst['percent'] >= 100 ? 'badge-danger' : ($burst['percent'] >= 70 ? 'badge-warning' : 'badge-info');
                        
                        // Определяем статус
                        if ($burst['is_blocked']) {
                            $statusBadge = '<span class="badge badge-danger" style="font-size: 11px;">🚫 BLOCKED</span>';
                        } elseif ($burst['exceeded']) {
                            $statusBadge = '<span class="badge badge-warning" style="font-size: 11px;">⚠️ EXCEEDED</span>';
                        } elseif ($burst['percent'] >= 50) {
                            $statusBadge = '<span class="badge badge-warning" style="font-size: 11px;">⚡ WARNING</span>';
                        } else {
                            $statusBadge = '<span class="badge badge-info" style="font-size: 11px;">👁️ ACTIVE</span>';
                        }
                    ?>
                        <tr>
                            <td><code><?php echo htmlspecialchars($burst['ip']); ?></code></td>
                            <td><strong><?php echo $burst['requests_in_window']; ?></strong> / <?php echo $burstThreshold; ?></td>
                            <td><span class="badge <?php echo $badgeClass; ?>"><?php echo $burst['percent']; ?>%</span></td>
                            <td><?php echo $statusBadge; ?></td>
                            <td><?php echo $burst['total_times']; ?></td>
                            <td><?php echo $burst['ttl']; ?>с</td>
                            <td>
                                <form method="POST" style="display: inline;">
                                    <input type="hidden" name="action" value="reset_burst_v2">
                                    <input type="hidden" name="key" value="<?php echo htmlspecialchars($burst['key']); ?>">
                                    <button type="submit" class="btn btn-small btn-warning" onclick="return confirm('Сбросить burst?');">Reset</button>
                                </form>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            </div>
        <?php else: ?>
            <div class="message info" style="background: #e3f2fd; border-color: #2196f3; color: #1565c0;">
                ℹ️ Нет активной Burst активности (все IP ниже 10% от порога).
                <?php if ($totalBurstTracking > 0): ?>
                    <br><small>Отслеживается IP: <?php echo $totalBurstTracking; ?>, но все запросы в пределах нормы.</small>
                <?php endif; ?>
            </div>
        <?php endif; ?>
    </div>

        <?php elseif ($section === 'js_challenge'): ?>
            <div class="card">
                <h2>🛡️ JS Challenge - JavaScript проверка браузера</h2>
                <p>Система защиты от ботов через JavaScript Challenge. Проверяет что запросы идут от настоящего браузера, а не бота.</p>
                
                <!-- Статистика -->
                <div class="stats-grid" style="margin-top: 20px;">
                    <div class="stat-card">
                        <h3>📊 Показов (всего)</h3>
                        <div class="value"><?php echo number_format($jsChallengeStats['total_shown']); ?></div>
                    </div>
                    
                    <div class="stat-card">
                        <h3>✅ Пройдено (всего)</h3>
                        <div class="value"><?php echo number_format($jsChallengeStats['total_passed']); ?></div>
                    </div>
                    
                    <div class="stat-card">
                        <h3>📅 Показов (сегодня)</h3>
                        <div class="value"><?php echo number_format($jsChallengeStats['today_shown']); ?></div>
                    </div>
                    
                    <div class="stat-card">
                        <h3>✓ Пройдено (сегодня)</h3>
                        <div class="value"><?php echo number_format($jsChallengeStats['today_passed']); ?></div>
                    </div>
                    
                    <div class="stat-card <?php echo $jsChallengeStats['active_tokens'] > 100 ? 'warning' : ''; ?>">
                        <h3>🎫 Активных токенов</h3>
                        <div class="value"><?php echo number_format($jsChallengeStats['active_tokens']); ?></div>
                        <small style="color: #666;">TTL: 1 час</small>
                    </div>
                    
                    <div class="stat-card <?php echo $jsChallengeStats['success_rate'] < 70 ? 'danger' : ($jsChallengeStats['success_rate'] < 90 ? 'warning' : ''); ?>">
                        <h3>📈 Success Rate</h3>
                        <div class="value"><?php echo $jsChallengeStats['success_rate']; ?>%</div>
                        <small style="color: #666;"><?php 
                            if ($jsChallengeStats['success_rate'] >= 90) {
                                echo '✅ Отлично';
                            } elseif ($jsChallengeStats['success_rate'] >= 70) {
                                echo '⚠️ Нормально';
                            } else {
                                echo '❌ Низкий';
                            }
                        ?></small>
                    </div>
                </div>
                
                <!-- Информация о проверках -->
                <h3 style="margin-top: 30px;">Проверки браузера</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Проверка</th>
                            <th>Описание</th>
                            <th>Цель</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><strong>✓ JavaScript execution</strong></td>
                            <td>Проверка выполнения JavaScript кода</td>
                            <td>Боты часто не выполняют JS</td>
                        </tr>
                        <tr>
                            <td><strong>✓ Canvas fingerprint</strong></td>
                            <td>Уникальный отпечаток браузера через Canvas</td>
                            <td>Идентификация устройства</td>
                        </tr>
                        <tr>
                            <td><strong>✓ WebGL rendering</strong></td>
                            <td>Проверка WebGL поддержки и GPU</td>
                            <td>Сложно эмулировать для ботов</td>
                        </tr>
                        <tr>
                            <td><strong>✓ Timing validation</strong></td>
                            <td>Проверка времени выполнения (мин. 2 сек)</td>
                            <td>Защита от replay атак</td>
                        </tr>
                        <tr>
                            <td><strong>✓ Proof of Work</strong></td>
                            <td>Вычислительная задача (хеш с нулями)</td>
                            <td>Нагрузка на ботов (опционально)</td>
                        </tr>
                        <tr>
                            <td><strong>✓ Behavior analysis</strong></td>
                            <td>Анализ поведения (screen, language, timezone)</td>
                            <td>Детекция headless браузеров</td>
                        </tr>
                    </tbody>
                </table>
                
                <!-- Настройки -->
                <?php 
                $jsSettings = $protection->getJSChallengeSettings();
                ?>
                <h3 style="margin-top: 30px;">⚙️ Текущие настройки</h3>
                <table>
                    <tbody>
                        <tr>
                            <td><strong>Включен</strong></td>
                            <td>
                                <?php if ($jsSettings['enabled']): ?>
                                    <span class="badge badge-success">✓ Да</span>
                                <?php else: ?>
                                    <span class="badge badge-danger">✗ Нет</span>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <tr>
                            <td><strong>Порог нарушений</strong></td>
                            <td><?php echo $jsSettings['violations_threshold']; ?> (показывать Challenge после стольких violations)</td>
                        </tr>
                        <tr>
                            <td><strong>Порог без cookie</strong></td>
                            <td><?php echo $jsSettings['no_cookie_threshold']; ?> запросов (показывать если нет cookie)</td>
                        </tr>
                        <tr>
                            <td><strong>TTL токена</strong></td>
                            <td><?php echo round($jsSettings['token_ttl'] / 60); ?> минут (<?php echo $jsSettings['token_ttl']; ?> сек)</td>
                        </tr>
                        <tr>
                            <td><strong>Минимальное время</strong></td>
                            <td><?php echo $jsSettings['min_solve_time']; ?> мс (защита от автоматизации)</td>
                        </tr>
                        <tr>
                            <td><strong>Сложность PoW</strong></td>
                            <td><?php echo $jsSettings['pow_difficulty']; ?> нулей (<?php 
                                if ($jsSettings['pow_difficulty'] <= 3) {
                                    echo 'лёгкая, ~50-500ms';
                                } elseif ($jsSettings['pow_difficulty'] == 4) {
                                    echo 'средняя, ~200-1500ms';
                                } else {
                                    echo 'сложная, ~500-2000ms';
                                }
                            ?>)</td>
                        </tr>
                        <tr>
                            <td><strong>Триггеры</strong></td>
                            <td>
                                <?php if ($jsSettings['trigger_on_high_violations']): ?>
                                    <span class="badge badge-info">Высокие violations</span>
                                <?php endif; ?>
                                <?php if ($jsSettings['trigger_on_slow_bot']): ?>
                                    <span class="badge badge-info">Slow bot</span>
                                <?php endif; ?>
                                <?php if ($jsSettings['trigger_on_no_cookie']): ?>
                                    <span class="badge badge-info">No cookie</span>
                                <?php endif; ?>
                                <?php if ($jsSettings['trigger_on_suspicious']): ?>
                                    <span class="badge badge-info">Подозрительное поведение</span>
                                <?php endif; ?>
                            </td>
                        </tr>
                    </tbody>
                </table>
                
                <!-- Как работает -->
                <h3 style="margin-top: 30px;">💡 Как работает</h3>
                <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin-top: 10px;">
                    <ol style="margin: 0; padding-left: 20px;">
                        <li><strong>Триггер:</strong> При подозрительной активности (3+ violations, slow bot, 5+ запросов без cookie)</li>
                        <li><strong>Показ Challenge:</strong> Пользователь видит страницу "Security Verification"</li>
                        <li><strong>Проверки:</strong> JavaScript выполняет 6 проверок браузера (~2-5 сек)</li>
                        <li><strong>Верификация:</strong> Сервер проверяет все данные</li>
                        <li><strong>Токен:</strong> При успехе создаётся токен на 1 час (cookie: murkir_js_token)</li>
                        <li><strong>Результат:</strong> Пользователь не видит Challenge следующий час</li>
                    </ol>
                </div>
                
                <!-- Преимущества -->
                <h3 style="margin-top: 30px;">✅ Преимущества</h3>
                <div style="background: #e8f5e9; padding: 15px; border-radius: 8px; margin-top: 10px;">
                    <ul style="margin: 0; padding-left: 20px;">
                        <li>✓ Блокирует простых ботов (curl, wget, scrapers)</li>
                        <li>✓ Затрудняет Selenium/Puppeteer ботов</li>
                        <li>✓ Защита от распределённого парсинга</li>
                        <li>✓ Красивый UI (не пугает пользователей)</li>
                        <li>✓ Токен на 1 час (не надоедает)</li>
                        <li>✓ Легко настраивается</li>
                    </ul>
                </div>
                
                <!-- Статистика по дням -->
                <?php
                try {
                    $redis = new Redis();
                    $redis->connect('127.0.0.1', 6379);
                    $redis->setOption(Redis::OPT_PREFIX, 'bot_protection:');
                    
                    echo '<h3 style="margin-top: 30px;">📅 Статистика по дням (последние 7 дней)</h3>';
                    echo '<table>';
                    echo '<thead><tr><th>Дата</th><th>Показов</th><th>Пройдено</th><th>Success Rate</th></tr></thead>';
                    echo '<tbody>';
                    
                    for ($i = 6; $i >= 0; $i--) {
                        $date = date('Y-m-d', strtotime("-$i days"));
                        $dayKey = "js_challenge:stats:$date";
                        $dayStats = $redis->hgetall($dayKey);
                        
                        $shown = (int)($dayStats['js_challenge_shown'] ?? 0);
                        $passed = (int)($dayStats['js_challenge_passed'] ?? 0);
                        $rate = $shown > 0 ? round(($passed / $shown) * 100, 1) : 0;
                        
                        if ($shown > 0) {
                            echo '<tr>';
                            echo '<td>' . date('d.m.Y', strtotime($date)) . ($i === 0 ? ' (сегодня)' : '') . '</td>';
                            echo '<td>' . number_format($shown) . '</td>';
                            echo '<td>' . number_format($passed) . '</td>';
                            echo '<td>';
                            if ($rate >= 90) {
                                echo '<span class="badge badge-success">' . $rate . '%</span>';
                            } elseif ($rate >= 70) {
                                echo '<span class="badge badge-warning">' . $rate . '%</span>';
                            } else {
                                echo '<span class="badge badge-danger">' . $rate . '%</span>';
                            }
                            echo '</td>';
                            echo '</tr>';
                        }
                    }
                    
                    echo '</tbody></table>';
                    
                    $redis->close();
                } catch (Exception $e) {
                    echo '<div class="message error">Ошибка получения статистики по дням: ' . htmlspecialchars($e->getMessage()) . '</div>';
                }
                ?>
                
                <!-- Логи -->
                <h3 style="margin-top: 30px;">📝 Последние события</h3>
                <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin-top: 10px; font-family: monospace; font-size: 12px;">
                    <?php
                    $logFile = '/var/log/php-fpm/kinoprostor-error.log';
                    if (@file_exists($logFile)) {
                        $logs = @shell_exec("grep 'JS CHALLENGE' $logFile | tail -20");
                        if ($logs) {
                            echo '<pre style="margin: 0; white-space: pre-wrap;">' . htmlspecialchars($logs) . '</pre>';
                        } else {
                            echo '<p style="color: #666; margin: 0;">Нет логов JS Challenge</p>';
                        }
                    } else {
                        echo '<p style="color: #666; margin: 0;">Файл логов недоступен (open_basedir ограничение)</p>';
                    }
                    ?>
                </div>
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
                                    <td style="font-size: 11px;" title="<?php echo htmlspecialchars($data['reason'] ?? 'N/A'); ?>"><span class="badge badge-warning"><?php echo htmlspecialchars($data['reason'] ?? 'N/A'); ?></span></td>
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
                } while ($iterator != 0);
                
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
                                    <td style="font-size: 11px;" title="<?php if ($type === 'blocked') echo htmlspecialchars($data['blocked_reason'] ?? 'N/A'); ?>"><?php if ($type === 'blocked') echo htmlspecialchars($data['blocked_reason'] ?? 'N/A'); elseif ($type === 'tracking') echo 'First: ' . date('H:i', $data['first_seen'] ?? 0); ?></td>
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
        
        <div class="card">
            <h2>🔍 rDNS настройки (Защита поисковиков)</h2>
            <?php 
            $rdnsSettings = $protection->getRDNSSettings(); 
            if (!empty($rdnsSettings)):
            ?>
            <div class="table-wrapper">
                <table>
                    <?php foreach ($rdnsSettings as $key => $value): ?>
                        <tr>
                            <td><code><?php echo htmlspecialchars($key); ?></code></td>
                            <td>
                                <?php if (is_bool($value)): ?>
                                    <span class="badge <?php echo $value ? 'badge-success' : 'badge-danger'; ?>">
                                        <?php echo $value ? '✓ Включено' : '✗ Выключено'; ?>
                                    </span>
                                <?php elseif (is_numeric($value)): ?>
                                    <strong><?php echo number_format($value); ?><?php echo strpos($key, 'ttl') !== false ? ' сек' : ''; ?></strong>
                                <?php else: ?>
                                    <strong><?php echo htmlspecialchars($value); ?></strong>
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </table>
            </div>
            <p style="margin-top: 10px; font-size: 12px; color: #666;">
                <strong>trust_search_engine_ua_on_limit</strong> — если включено, при превышении rDNS лимита 
                поисковики пропускаются по User-Agent без блокировки.
            </p>
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
            Redis MurKir Security - Admin Panel v4.2 (inline_check v2.5.1) | Работает на Redis
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
