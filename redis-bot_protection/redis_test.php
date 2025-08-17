<?php
// Компактный тестер для Redis Bot Protection v2.1
require_once 'inline_check.php';

// API для автоматизированного тестирования
if (isset($_GET['api'])) {
    header('Content-Type: application/json');
    
    try {
        $protection = new RedisBotProtectionNoSessions('127.0.0.1', 6379, null, 0);
        
        switch ($_GET['api']) {
            case 'stats':
                echo json_encode($protection->getStats());
                break;
            case 'user_info':
                $userInfo = $protection->getUserHashInfo();
                $userStatus = calculateUserStatus($userInfo, $isMobile, $currentUA);
                echo json_encode(['user_info' => $userInfo, 'user_status' => $userStatus]);
                break;
            case 'detailed_status':
                $userInfo = $protection->getUserHashInfo();
                $userStatus = calculateUserStatus($userInfo, $isMobile, $currentUA);
                echo json_encode($userStatus);
                break;
            case 'test_slow_bot':
                // Симуляция медленного бота
                for ($i = 0; $i < 20; $i++) {
                    $protection->protect();
                    usleep(500000); // 0.5 сек между запросами
                }
                echo json_encode(['status' => 'slow_bot_test_completed', 'requests' => 20]);
                break;
            case 'test_fast_bot':
                // Симуляция быстрого бота
                for ($i = 0; $i < 50; $i++) {
                    $protection->protect();
                    usleep(50000); // 0.05 сек между запросами
                }
                echo json_encode(['status' => 'fast_bot_test_completed', 'requests' => 50]);
                break;
            case 'test_rdns':
                $ip = $_GET['ip'] ?? '66.249.66.1';
                $ua = $_GET['ua'] ?? 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
                ob_start();
                $result = $protection->testRDNS($ip, $ua);
                $output = ob_get_clean();
                echo json_encode(['result' => $result, 'output' => $output]);
                break;
            case 'unblock':
                $result = [
                    'hash_unblocked' => $protection->unblockUserHash(),
                    'ip_unblocked' => $protection->unblockIP($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1')
                ];
                echo json_encode($result);
                break;
            case 'cleanup':
                echo json_encode(['cleaned' => $protection->cleanup(true)]);
                break;
            default:
                echo json_encode(['error' => 'Unknown API command']);
        }
    } catch (Exception $e) {
        echo json_encode(['error' => $e->getMessage()]);
    }
    exit;
}

// Инициализация
try {
    $protection = new RedisBotProtectionNoSessions('127.0.0.1', 6379, null, 0);
    $active = true;
    $stats = $protection->getStats();
    $userInfo = $protection->getUserHashInfo();
    $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
} catch (Exception $e) {
    $active = false;
    $stats = null;
    $userInfo = null;
}

$isMobile = preg_match('/mobile|android|iphone/i', $_SERVER['HTTP_USER_AGENT'] ?? '');
$isBlocked = $userInfo && $userInfo['blocked'];
$currentUA = $_SERVER['HTTP_USER_AGENT'] ?? '';

// Расчет статуса пользователя и уровня доверия
function calculateUserStatus($userInfo, $isMobile, $currentUA) {
    if (!$userInfo) return ['status' => 'Unknown', 'trust' => 0, 'details' => []];
    
    if ($userInfo['blocked']) {
        return ['status' => 'Blocked', 'trust' => 0, 'details' => ['Заблокирован системой защиты']];
    }
    
    if (!isset($userInfo['tracking_data'])) {
        return ['status' => 'New User', 'trust' => 15, 'details' => ['Новый пользователь']];
    }
    
    $tracking = $userInfo['tracking_data'];
    $timeSpent = time() - ($tracking['first_seen'] ?? time());
    $requests = $tracking['requests'] ?? 0;
    $pages = count(array_unique($tracking['pages'] ?? []));
    $uniqueIPs = count(array_unique($tracking['ips'] ?? []));
    
    $trust = 0;
    $details = [];
    
    // Время на сайте (до 25 баллов)
    if ($timeSpent > 1800) { // 30+ минут
        $trust += 25;
        $details[] = '✅ Долгое время на сайте (' . gmdate('H:i:s', $timeSpent) . ')';
    } elseif ($timeSpent > 600) { // 10+ минут
        $trust += 15;
        $details[] = '✅ Умеренное время на сайте (' . gmdate('H:i:s', $timeSpent) . ')';
    } elseif ($timeSpent > 180) { // 3+ минуты
        $trust += 8;
        $details[] = '⚠️ Короткое время на сайте (' . gmdate('H:i:s', $timeSpent) . ')';
    }
    
    // Разнообразие страниц (до 20 баллов)
    if ($pages > 5) {
        $trust += 20;
        $details[] = '✅ Просмотрено много страниц (' . $pages . ')';
    } elseif ($pages > 2) {
        $trust += 12;
        $details[] = '✅ Просмотрено несколько страниц (' . $pages . ')';
    }
    
    // Количество запросов (до 20 баллов)
    if ($requests > 20 && $requests < 200) {
        $trust += 20;
        $details[] = '✅ Нормальная активность (' . $requests . ' запросов)';
    } elseif ($requests > 5 && $requests < 500) {
        $trust += 10;
        $details[] = '⚠️ Умеренная активность (' . $requests . ' запросов)';
    } elseif ($requests >= 500) {
        $trust -= 20;
        $details[] = '❌ Подозрительно высокая активность (' . $requests . ' запросов)';
    }
    
    // Стабильность IP (до 15 баллов)
    if ($uniqueIPs === 1) {
        $trust += 15;
        $details[] = '✅ Стабильный IP адрес';
    } elseif ($uniqueIPs <= 3) {
        $trust += 8;
        $details[] = '⚠️ Несколько IP адресов (' . $uniqueIPs . ')';
    } else {
        $trust -= 10;
        $details[] = '❌ Много разных IP (' . $uniqueIPs . ')';
    }
    
    // User-Agent анализ (до 15 баллов)
    $suspiciousPatterns = ['curl', 'wget', 'python', 'bot', 'spider', 'crawler'];
    $isSuspicious = false;
    foreach ($suspiciousPatterns as $pattern) {
        if (stripos($currentUA, $pattern) !== false) {
            $isSuspicious = true;
            break;
        }
    }
    
    if (!$isSuspicious && !empty($currentUA)) {
        $trust += 15;
        $details[] = '✅ Нормальный браузер';
    } elseif ($isSuspicious) {
        $trust -= 25;
        $details[] = '❌ Подозрительный User-Agent';
    }
    
    // Мобильное устройство (бонус 5 баллов)
    if ($isMobile) {
        $trust += 5;
        $details[] = '📱 Мобильное устройство';
    }
    
    // Ограничиваем от 0 до 100
    $trust = min(100, max(0, $trust));
    
    // Определяем статус
    if ($trust >= 85) {
        $status = 'VIP User';
    } elseif ($trust >= 70) {
        $status = 'Trusted User';
    } elseif ($trust >= 50) {
        $status = 'Regular User';
    } elseif ($trust >= 25) {
        $status = 'New User';
    } else {
        $status = 'Suspicious';
    }
    
    return ['status' => $status, 'trust' => $trust, 'details' => $details];
}

$userStatus = calculateUserStatus($userInfo, $isMobile, $currentUA);
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ Bot Protection Tester v2.1</title>
    <style>
        body { font-family: -apple-system, sans-serif; margin: 0; padding: 15px; background: linear-gradient(135deg, #667eea, #764ba2); min-height: 100vh; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 5px 20px rgba(0,0,0,0.2); }
        .header { text-align: center; padding: 15px; background: linear-gradient(135deg, #007bff, #0056b3); color: white; border-radius: 8px; margin-bottom: 20px; }
        .status { padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid #007bff; background: #f8f9fa; }
        .status.error { border-left-color: #dc3545; background: #f8d7da; }
        .status.success { border-left-color: #28a745; background: #d4edda; }
        .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 15px; margin: 15px 0; }
        .metric { text-align: center; padding: 15px; background: #f8f9fa; border-radius: 8px; }
        .metric .num { font-size: 24px; font-weight: bold; color: #007bff; }
        .metric .label { font-size: 12px; color: #6c757d; margin-top: 5px; }
        .btn { display: inline-block; padding: 8px 16px; margin: 4px; background: #007bff; color: white; text-decoration: none; border-radius: 5px; border: none; cursor: pointer; font-size: 14px; }
        .btn:hover { background: #0056b3; }
        .btn-success { background: #28a745; }
        .btn-warning { background: #ffc107; color: #212529; }
        .btn-danger { background: #dc3545; }
        .badge { padding: 3px 8px; border-radius: 12px; font-size: 11px; font-weight: bold; }
        .badge-success { background: rgba(40,167,69,0.2); color: #155724; }
        .badge-danger { background: rgba(220,53,69,0.2); color: #721c24; }
        .badge-info { background: rgba(23,162,184,0.2); color: #0c5460; }
        .code { background: #f8f9fa; padding: 2px 6px; border-radius: 3px; font-family: monospace; font-size: 13px; }
        .log { background: #000; color: #0f0; padding: 10px; border-radius: 5px; font-family: monospace; font-size: 12px; max-height: 200px; overflow-y: auto; margin: 10px 0; }
        @media (max-width: 600px) { .container { padding: 10px; } .metrics { grid-template-columns: repeat(2, 1fr); } }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>🛡️ Bot Protection Tester v2.1</h2>
            <div style="display: flex; justify-content: center; align-items: center; gap: 10px; margin-top: 10px; flex-wrap: wrap;">
                <span class="badge <?= $active ? 'badge-success' : 'badge-danger' ?>">
                    <?= $active ? '✅ Active' : '❌ Inactive' ?>
                </span>
                <span class="badge badge-info"><?= $isMobile ? '📱 Mobile' : '🖥️ Desktop' ?></span>
                <span class="badge <?= $userStatus['trust'] >= 85 ? 'badge-success' : ($userStatus['trust'] >= 50 ? 'badge-info' : 'badge-danger') ?>">
                    <?php
                    $statusIcons = [
                        'VIP User' => '🌟',
                        'Trusted User' => '⭐',
                        'Regular User' => '👤',
                        'New User' => '🆕',
                        'Suspicious' => '⚠️',
                        'Blocked' => '🚫'
                    ];
                    echo $statusIcons[$userStatus['status']] ?? '❓';
                    ?> 
                    <?= $userStatus['status'] ?> (<?= $userStatus['trust'] ?>%)
                </span>
            </div>
        </div>

        <!-- Статус системы -->
        <div class="status <?= $active ? 'success' : 'error' ?>">
            <strong><?= $active ? '✅ Redis Protection Active' : '❌ Redis Unavailable' ?></strong>
            <?php if ($active && $stats): ?>
                <div class="metrics">
                    <div class="metric"><div class="num"><?= $stats['blocked_ips'] ?? 0 ?></div><div class="label">Blocked IPs</div></div>
                    <div class="metric"><div class="num"><?= $stats['blocked_user_hashes'] ?? 0 ?></div><div class="label">Blocked Hashes</div></div>
                    <div class="metric"><div class="num"><?= $stats['tracked_user_hashes'] ?? 0 ?></div><div class="label">Active Tracking</div></div>
                    <div class="metric"><div class="num"><?= $stats['extended_tracking_active'] ?? 0 ?></div><div class="label">Extended Tracking</div></div>
                </div>
            <?php endif; ?>
        </div>

        <!-- Статус пользователя -->
        <div class="status <?= $userStatus['status'] === 'Blocked' ? 'error' : ($userStatus['trust'] >= 85 ? 'success' : ($userStatus['trust'] >= 50 ? '' : 'error')) ?>">
            <strong>👤 Статус пользователя</strong><br>
            <div style="display: flex; align-items: center; gap: 15px; margin: 10px 0;">
                <div>
                    <strong>Статус:</strong> 
                    <?php
                    $statusIcons = [
                        'VIP User' => '🌟',
                        'Trusted User' => '⭐',
                        'Regular User' => '👤',
                        'New User' => '🆕',
                        'Suspicious' => '⚠️',
                        'Blocked' => '🚫'
                    ];
                    echo $statusIcons[$userStatus['status']] ?? '❓';
                    ?> 
                    <span class="badge <?= $userStatus['trust'] >= 85 ? 'badge-success' : ($userStatus['trust'] >= 50 ? 'badge-info' : 'badge-danger') ?>">
                        <?= $userStatus['status'] ?>
                    </span>
                </div>
                <div>
                    <strong>🎯 Уровень доверия:</strong> 
                    <span style="color: <?= $userStatus['trust'] >= 85 ? '#28a745' : ($userStatus['trust'] >= 50 ? '#007bff' : '#dc3545') ?>; font-weight: bold;">
                        <?= $userStatus['trust'] ?>%
                    </span>
                </div>
            </div>
            
            <!-- Прогресс бар доверия -->
            <div class="progress-bar" style="margin: 10px 0;">
                <div class="progress-fill" style="width: <?= $userStatus['trust'] ?>%; background: <?= $userStatus['trust'] >= 85 ? 'linear-gradient(90deg, #28a745, #20c997)' : ($userStatus['trust'] >= 50 ? 'linear-gradient(90deg, #007bff, #6610f2)' : 'linear-gradient(90deg, #dc3545, #fd7e14)') ?>;"></div>
            </div>
            
            <?php if ($userStatus['trust'] >= 85): ?>
                <p style="color: #28a745; font-weight: bold; margin: 10px 0;">
                    🌟 VIP пользователь - максимальное доверие!
                </p>
            <?php elseif ($userStatus['trust'] >= 70): ?>
                <p style="color: #007bff; font-weight: bold; margin: 10px 0;">
                    ⭐ Доверенный пользователь
                </p>
            <?php elseif ($userStatus['status'] === 'Blocked'): ?>
                <p style="color: #dc3545; font-weight: bold; margin: 10px 0;">
                    🚫 Пользователь заблокирован системой защиты
                </p>
            <?php endif; ?>
            
            <!-- Детали анализа -->
            <?php if (!empty($userStatus['details'])): ?>
                <details style="margin-top: 10px;">
                    <summary style="cursor: pointer; font-weight: bold;">📊 Детали анализа</summary>
                    <div style="margin-top: 10px; padding-left: 15px;">
                        <?php foreach ($userStatus['details'] as $detail): ?>
                            <div style="margin: 5px 0; font-size: 14px;"><?= $detail ?></div>
                        <?php endforeach; ?>
                    </div>
                </details>
            <?php endif; ?>
            
            <?php if ($userInfo): ?>
                <div style="margin-top: 15px; font-size: 14px; color: #6c757d;">
                    Hash: <span class="code"><?= htmlspecialchars($userInfo['hash_preview']) ?></span>
                    <?php if ($userInfo['tracking_data']): ?>
                        <?php $track = $userInfo['tracking_data']; ?>
                        | Requests: <?= $track['requests'] ?? 0 ?>
                        | Pages: <?= count(array_unique($track['pages'] ?? [])) ?>
                        | Time: <?= gmdate('H:i:s', time() - ($track['first_seen'] ?? time())) ?>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
        </div>

        <!-- Быстрое тестирование -->
        <div class="status">
            <strong>🧪 Quick Tests</strong><br>
            <button onclick="runTest('slow_bot')" class="btn btn-warning">🐌 Slow Bot</button>
            <button onclick="runTest('fast_bot')" class="btn btn-danger">⚡ Fast Bot</button>
            <button onclick="runTest('human')" class="btn btn-success">👤 Human</button>
            <button onclick="runTest('rdns')" class="btn">🔍 rDNS Test</button>
            <br><br>
            <button onclick="runAPI('detailed_status')" class="btn">👤 Check Status</button>
            <button onclick="runAPI('unblock')" class="btn btn-success">🔓 Unblock</button>
            <button onclick="runAPI('cleanup')" class="btn btn-warning">🧹 Cleanup</button>
            <button onclick="refreshStats()" class="btn">🔄 Refresh</button>
            <button onclick="clearLog()" class="btn">🗑️ Clear Log</button>
        </div>

        <!-- Лог -->
        <div id="log" class="log">Bot Protection Tester Ready...<br></div>

        <!-- Информация -->
        <div class="status">
            <strong>📊 Current Request</strong><br>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; margin-top: 10px;">
                <div>
                    <strong>IP:</strong> <span class="code"><?= htmlspecialchars($_SERVER['REMOTE_ADDR'] ?? 'unknown') ?></span>
                </div>
                <div>
                    <strong>Time:</strong> <?= date('H:i:s') ?>
                </div>
                <div>
                    <strong>Cookie:</strong> 
                    <span class="badge <?= isset($_COOKIE['visitor_verified']) ? 'badge-success' : 'badge-danger' ?>">
                        <?= isset($_COOKIE['visitor_verified']) ? 'Set' : 'None' ?>
                    </span>
                </div>
                <div>
                    <strong>Device:</strong> <?= $isMobile ? '📱 Mobile' : '🖥️ Desktop' ?>
                </div>
            </div>
            <div style="margin-top: 10px;">
                <strong>User-Agent:</strong> 
                <span class="code" style="font-size: 12px;"><?= htmlspecialchars(substr($_SERVER['HTTP_USER_AGENT'] ?? 'unknown', 0, 80)) ?>...</span>
            </div>
        </div>
    </div>

    <script>
        let testRunning = false;
        
        function log(message, type = 'info') {
            const colors = { error: '#f00', success: '#0f0', warning: '#ff0', info: '#0ff' };
            const logEl = document.getElementById('log');
            const time = new Date().toLocaleTimeString();
            logEl.innerHTML += `<span style="color: ${colors[type]}">[${time}] ${message}</span><br>`;
            logEl.scrollTop = logEl.scrollHeight;
        }

        function clearLog() {
            document.getElementById('log').innerHTML = 'Log cleared...<br>';
        }

        async function runAPI(command, params = {}) {
            if (testRunning) { log('Test already running!', 'warning'); return; }
            
            try {
                testRunning = true;
                log(`Running API: ${command}...`);
                
                const url = new URL(window.location);
                url.searchParams.set('api', command);
                Object.entries(params).forEach(([k, v]) => url.searchParams.set(k, v));
                
                const response = await fetch(url);
                const result = await response.json();
                
                if (result.error) {
                    log(`API Error: ${result.error}`, 'error');
                } else {
                    log(`API Success: ${JSON.stringify(result)}`, 'success');
                }
            } catch (error) {
                log(`Request failed: ${error.message}`, 'error');
            } finally {
                testRunning = false;
            }
        }

        async function runTest(testType) {
            if (testRunning) { log('Test already running!', 'warning'); return; }
            
            switch (testType) {
                case 'slow_bot':
                    log('🐌 Starting slow bot simulation...', 'warning');
                    await runAPI('test_slow_bot');
                    break;
                    
                case 'fast_bot':
                    log('⚡ Starting fast bot simulation...', 'error');
                    await runAPI('test_fast_bot');
                    break;
                    
                case 'human':
                    log('👤 Simulating human behavior...', 'info');
                    testRunning = true;
                    try {
                        const pages = ['?p=1', '?p=2', '?about=1'];
                        for (let i = 0; i < pages.length; i++) {
                            await new Promise(resolve => setTimeout(resolve, 2000 + Math.random() * 1000));
                            await fetch(window.location.origin + window.location.pathname + pages[i]);
                            log(`Human request ${i + 1}/${pages.length}`, 'success');
                        }
                    } finally {
                        testRunning = false;
                    }
                    break;
                    
                case 'rdns':
                    log('🔍 Testing rDNS verification...', 'info');
                    await runAPI('test_rdns', { ip: '66.249.66.1', ua: 'Mozilla/5.0 (compatible; Googlebot/2.1)' });
                    break;
            }
        }

        async function refreshStats() {
            log('🔄 Refreshing stats...', 'info');
            await runAPI('stats');
            setTimeout(() => location.reload(), 1000);
        }

        // Автообновление каждые 30 секунд
        setInterval(async () => {
            if (!testRunning) {
                const response = await fetch('?api=stats');
                const stats = await response.json();
                if (stats && !stats.error) {
                    log(`📊 Stats: IPs:${stats.blocked_ips || 0} Hashes:${stats.blocked_user_hashes || 0} Tracking:${stats.tracked_user_hashes || 0}`, 'info');
                }
            }
        }, 30000);

        // Горячие клавиши
        document.addEventListener('keydown', (e) => {
            if (e.ctrlKey) {
                switch (e.key) {
                    case '1': runTest('slow_bot'); e.preventDefault(); break;
                    case '2': runTest('fast_bot'); e.preventDefault(); break;
                    case '3': runTest('human'); e.preventDefault(); break;
                    case 's': runAPI('detailed_status'); e.preventDefault(); break;
                    case 'r': refreshStats(); e.preventDefault(); break;
                    case 'l': clearLog(); e.preventDefault(); break;
                }
            }
        });

        log('🛡️ Bot Protection Tester v2.1 loaded');
        log('💡 Hotkeys: Ctrl+1(SlowBot) Ctrl+2(FastBot) Ctrl+3(Human) Ctrl+S(Status) Ctrl+R(Refresh) Ctrl+L(ClearLog)');
        
        <?php if (!$active): ?>
        log('❌ Redis protection is INACTIVE!', 'error');
        <?php elseif ($userStatus['status'] === 'Blocked'): ?>
        log('🚫 Current user is BLOCKED!', 'error');
        <?php elseif ($userStatus['trust'] >= 85): ?>
        log('🌟 VIP User detected! Trust level: <?= $userStatus['trust'] ?>%', 'success');
        <?php elseif ($userStatus['trust'] >= 70): ?>
        log('⭐ Trusted user detected! Trust level: <?= $userStatus['trust'] ?>%', 'success');
        <?php else: ?>
        log('✅ Protection system operational. Trust level: <?= $userStatus['trust'] ?>%', 'info');
        <?php endif; ?>
        
        // Показываем приветственные уведомления
        setTimeout(() => {
            <?php if (!$active): ?>
                showNotification('⚠️ Redis недоступен! Система защиты неактивна.', 'error');
            <?php elseif ($userStatus['status'] === 'Blocked'): ?>
                showNotification('🚫 Пользователь заблокирован системой защиты!', 'error');
            <?php elseif ($userStatus['trust'] >= 85): ?>
                showNotification('🌟 Добро пожаловать, VIP пользователь! Уровень доверия: <?= $userStatus['trust'] ?>%', 'success');
            <?php elseif ($userStatus['trust'] >= 70): ?>
                showNotification('⭐ Добро пожаловать, доверенный пользователь! Уровень доверия: <?= $userStatus['trust'] ?>%', 'success');
            <?php else: ?>
                showNotification('🛡️ Bot Protection v2.1 активна! Уровень доверия: <?= $userStatus['trust'] ?>%', 'info');
            <?php endif; ?>
        }, 500);
    </script>
</body>
</html>
