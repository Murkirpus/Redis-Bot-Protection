<?php
// Подключаем систему защиты от ботов
require_once 'inline_check.php';

// Инициализируем защиту
try {
    $protection = new RedisBotProtectionNoSessions(
        '127.0.0.1',    // Redis host
        6379,           // Redis port  
        null,           // Redis password
        0               // Redis database
    );
    $protectionActive = true;
} catch (Exception $e) {
    $protectionActive = false;
    error_log("Redis protection failed: " . $e->getMessage());
}

// Получаем данные
function getCurrentIP() {
    $headers = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'];
    foreach ($headers as $header) {
        if (!empty($_SERVER[$header])) {
            return trim(explode(',', $_SERVER[$header])[0]);
        }
    }
    return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

function isMobileDevice($userAgent) {
    return preg_match('/mobile|android|iphone|ipad|ipod|blackberry/i', $userAgent);
}

function isSuspiciousUA($userAgent) {
    $patterns = ['curl', 'wget', 'python', 'bot', 'spider', 'crawler'];
    foreach ($patterns as $pattern) {
        if (stripos($userAgent, $pattern) !== false) return true;
    }
    return false;
}

$currentIP = getCurrentIP();
$currentUA = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
$isMobile = isMobileDevice($currentUA);
$isSuspiciousUA = isSuspiciousUA($currentUA);
$hasVisitorCookie = isset($_COOKIE['visitor_verified']);

// Получаем статистику если Redis активен
$stats = null;
$userHashInfo = null;
$ipInfo = null;

if ($protectionActive) {
    try {
        $stats = $protection->getStats();
        $userHashInfo = $protection->getUserHashInfo();
        $ipInfo = $protection->getBlockedIPInfo($currentIP);
    } catch (Exception $e) {
        error_log("Failed to get protection data: " . $e->getMessage());
    }
}

// Определяем статус пользователя
$userStatus = 'Unknown';
$trustScore = 0;

if ($userHashInfo && !$userHashInfo['blocked'] && isset($userHashInfo['tracking_data'])) {
    $tracking = $userHashInfo['tracking_data'];
    $timeSpent = time() - ($tracking['first_seen'] ?? time());
    $pages = count(array_unique($tracking['pages'] ?? []));
    $requests = $tracking['requests'] ?? 0;
    
    // Простая формула доверия
    $trustScore = min(100, max(0, 
        ($timeSpent > 300 ? 30 : 0) +
        ($pages > 2 ? 25 : 0) + 
        ($requests > 5 && $requests < 100 ? 20 : 0) +
        (count(array_unique($tracking['ips'] ?? [])) === 1 ? 15 : 0) +
        (!$isSuspiciousUA ? 10 : -20)
    ));
    
    if ($trustScore >= 80) $userStatus = 'VIP User';
    elseif ($trustScore >= 60) $userStatus = 'Trusted';
    else $userStatus = 'Regular';
}

if ($userHashInfo && $userHashInfo['blocked']) {
    $userStatus = 'Blocked';
    $trustScore = 0;
}
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ Redis Bot Protection Test v2.1</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        .header {
            text-align: center;
            padding: 20px;
            background: linear-gradient(135deg, #007bff, #0056b3);
            color: white;
            border-radius: 10px;
            margin-bottom: 30px;
        }
        .status-card {
            background: #f8f9fa;
            border-left: 4px solid #007bff;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .status-card.success { border-left-color: #28a745; }
        .status-card.warning { border-left-color: #ffc107; }
        .status-card.error { border-left-color: #dc3545; }
        .metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .metric {
            text-align: center;
            padding: 20px;
            background: linear-gradient(135deg, #f8f9fa, #e9ecef);
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .metric .number {
            font-size: 2em;
            font-weight: bold;
            color: #007bff;
        }
        .metric .label {
            color: #6c757d;
            font-size: 0.9em;
            margin-top: 5px;
        }
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .info-box {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 3px solid #007bff;
        }
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 15px;
            font-size: 0.8em;
            font-weight: bold;
            margin: 2px;
        }
        .badge-success { background: rgba(40, 167, 69, 0.2); color: #155724; }
        .badge-warning { background: rgba(255, 193, 7, 0.2); color: #856404; }
        .badge-danger { background: rgba(220, 53, 69, 0.2); color: #721c24; }
        .badge-info { background: rgba(23, 162, 184, 0.2); color: #0c5460; }
        .btn {
            display: inline-block;
            padding: 10px 20px;
            background: #007bff;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            margin: 5px;
            border: none;
            cursor: pointer;
            transition: all 0.3s;
        }
        .btn:hover { background: #0056b3; transform: translateY(-2px); }
        .btn-success { background: #28a745; }
        .btn-warning { background: #ffc107; color: #212529; }
        .btn-danger { background: #dc3545; }
        .progress-bar {
            width: 100%;
            height: 12px;
            background: #e9ecef;
            border-radius: 6px;
            overflow: hidden;
            margin: 10px 0;
        }
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #28a745, #20c997);
            border-radius: 6px;
            transition: width 0.8s ease;
        }
        .code {
            background: #f8f9fa;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }
        .footer {
            text-align: center;
            color: #6c757d;
            font-size: 0.9em;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #dee2e6;
        }
        @media (max-width: 768px) {
            .container { padding: 15px; }
            .metrics { grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); }
            .info-grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Redis Bot Protection Test v2.1</h1>
            <p>Упрощённая система мониторинга защиты от ботов</p>
            <div style="margin-top: 15px;">
                <span class="badge <?php echo $protectionActive ? 'badge-success' : 'badge-danger'; ?>">
                    <?php echo $protectionActive ? '✅ Redis Active' : '❌ Redis Inactive'; ?>
                </span>
                <span class="badge <?php echo $isMobile ? 'badge-info' : 'badge-warning'; ?>">
                    <?php echo $isMobile ? '📱 Mobile' : '🖥️ Desktop'; ?>
                </span>
                <span class="badge <?php echo $isSuspiciousUA ? 'badge-danger' : 'badge-success'; ?>">
                    <?php echo $isSuspiciousUA ? '⚠️ Suspicious' : '✅ Normal'; ?>
                </span>
            </div>
        </div>

        <!-- Статус системы -->
        <div class="status-card <?php echo $protectionActive ? 'success' : 'error'; ?>">
            <h3>📊 Статус системы защиты</h3>
            <?php if ($protectionActive): ?>
                <p><strong>✅ Redis Bot Protection v2.1 активна</strong></p>
                <p>Система работает без PHP сессий, используя продвинутые алгоритмы хеш-блокировки пользователей.</p>
                
                <?php if ($stats): ?>
                <div class="metrics">
                    <div class="metric">
                        <div class="number"><?php echo $stats['blocked_ips'] ?? 0; ?></div>
                        <div class="label">Заблокированных IP</div>
                    </div>
                    <div class="metric">
                        <div class="number"><?php echo $stats['blocked_user_hashes'] ?? 0; ?></div>
                        <div class="label">Заблокированных хешей</div>
                    </div>
                    <div class="metric">
                        <div class="number"><?php echo $stats['tracked_user_hashes'] ?? 0; ?></div>
                        <div class="label">Активный трекинг</div>
                    </div>
                    <div class="metric">
                        <div class="number"><?php echo $stats['total_keys'] ?? 0; ?></div>
                        <div class="label">Всего ключей</div>
                    </div>
                </div>
                <?php endif; ?>
            <?php else: ?>
                <p><strong>❌ Redis недоступен</strong></p>
                <p>Проверьте подключение к Redis серверу. Система защиты не активна.</p>
            <?php endif; ?>
        </div>

        <!-- Статус пользователя -->
        <div class="status-card <?php echo $userStatus === 'Blocked' ? 'error' : ($userStatus === 'VIP User' ? 'success' : 'warning'); ?>">
            <h3>👤 Статус пользователя</h3>
            <p><strong>Статус:</strong> <?php echo $userStatus; ?></p>
            
            <?php if ($userStatus !== 'Unknown' && $userStatus !== 'Blocked'): ?>
                <p><strong>🎯 Уровень доверия:</strong> <?php echo $trustScore; ?>%</p>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: <?php echo $trustScore; ?>%;"></div>
                </div>
                
                <?php if ($trustScore >= 80): ?>
                    <p style="color: #28a745; font-weight: bold;">🌟 VIP пользователь - максимальное доверие!</p>
                <?php elseif ($trustScore >= 60): ?>
                    <p style="color: #007bff; font-weight: bold;">⭐ Доверенный пользователь</p>
                <?php else: ?>
                    <p style="color: #6c757d;">👤 Обычный пользователь</p>
                <?php endif; ?>
            <?php endif; ?>
            
            <?php if ($userStatus === 'Blocked'): ?>
                <p style="color: #dc3545; font-weight: bold;">🚫 Пользователь заблокирован системой защиты</p>
                <?php if ($userHashInfo && $userHashInfo['block_ttl'] > 0): ?>
                    <p><strong>⏰ Время до разблокировки:</strong> <?php echo gmdate('H:i:s', $userHashInfo['block_ttl']); ?></p>
                <?php endif; ?>
            <?php endif; ?>
        </div>

        <!-- Информация о запросе -->
        <div class="info-grid">
            <div class="info-box">
                <h4>🌐 Детали запроса</h4>
                <p><strong>IP:</strong> <span class="code"><?php echo htmlspecialchars($currentIP); ?></span></p>
                <p><strong>User-Agent:</strong> <?php echo htmlspecialchars(substr($currentUA, 0, 80)) . '...'; ?></p>
                <p><strong>Устройство:</strong> <?php echo $isMobile ? '📱 Мобильное' : '🖥️ Десктопное'; ?></p>
                <p><strong>Время:</strong> <?php echo date('Y-m-d H:i:s'); ?></p>
                <p><strong>Cookie:</strong> 
                    <span class="badge <?php echo $hasVisitorCookie ? 'badge-success' : 'badge-warning'; ?>">
                        <?php echo $hasVisitorCookie ? '✅ Установлена' : '⚠️ Отсутствует'; ?>
                    </span>
                </p>
            </div>

            <?php if ($userHashInfo): ?>
            <div class="info-box">
                <h4>🔐 Хеш пользователя v2.1</h4>
                <p><strong>Статус:</strong> 
                    <span class="badge <?php echo $userHashInfo['blocked'] ? 'badge-danger' : 'badge-success'; ?>">
                        <?php echo $userHashInfo['blocked'] ? '🚫 Заблокирован' : '✅ Активен'; ?>
                    </span>
                </p>
                <p><strong>Превью:</strong> <span class="code"><?php echo htmlspecialchars($userHashInfo['hash_preview']); ?></span></p>
                
                <?php if ($userHashInfo['tracking_data']): ?>
                    <?php $track = $userHashInfo['tracking_data']; ?>
                    <p><strong>Запросов:</strong> <?php echo $track['requests'] ?? 0; ?></p>
                    <p><strong>Страниц:</strong> <?php echo count(array_unique($track['pages'] ?? [])); ?></p>
                    <p><strong>Время на сайте:</strong> <?php echo gmdate('H:i:s', time() - ($track['first_seen'] ?? time())); ?></p>
                <?php endif; ?>
            </div>
            <?php endif; ?>
        </div>

        <!-- Простое тестирование -->
        <div class="status-card">
            <h3>🧪 Быстрое тестирование</h3>
            <p>Используйте эти инструменты для тестирования системы защиты:</p>
            
            <a href="?" class="btn">🔄 Обновить страницу</a>
            <a href="?test=human" class="btn btn-success">👤 Тест человека</a>
            <a href="?test=bot" class="btn btn-warning">🤖 Тест бота</a>
            
            <?php if ($protectionActive): ?>
                <a href="?admin=1" class="btn btn-danger">⚙️ Админ панель</a>
            <?php endif; ?>
            
            <div style="margin-top: 15px;">
                <button onclick="testBot()" class="btn btn-warning">🤖 JS тест бота</button>
                <button onclick="testHuman()" class="btn btn-success">👤 JS тест человека</button>
                <button onclick="clearData()" class="btn btn-danger">🧹 Очистить данные</button>
            </div>
        </div>

        <!-- Админ панель -->
        <?php if (isset($_GET['admin']) && $protectionActive): ?>
        <div class="status-card error">
            <h3>⚙️ Административная панель</h3>
            
            <?php
            if (isset($_GET['action'])) {
                switch ($_GET['action']) {
                    case 'unblock_hash':
                        $result = $protection->unblockUserHash();
                        echo "<p><strong>🔓 Результат разблокировки хеша:</strong><br>";
                        echo "Разблокирован: " . ($result['unblocked'] ? '✅ Да' : '❌ Нет') . "</p>";
                        break;
                    case 'unblock_ip':
                        $result = $protection->unblockIP($currentIP);
                        echo "<p><strong>🔓 Результат разблокировки IP:</strong><br>";
                        echo "Разблокирован: " . ($result['ip_unblocked'] ? '✅ Да' : '❌ Нет') . "</p>";
                        break;
                    case 'cleanup':
                        $cleaned = $protection->cleanup();
                        echo "<p><strong>🧹 Очистка выполнена:</strong><br>";
                        echo "Удалено элементов: " . ($cleaned !== false ? $cleaned : 'Ошибка') . "</p>";
                        break;
                }
            }
            ?>
            
            <a href="?admin=1&action=unblock_hash" class="btn btn-success">🔓 Разблокировать хеш</a>
            <a href="?admin=1&action=unblock_ip" class="btn btn-success">🌐 Разблокировать IP</a>
            <a href="?admin=1&action=cleanup" class="btn btn-warning">🧹 Очистка</a>
            <a href="?" class="btn">👁️ Обычный режим</a>
        </div>
        <?php endif; ?>

        <!-- Обработка тестов -->
        <?php if (isset($_GET['test'])): ?>
        <div class="status-card warning">
            <h4>🧪 Результат теста: <?php echo $_GET['test']; ?></h4>
            <?php if ($_GET['test'] === 'human'): ?>
                <p>👤 Тест человеческого поведения выполнен. Проверьте изменения в статистике.</p>
            <?php elseif ($_GET['test'] === 'bot'): ?>
                <p>🤖 Тест bot-поведения выполнен. Система должна зарегистрировать подозрительную активность.</p>
            <?php endif; ?>
            <p><em>Время выполнения: <?php echo date('H:i:s'); ?></em></p>
        </div>
        <?php endif; ?>

        <div class="footer">
            🛡️ <strong>Redis Bot Protection System v2.1</strong> | 
            Generated: <?php echo date('Y-m-d H:i:s'); ?> | 
            PHP: <?php echo PHP_VERSION; ?> | 
            Redis: <?php echo $protectionActive ? '✅ Active' : '❌ Inactive'; ?>
        </div>
    </div>

    <script>
        function testBot() {
            console.log('🤖 Simulating bot behavior...');
            showNotification('🤖 Запуск симуляции бота...', 'warning');
            
            // Быстрые запросы
            for(let i = 0; i < 10; i++) {
                setTimeout(() => {
                    fetch(window.location.href + '?bot_test=' + i + '&rapid=1')
                        .then(r => console.log(`Bot request ${i}: ${r.status}`));
                }, i * 50);
            }
        }

        function testHuman() {
            console.log('👤 Simulating human behavior...');
            showNotification('👤 Симуляция человеческого поведения...', 'info');
            
            const pages = ['?page=1', '?page=2', '?about=1'];
            pages.forEach((page, i) => {
                setTimeout(() => {
                    fetch(window.location.origin + window.location.pathname + page)
                        .then(r => console.log(`Human request ${i}: ${r.status}`));
                }, i * 2000 + Math.random() * 1000);
            });
        }

        function clearData() {
            localStorage.clear();
            sessionStorage.clear();
            showNotification('🧹 Локальные данные очищены', 'success');
            setTimeout(() => location.reload(), 2000);
        }

        function showNotification(message, type = 'info') {
            const colors = {
                error: '#dc3545', success: '#28a745', 
                warning: '#ffc107', info: '#007bff'
            };
            
            const notification = document.createElement('div');
            notification.style.cssText = `
                position: fixed; top: 20px; right: 20px; z-index: 1000;
                background: ${colors[type]}; color: white; padding: 15px 20px;
                border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.3);
                opacity: 0; transform: translateX(100%); transition: all 0.3s;
            `;
            notification.textContent = message;
            document.body.appendChild(notification);

            setTimeout(() => {
                notification.style.opacity = '1';
                notification.style.transform = 'translateX(0)';
            }, 100);

            setTimeout(() => {
                notification.style.opacity = '0';
                notification.style.transform = 'translateX(100%)';
                setTimeout(() => notification.remove(), 300);
            }, 3000);
        }

        // Показываем приветственное сообщение
        document.addEventListener('DOMContentLoaded', () => {
            <?php if (!$protectionActive): ?>
                showNotification('⚠️ Redis недоступен! Система защиты неактивна.', 'error');
            <?php elseif ($userStatus === 'Blocked'): ?>
                showNotification('🚫 Пользователь заблокирован системой защиты!', 'error');
            <?php elseif ($userStatus === 'VIP User'): ?>
                showNotification('🌟 Добро пожаловать, VIP пользователь!', 'success');
            <?php else: ?>
                showNotification('🛡️ Bot Protection v2.1 активна!', 'info');
            <?php endif; ?>
        });

        console.log('🛡️ Bot Protection Test Page v2.1 loaded');
        console.log('📊 System status:', {
            redis: <?php echo $protectionActive ? 'true' : 'false'; ?>,
            userStatus: '<?php echo $userStatus; ?>',
            trustScore: <?php echo $trustScore; ?>,
            mobile: <?php echo $isMobile ? 'true' : 'false'; ?>
        });
    </script>
</body>
</html>
