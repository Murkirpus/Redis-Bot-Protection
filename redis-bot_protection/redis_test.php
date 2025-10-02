<?php
/**
 * Redis Bot Protection - Test Suite
 * Комплексное тестирование всех функций системы
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

// Подключаем основной класс
require_once __DIR__ . '/inline_check.php';

// Настройки отображения
header('Content-Type: text/html; charset=utf-8');

?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Redis Bot Protection - Test Suite</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            min-height: 100vh;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .header {
            background: white;
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        .header h1 {
            color: #667eea;
            margin-bottom: 10px;
        }
        .header p {
            color: #666;
        }
        .test-section {
            background: white;
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        .test-section h2 {
            color: #333;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
        }
        .test-item {
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 5px;
            background: #f8f9fa;
        }
        .test-item h3 {
            color: #555;
            margin-bottom: 10px;
            font-size: 16px;
        }
        .success {
            background: #d4edda;
            border-left: 4px solid #28a745;
            color: #155724;
        }
        .error {
            background: #f8d7da;
            border-left: 4px solid #dc3545;
            color: #721c24;
        }
        .warning {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            color: #856404;
        }
        .info {
            background: #d1ecf1;
            border-left: 4px solid #17a2b8;
            color: #0c5460;
        }
        .stat-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }
        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        .stat-card .number {
            font-size: 32px;
            font-weight: bold;
            margin-bottom: 5px;
        }
        .stat-card .label {
            font-size: 12px;
            opacity: 0.9;
        }
        .code-block {
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            line-height: 1.5;
        }
        .btn {
            display: inline-block;
            padding: 10px 20px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            margin-top: 10px;
            transition: background 0.3s;
        }
        .btn:hover {
            background: #5568d3;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }
        th {
            background: #f8f9fa;
            font-weight: 600;
            color: #495057;
        }
        tr:hover {
            background: #f8f9fa;
        }
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 3px;
            font-size: 12px;
            font-weight: 600;
        }
        .badge-success { background: #28a745; color: white; }
        .badge-danger { background: #dc3545; color: white; }
        .badge-warning { background: #ffc107; color: #000; }
        .badge-info { background: #17a2b8; color: white; }
        
        .trust-level-container {
            background: white;
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        .trust-level-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        .trust-percentage {
            font-size: 48px;
            font-weight: bold;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        .trust-label {
            font-size: 18px;
            color: #666;
            margin-top: 5px;
        }
        .progress-bar-container {
            width: 100%;
            height: 40px;
            background: #e9ecef;
            border-radius: 20px;
            overflow: hidden;
            position: relative;
            box-shadow: inset 0 2px 4px rgba(0,0,0,0.1);
        }
        .progress-bar-fill {
            height: 100%;
            background: linear-gradient(90deg, #dc3545 0%, #ffc107 50%, #28a745 100%);
            border-radius: 20px;
            transition: width 0.8s ease;
            display: flex;
            align-items: center;
            justify-content: flex-end;
            padding-right: 15px;
            color: white;
            font-weight: bold;
            font-size: 16px;
        }
        .trust-factors {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-top: 25px;
        }
        .trust-factor {
            display: flex;
            align-items: center;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
            border-left: 4px solid #dee2e6;
        }
        .trust-factor.positive {
            border-left-color: #28a745;
            background: #d4edda;
        }
        .trust-factor.negative {
            border-left-color: #dc3545;
            background: #f8d7da;
        }
        .trust-factor-icon {
            font-size: 24px;
            margin-right: 12px;
        }
        .trust-factor-text {
            flex: 1;
        }
        .trust-factor-value {
            font-weight: bold;
            color: #333;
        }
        .trust-status {
            display: inline-block;
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: 600;
            font-size: 14px;
            margin-top: 10px;
        }
        .trust-status.high { background: #d4edda; color: #155724; }
        .trust-status.medium { background: #fff3cd; color: #856404; }
        .trust-status.low { background: #f8d7da; color: #721c24; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Redis Bot Protection - Test Suite</h1>
            <p>Комплексное тестирование системы защиты от ботов</p>
        </div>

<?php

try {
    // Инициализация системы
    $protection = new RedisBotProtectionNoSessions('127.0.0.1', 6379, null, 0);
    echo '<div class="test-section success">
            <h3>✅ Подключение к Redis успешно</h3>
          </div>';
    
    // ========================================
    // УРОВЕНЬ ДОВЕРИЯ ПОЛЬЗОВАТЕЛЯ
    // ========================================
    
    // Получаем необходимые данные
    $diagnosis = $protection->diagnoseUserHash();
    $hashInfo = $protection->getUserHashInfo();
    $rateLimitStats = $protection->getRateLimitStats($diagnosis['ip']);
    $blockInfo = $protection->getBlockedIPInfo($diagnosis['ip']);
    
    // Расчет уровня доверия
    $trustScore = 0;
    $trustFactors = [];
    
    // Фактор 1: Валидная кука (20%)
    if (isset($_COOKIE['visitor_verified'])) {
        $cookieData = json_decode($_COOKIE['visitor_verified'], true);
        if ($cookieData && isset($cookieData['hash'], $cookieData['time'])) {
            $trustScore += 20;
            $trustFactors[] = [
                'icon' => '🍪',
                'text' => 'Валидная кука присутствует',
                'value' => '+20%',
                'positive' => true
            ];
        } else {
            $trustFactors[] = [
                'icon' => '❌',
                'text' => 'Невалидная кука',
                'value' => '0%',
                'positive' => false
            ];
        }
    } else {
        $trustFactors[] = [
            'icon' => '⚠️',
            'text' => 'Кука отсутствует',
            'value' => '0%',
            'positive' => false
        ];
    }
    
    // Фактор 2: IP не заблокирован (20%)
    if (!$blockInfo['blocked']) {
        $trustScore += 20;
        $trustFactors[] = [
            'icon' => '✅',
            'text' => 'IP адрес не заблокирован',
            'value' => '+20%',
            'positive' => true
        ];
    } else {
        $trustFactors[] = [
            'icon' => '🚫',
            'text' => 'IP адрес заблокирован',
            'value' => '0%',
            'positive' => false
        ];
    }
    
    // Фактор 3: User Hash не заблокирован (20%)
    if (!$hashInfo['blocked']) {
        $trustScore += 20;
        $trustFactors[] = [
            'icon' => '✅',
            'text' => 'User Hash не заблокирован',
            'value' => '+20%',
            'positive' => true
        ];
    } else {
        $trustFactors[] = [
            'icon' => '🚫',
            'text' => 'User Hash заблокирован',
            'value' => '0%',
            'positive' => false
        ];
    }
    
    // Фактор 4: Нормальная активность (15%)
    if ($rateLimitStats['current_stats']) {
        $rl = $rateLimitStats['current_stats'];
        $requests1min = $rl['requests_1min'] ?? 0;
        $maxPerMin = 60; // из настроек по умолчанию
        
        if ($requests1min < $maxPerMin * 0.3) {
            $trustScore += 15;
            $trustFactors[] = [
                'icon' => '📊',
                'text' => 'Нормальная активность',
                'value' => '+15%',
                'positive' => true
            ];
        } elseif ($requests1min < $maxPerMin * 0.7) {
            $trustScore += 8;
            $trustFactors[] = [
                'icon' => '⚠️',
                'text' => 'Повышенная активность',
                'value' => '+8%',
                'positive' => false
            ];
        } else {
            $trustFactors[] = [
                'icon' => '🔥',
                'text' => 'Высокая активность',
                'value' => '0%',
                'positive' => false
            ];
        }
    } else {
        $trustScore += 15;
        $trustFactors[] = [
            'icon' => '📊',
            'text' => 'Первый визит / низкая активность',
            'value' => '+15%',
            'positive' => true
        ];
    }
    
    // Фактор 5: Отсутствие нарушений (15%)
    if ($rateLimitStats['current_stats']) {
        $violations = $rateLimitStats['current_stats']['violations'] ?? 0;
        if ($violations == 0) {
            $trustScore += 15;
            $trustFactors[] = [
                'icon' => '✅',
                'text' => 'Нет нарушений лимитов',
                'value' => '+15%',
                'positive' => true
            ];
        } else {
            $trustFactors[] = [
                'icon' => '⚠️',
                'text' => "Нарушений: $violations",
                'value' => '0%',
                'positive' => false
            ];
        }
    } else {
        $trustScore += 15;
        $trustFactors[] = [
            'icon' => '✅',
            'text' => 'Нет нарушений лимитов',
            'value' => '+15%',
            'positive' => true
        ];
    }
    
    // Фактор 6: Расширенное отслеживание (10%)
    if (!$diagnosis['extended_tracking']) {
        $trustScore += 10;
        $trustFactors[] = [
            'icon' => '👁️',
            'text' => 'Расширенное отслеживание не активно',
            'value' => '+10%',
            'positive' => true
        ];
    } else {
        $trustFactors[] = [
            'icon' => '🔍',
            'text' => 'Под расширенным наблюдением',
            'value' => '0%',
            'positive' => false
        ];
    }
    
    // Определяем статус доверия
    $trustStatus = '';
    $trustStatusClass = '';
    if ($trustScore >= 80) {
        $trustStatus = 'Высокий уровень доверия';
        $trustStatusClass = 'high';
    } elseif ($trustScore >= 50) {
        $trustStatus = 'Средний уровень доверия';
        $trustStatusClass = 'medium';
    } else {
        $trustStatus = 'Низкий уровень доверия';
        $trustStatusClass = 'low';
    }
    
    // Вывод блока с уровнем доверия
    echo '<div class="trust-level-container">
            <div class="trust-level-header">
                <div>
                    <h2 style="color: #333; margin-bottom: 5px;">🛡️ Уровень доверия пользователя</h2>
                    <div class="trust-label">' . htmlspecialchars($diagnosis['ip']) . ' • ' . htmlspecialchars($diagnosis['device_type']) . '</div>
                    <span class="trust-status ' . $trustStatusClass . '">' . $trustStatus . '</span>
                </div>
                <div class="trust-percentage">' . $trustScore . '%</div>
            </div>
            
            <div class="progress-bar-container">
                <div class="progress-bar-fill" style="width: ' . $trustScore . '%;">
                    ' . ($trustScore > 10 ? $trustScore . '%' : '') . '
                </div>
            </div>
            
            <div class="trust-factors">';
    
    foreach ($trustFactors as $factor) {
        $factorClass = $factor['positive'] ? 'positive' : 'negative';
        echo '<div class="trust-factor ' . $factorClass . '">
                <div class="trust-factor-icon">' . $factor['icon'] . '</div>
                <div class="trust-factor-text">
                    ' . htmlspecialchars($factor['text']) . '
                </div>
                <div class="trust-factor-value">' . htmlspecialchars($factor['value']) . '</div>
              </div>';
    }
    
    echo '</div></div>';
    
    // ========================================
    // 1. ТЕСТ БАЗОВОЙ ФУНКЦИОНАЛЬНОСТИ
    // ========================================
    echo '<div class="test-section">
            <h2>1. Базовая функциональность</h2>';
    
    // Текущий пользователь
    $diagnosis = $protection->diagnoseUserHash();
    echo '<div class="test-item info">
            <h3>👤 Информация о текущем пользователе</h3>
            <table>
                <tr><td><strong>IP адрес:</strong></td><td>' . htmlspecialchars($diagnosis['ip']) . '</td></tr>
                <tr><td><strong>User Hash:</strong></td><td>' . htmlspecialchars($diagnosis['stable_hash']) . '</td></tr>
                <tr><td><strong>Тип устройства:</strong></td><td>' . htmlspecialchars($diagnosis['device_type']) . '</td></tr>
                <tr><td><strong>Браузер:</strong></td><td>' . htmlspecialchars($diagnosis['browser']['name'] . ' ' . $diagnosis['browser']['version']) . '</td></tr>
                <tr><td><strong>Платформа:</strong></td><td>' . htmlspecialchars($diagnosis['browser']['platform']) . '</td></tr>
                <tr><td><strong>Расширенное отслеживание:</strong></td><td>' . ($diagnosis['extended_tracking'] ? '<span class="badge badge-warning">Активно</span>' : '<span class="badge badge-success">Нет</span>') . '</td></tr>
            </table>
          </div>';
    
    // Проверка hash info
    $hashInfo = $protection->getUserHashInfo();
    echo '<div class="test-item ' . ($hashInfo['blocked'] ? 'error' : 'success') . '">
            <h3>🔐 Статус User Hash</h3>
            <p><strong>Заблокирован:</strong> ' . ($hashInfo['blocked'] ? '❌ ДА' : '✅ НЕТ') . '</p>';
    if ($hashInfo['blocked']) {
        echo '<p><strong>Причина:</strong> ' . htmlspecialchars($hashInfo['block_data']['blocked_reason'] ?? 'неизвестна') . '</p>';
        echo '<p><strong>Время блокировки:</strong> ' . date('Y-m-d H:i:s', $hashInfo['block_data']['blocked_at'] ?? 0) . '</p>';
    }
    echo '</div>';
    
    echo '</div>';
    
    // ========================================
    // 2. ОБЩАЯ СТАТИСТИКА
    // ========================================
    $stats = $protection->getStats();
    echo '<div class="test-section">
            <h2>2. Общая статистика системы</h2>
            <div class="stat-grid">
                <div class="stat-card">
                    <div class="number">' . $stats['blocked_ips'] . '</div>
                    <div class="label">Заблокировано IP</div>
                </div>
                <div class="stat-card">
                    <div class="number">' . $stats['blocked_user_hashes'] . '</div>
                    <div class="label">Заблокировано Hash</div>
                </div>
                <div class="stat-card">
                    <div class="number">' . $stats['tracking_records'] . '</div>
                    <div class="label">Отслеживается IP</div>
                </div>
                <div class="stat-card">
                    <div class="number">' . $stats['rate_limit_violations'] . '</div>
                    <div class="label">Нарушений лимитов</div>
                </div>
                <div class="stat-card">
                    <div class="number">' . $stats['extended_tracking_active'] . '</div>
                    <div class="label">Расширенное отслеживание</div>
                </div>
                <div class="stat-card">
                    <div class="number">' . $stats['total_keys'] . '</div>
                    <div class="label">Всего ключей в Redis</div>
                </div>
            </div>
          </div>';
    
    // ========================================
    // 3. RATE LIMITING
    // ========================================
    echo '<div class="test-section">
            <h2>3. Rate Limiting</h2>';
    
    // Данные уже получены выше для расчета уровня доверия
    $ip = $diagnosis['ip'];
    
    if ($rateLimitStats['current_stats']) {
        $rl = $rateLimitStats['current_stats'];
        echo '<div class="test-item info">
                <h3>📊 Текущие лимиты для вашего IP</h3>
                <table>
                    <tr><td><strong>Запросов за минуту:</strong></td><td>' . ($rl['requests_1min'] ?? 0) . '</td></tr>
                    <tr><td><strong>Запросов за 5 минут:</strong></td><td>' . ($rl['requests_5min'] ?? 0) . '</td></tr>
                    <tr><td><strong>Запросов за час:</strong></td><td>' . ($rl['requests_1hour'] ?? 0) . '</td></tr>
                    <tr><td><strong>Нарушений:</strong></td><td>' . ($rl['violations'] ?? 0) . '</td></tr>
                    <tr><td><strong>Последний запрос:</strong></td><td>' . date('Y-m-d H:i:s', $rl['last_request'] ?? 0) . '</td></tr>
                </table>
              </div>';
    } else {
        echo '<div class="test-item success">
                <h3>✅ Rate Limiting</h3>
                <p>Нет активных ограничений для вашего IP</p>
              </div>';
    }
    
    // Топ нарушителей
    $violators = $protection->getTopRateLimitViolators(5);
    if (!empty($violators)) {
        echo '<div class="test-item warning">
                <h3>⚠️ Топ-5 нарушителей Rate Limit</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Нарушений</th>
                            <th>1 мин</th>
                            <th>5 мин</th>
                            <th>1 час</th>
                            <th>Последний запрос</th>
                        </tr>
                    </thead>
                    <tbody>';
        foreach ($violators as $v) {
            echo '<tr>
                    <td><span class="badge badge-danger">' . $v['violations'] . '</span></td>
                    <td>' . $v['requests_1min'] . '</td>
                    <td>' . $v['requests_5min'] . '</td>
                    <td>' . $v['requests_1hour'] . '</td>
                    <td>' . $v['last_request'] . '</td>
                  </tr>';
        }
        echo '</tbody></table></div>';
    }
    
    echo '</div>';
    
    // ========================================
    // 4. НАСТРОЙКИ СИСТЕМЫ
    // ========================================
    echo '<div class="test-section">
            <h2>4. Текущие настройки</h2>';
    
    $rateLimitSettings = $protection->getRateLimitSettings();
    echo '<div class="test-item info">
            <h3>⚙️ Rate Limit Settings</h3>
            <table>
                <tr><td><strong>Макс. запросов/минута:</strong></td><td>' . $rateLimitSettings['max_requests_per_minute'] . '</td></tr>
                <tr><td><strong>Макс. запросов/5мин:</strong></td><td>' . $rateLimitSettings['max_requests_per_5min'] . '</td></tr>
                <tr><td><strong>Макс. запросов/час:</strong></td><td>' . $rateLimitSettings['max_requests_per_hour'] . '</td></tr>
                <tr><td><strong>Порог всплеска:</strong></td><td>' . $rateLimitSettings['burst_threshold'] . ' за ' . $rateLimitSettings['burst_window'] . ' сек</td></tr>
                <tr><td><strong>Смена UA (порог):</strong></td><td>' . $rateLimitSettings['ua_change_threshold'] . ' за ' . $rateLimitSettings['ua_change_time_window'] . ' сек</td></tr>
            </table>
          </div>';
    
    $slowBotSettings = $protection->getSlowBotSettings();
    echo '<div class="test-item info">
            <h3>🐌 Slow Bot Settings</h3>
            <table>
                <tr><td><strong>Мин. запросов для анализа:</strong></td><td>' . $slowBotSettings['min_requests_for_analysis'] . '</td></tr>
                <tr><td><strong>Длинная сессия (часы):</strong></td><td>' . $slowBotSettings['long_session_hours'] . '</td></tr>
                <tr><td><strong>Мин. запросов slow bot:</strong></td><td>' . $slowBotSettings['slow_bot_min_requests'] . '</td></tr>
            </table>
          </div>';
    
    echo '</div>';
    
    // ========================================
    // 5. ТЕСТ RDNS
    // ========================================
    echo '<div class="test-section">
            <h2>5. Тест верификации поисковиков (rDNS)</h2>
            <div class="test-item info">
                <h3>🔍 Примеры проверки известных поисковиков</h3>
                <p>Раскомментируйте строки в коде для полного теста rDNS</p>
                <div class="code-block">// Googlebot
$protection->testRDNS(\'66.249.66.1\', \'Mozilla/5.0 (compatible; Googlebot/2.1)\');

// Bingbot
$protection->testRDNS(\'40.77.167.181\', \'Mozilla/5.0 (compatible; bingbot/2.0)\');

// Fake bot
$protection->testRDNS(\'1.2.3.4\', \'Mozilla/5.0 (compatible; Googlebot/2.1)\');</div>
            </div>
          </div>';
    
    // ========================================
    // 6. ПРИМЕРЫ УПРАВЛЕНИЯ
    // ========================================
    echo '<div class="test-section">
            <h2>6. Административные функции</h2>
            <div class="test-item info">
                <h3>🛠️ Примеры использования</h3>
                <div class="code-block">// Разблокировать IP
$protection->unblockIP(\'1.2.3.4\');
$protection->resetRateLimit(\'1.2.3.4\');

// Разблокировать текущего пользователя
$protection->unblockUserHash();

// Получить информацию о блокировке
$info = $protection->getBlockedIPInfo(\'1.2.3.4\');
print_r($info);

// Очистка данных
$cleaned = $protection->cleanup(true);
$deepCleaned = $protection->deepCleanup();

// Изменить настройки
$protection->updateRateLimitSettings([
    \'max_requests_per_minute\' => 120,
    \'burst_threshold\' => 30
]);</div>
            </div>
          </div>';
    
    // ========================================
    // 7. РЕКОМЕНДАЦИИ
    // ========================================
    echo '<div class="test-section">
            <h2>7. Рекомендации</h2>';
    
    if ($stats['rate_limit_violations'] > 50) {
        echo '<div class="test-item warning">
                <h3>⚠️ Высокое количество нарушений лимитов</h3>
                <p>Обнаружено ' . $stats['rate_limit_violations'] . ' нарушений. Рекомендуется:</p>
                <ul>
                    <li>Проверить логи на предмет атак</li>
                    <li>Возможно, увеличить лимиты для легитимных пользователей</li>
                    <li>Проверить топ нарушителей выше</li>
                </ul>
              </div>';
    }
    
    if ($stats['blocked_ips'] > 20) {
        echo '<div class="test-item warning">
                <h3>⚠️ Большое количество заблокированных IP</h3>
                <p>Заблокировано ' . $stats['blocked_ips'] . ' IP адресов. Это может указывать на:</p>
                <ul>
                    <li>Активную атаку ботов</li>
                    <li>Слишком строгие настройки</li>
                    <li>Необходимость анализа паттернов блокировок</li>
                </ul>
              </div>';
    }
    
    if ($stats['blocked_ips'] == 0 && $stats['rate_limit_violations'] == 0) {
        echo '<div class="test-item success">
                <h3>✅ Система работает нормально</h3>
                <p>Нет активных блокировок и нарушений. Система готова к защите.</p>
              </div>';
    }
    
    echo '</div>';
    
} catch (Exception $e) {
    echo '<div class="test-section error">
            <h3>❌ Ошибка при тестировании</h3>
            <p><strong>Сообщение:</strong> ' . htmlspecialchars($e->getMessage()) . '</p>
            <p><strong>Проверьте:</strong></p>
            <ul>
                <li>Запущен ли Redis сервер (redis-cli ping)</li>
                <li>Правильность настроек подключения</li>
                <li>Доступность Redis по указанному адресу и порту</li>
            </ul>
          </div>';
}

?>

        <div class="header" style="text-align: center; margin-top: 20px;">
            <p>Тестирование завершено • <?php echo date('Y-m-d H:i:s'); ?></p>
            <a href="?" class="btn">🔄 Обновить тест</a>
        </div>
    </div>
</body>
</html>
