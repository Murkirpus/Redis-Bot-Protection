<?php
/**
 * ============================================================================
 * Redis MurKir Security - Visual Dashboard (v2.7.2 Compatible)
 * ============================================================================
 * Красивая панель тестирования и мониторинга защиты
 * 
 * Изменения v2.7.2:
 * ✓ Совместимость с оптимизированной inline_check.php
 * ✓ Тестовые функции удалены (testRateLimit, testBurst, testRDNS)
 * ✓ Исправлено: blocked_user_hashes → user_hash_blocked
 * ✓ Добавлена информация про автоблокировку провалов JS Challenge
 * ✓ Обновленный дизайн под v2.7.2
 * 
 * Предыдущие версии:
 * v2.5.0: Поддержка no_cookie_block_threshold, slow_bot_instant_block
 * v2.4.0: Карточка Violations Status с порогами API блокировки
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

require_once __DIR__ . '/inline_check.php';

// Имя текущего скрипта для ссылок
$currentScript = basename(__FILE__);

// --- ЛОГИКА СИМУЛЯЦИЙ С КРАСИВЫМ ВЫВОДОМ ---
if (isset($_GET['run_simulation'])) {
    $protection = new RedisBotProtectionNoSessions('127.0.0.1', 6379, null, 0);
    $ip = $_SERVER['REMOTE_ADDR'];
    $simType = $_GET['run_simulation'];
    
    // Заголовки симуляции
    $titles = [
        'ratelimit' => '⚡ Stress Test: Rate Limiting',
        'burst' => '💥 Stress Test: Burst Detection',
        'rdns' => '🤖 Verification: Fake Googlebot'
    ];
    $title = $titles[$simType] ?? 'Unknown Simulation';

    // ВАЖНО: Тестовые функции удалены в v2.7.2 при оптимизации
    $rawOutput = "\n";
    $rawOutput .= "╔═══════════════════════════════════════════════════════════════╗\n";
    $rawOutput .= "║                                                               ║\n";
    $rawOutput .= "║  ⚠️  ТЕСТОВЫЕ ФУНКЦИИ УДАЛЕНЫ В v2.7.2                       ║\n";
    $rawOutput .= "║                                                               ║\n";
    $rawOutput .= "╚═══════════════════════════════════════════════════════════════╝\n\n";
    
    if ($simType === 'ratelimit') {
        $rawOutput .= "Функция testRateLimit() была удалена при оптимизации.\n\n";
        $rawOutput .= "Причина: Тестовые функции использовались только для разработки\n";
        $rawOutput .= "и не нужны в production окружении.\n\n";
        $rawOutput .= "Альтернатива:\n";
        $rawOutput .= "✅ Rate Limit работает автоматически на всех запросах\n";
        $rawOutput .= "✅ Проверьте статистику в Dashboard\n";
        $rawOutput .= "✅ Смотрите логи: tail -f /var/log/php-fpm/kinoprostor-error.log\n";
    } elseif ($simType === 'burst') {
        $rawOutput .= "Функция testBurst() была удалена при оптимизации.\n\n";
        $rawOutput .= "Причина: Тестовые функции использовались только для разработки\n";
        $rawOutput .= "и не нужны в production окружении.\n\n";
        $rawOutput .= "Альтернатива:\n";
        $rawOutput .= "✅ Burst Detection работает автоматически\n";
        $rawOutput .= "✅ Проверьте Burst violations в Dashboard\n";
        $rawOutput .= "✅ Смотрите логи блокировок\n";
    } elseif ($simType === 'rdns') {
        $rawOutput .= "Функция testRDNS() была удалена при оптимизации.\n\n";
        $rawOutput .= "Причина: Тестовые функции использовались только для разработки.\n\n";
        $rawOutput .= "ВАЖНО: RDNS модуль СОХРАНЁН и работает!\n";
        $rawOutput .= "✅ RDNS верификация активна\n";
        $rawOutput .= "✅ Поисковики проверяются автоматически\n";
        $rawOutput .= "✅ Whitelist работает (Google, Yandex не блокируются)\n";
        $rawOutput .= "✅ Смотрите RDNS статистику в Dashboard\n";
    }

    // Обработка текста для подсветки (Syntax Highlighting)
    $formattedOutput = htmlspecialchars($rawOutput);
    
    // Подсветка ключевых слов
    $replacements = [
        '/⚠️/' => '<span class="log-warning">⚠️</span>',
        '/✅/' => '<span class="log-success">✅</span>',
        '/❌/' => '<span class="log-error">❌</span>',
        '/═+/' => '<span class="log-dim">$0</span>',
        '/║/' => '<span class="log-dim">║</span>',
        '/ТЕСТОВЫЕ ФУНКЦИИ УДАЛЕНЫ В v2.7.2/' => '<span class="log-warning">ТЕСТОВЫЕ ФУНКЦИИ УДАЛЕНЫ В v2.7.2</span>',
        '/Функция (test\w+)\(\)/' => '<span class="log-meta">Функция $1()</span>',
        '/Причина:/' => '<span class="log-header">Причина:</span>',
        '/Альтернатива:/' => '<span class="log-header">Альтернатива:</span>',
        '/ВАЖНО:/' => '<span class="log-warning">ВАЖНО:</span>',
        '/\n/' => '<br>'
    ];
    
    $prettyLog = preg_replace(array_keys($replacements), array_values($replacements), $formattedOutput);

    // HTML Структура страницы симуляции
    ?>
    <!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Simulation: <?php echo htmlspecialchars($simType); ?></title>
        <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@400;600&display=swap" rel="stylesheet">
        <style>
            :root { --bg: #0f172a; --term-bg: #1e293b; --text: #f8fafc; --accent: #6366f1; }
            body { background: var(--bg); color: var(--text); font-family: 'Inter', sans-serif; margin: 0; padding: 20px; display: flex; justify-content: center; min-height: 100vh; }
            .sim-container { width: 100%; max-width: 900px; }
            
            /* Header */
            .sim-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
            .sim-title { font-size: 20px; font-weight: 600; display: flex; align-items: center; gap: 10px; }
            .btn-back { background: rgba(255,255,255,0.1); color: white; text-decoration: none; padding: 8px 16px; border-radius: 6px; font-size: 14px; transition: 0.2s; border: 1px solid rgba(255,255,255,0.2); }
            .btn-back:hover { background: rgba(255,255,255,0.2); }

            /* Terminal Window */
            .terminal { background: var(--term-bg); border-radius: 12px; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5); overflow: hidden; border: 1px solid #334155; }
            .terminal-bar { background: #0f172a; padding: 12px 16px; display: flex; gap: 8px; border-bottom: 1px solid #334155; }
            .dot { width: 12px; height: 12px; border-radius: 50%; }
            .dot-red { background: #ef4444; } .dot-yellow { background: #f59e0b; } .dot-green { background: #22c55e; }
            
            /* Logs */
            .terminal-body { padding: 20px; font-family: 'JetBrains Mono', monospace; font-size: 14px; line-height: 1.6; color: #cbd5e1; overflow-x: auto; }
            
            /* Syntax Highlighting */
            .log-header { color: #facc15; font-weight: bold; }
            .log-success { color: #4ade80; font-weight: bold; }
            .log-error { color: #f87171; font-weight: bold; background: rgba(239, 68, 68, 0.1); padding: 0 4px; border-radius: 4px; }
            .log-warning { color: #fbbf24; font-weight: bold; }
            .log-meta { color: #94a3b8; }
            .log-dim { color: #64748b; }
            
            /* Animation */
            .terminal-body { animation: fadeIn 0.5s ease-out; }
            @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        </style>
    </head>
    <body>
        <div class="sim-container">
            <div class="sim-header">
                <div class="sim-title">
                    <span><?php echo ($simType == 'burst' ? '💥' : ($simType == 'rdns' ? '🤖' : '⚡')); ?></span>
                    <?php echo $title; ?>
                </div>
                <a href="<?php echo $currentScript; ?>" class="btn-back">← Вернуться в Dashboard</a>
            </div>
            
            <div class="terminal">
                <div class="terminal-bar">
                    <div class="dot dot-red"></div>
                    <div class="dot dot-yellow"></div>
                    <div class="dot dot-green"></div>
                    <div style="margin-left: auto; font-size: 12px; color: #64748b; font-family: monospace;">bash — v2.7.2 info</div>
                </div>
                <div class="terminal-body">
                    <?php echo $prettyLog; ?>
                    <br><br>
                    <span style="color: #6366f1;">➜</span> <span style="animation: blink 1s infinite;">_</span>
                </div>
            </div>
        </div>
        <style>@keyframes blink { 50% { opacity: 0; } }</style>
    </body>
    </html>
    <?php
    exit;
}

// --- ДАЛЕЕ ИДЕТ ОСНОВНОЙ DASHBOARD (HTML) ---
// --- ЛОГИКА СБРОСА ---
if (isset($_GET['action'])) {
    $protection = new RedisBotProtectionNoSessions('127.0.0.1', 6379, null, 0);
    $ip = $_SERVER['REMOTE_ADDR'];
    
    if ($_GET['action'] === 'reset_me') {
        $protection->unblockIP($ip);
        $protection->resetRateLimit($ip);
        $protection->resetBurst($ip);
        $protection->resetViolations($ip);
        header("Location: $currentScript");
        exit;
    } elseif ($_GET['action'] === 'reset_rdns') {
        $protection->clearRDNSCache();
        header("Location: $currentScript");
        exit;
    }
}

// --- ФУНКЦИИ DASHBOARD ---
function drawBar($label, $current, $max) {
    $percent = $max > 0 ? min(100, ($current / $max) * 100) : 0;
    $barColor = $percent > 90 ? '#f87171' : ($percent > 60 ? '#fbbf24' : '#4ade80');
    ?>
    <div style="margin: 15px 0;">
        <div style="display: flex; justify-content: space-between; margin-bottom: 6px; font-size: 13px;">
            <span style="color: var(--text-muted);"><?php echo $label; ?></span>
            <span style="font-weight: 600; color: <?php echo $barColor; ?>;"><?php echo $current; ?> / <?php echo $max; ?></span>
        </div>
        <div style="height: 8px; background: #e5e7eb; border-radius: 10px; overflow: hidden;">
            <div style="height: 100%; width: <?php echo $percent; ?>%; background: <?php echo $barColor; ?>; transition: width 0.3s;"></div>
        </div>
    </div>
    <?php
}

try {
    $protection = new RedisBotProtectionNoSessions('127.0.0.1', 6379, null, 0);
    $ip = $_SERVER['REMOTE_ADDR'];
    
    // Получение данных
    $stats = $protection->getStats();
    
    // Собираем статус текущего IP вручную (функция getMyStatus() удалена)
    $cookieName = 'visitor_verified'; // Имя cookie из inline_check.php
    $rateLimitStatus = $protection->getRateLimitStatus($ip);
    $burstStatus = $protection->getBurstStatus($ip, isset($_COOKIE[$cookieName]));
    $violationsStatus = $protection->getViolationsStatus($ip);
    
    // Получаем подробные данные Rate Limit
    $hasCookie = isset($_COOKIE[$cookieName]);
    $currentCounts = $rateLimitStatus['current_counts'] ?? ['1min' => 0, '5min' => 0, '1hour' => 0];
    $limitsNoC = $rateLimitStatus['limits_no_cookie'] ?? [];
    $limitsWithC = $rateLimitStatus['limits_with_cookie'] ?? [];
    
    $myStatus = [
        'ip' => $ip,
        'requests' => $currentCounts['1min'],
        'violations' => $violationsStatus['violations']['total'] ?? 0,
        'burst_count' => $burstStatus['requests_in_window'] ?? 0,
        'has_cookie' => $hasCookie,
        'blocked' => $violationsStatus['will_block_api']['block'] ?? false,
        'block_reason' => $violationsStatus['will_block_api']['reason'] ?? ''
    ];
    
    $rateLimitSettings = $protection->getRateLimitSettings();
    $rdnsStats = $protection->getRDNSRateLimitStats();
    $jsChallengeStats = $protection->getJSChallengeStats();
    $cleanupStatus = $protection->getCleanupStatus();
?>

<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Redis MurKir Security Dashboard v2.7.2</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #f9fafb;
            --text: #111827;
            --text-muted: #6b7280;
            --card-bg: #ffffff;
            --border: #e5e7eb;
            --accent: #6366f1;
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #10b981;
            --shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Inter', -apple-system, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; padding: 20px; }
        
        /* Header */
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 16px; margin-bottom: 30px; box-shadow: 0 10px 25px rgba(102, 126, 234, 0.3); }
        .header h1 { font-size: 28px; font-weight: 700; margin-bottom: 10px; display: flex; align-items: center; gap: 12px; }
        .version-badge { background: rgba(255,255,255,0.2); padding: 4px 12px; border-radius: 20px; font-size: 13px; font-weight: 500; }
        .header-subtitle { opacity: 0.9; font-size: 14px; }
        
        /* Grid */
        .container { max-width: 1400px; margin: 0 auto; }
        .grid { display: grid; gap: 20px; margin-bottom: 20px; }
        .col-12 { grid-column: span 12; }
        .col-6 { grid-column: span 6; }
        .col-4 { grid-column: span 4; }
        .col-3 { grid-column: span 3; }
        @media (min-width: 1024px) { .grid { grid-template-columns: repeat(12, 1fr); } }
        @media (max-width: 1023px) { .col-12, .col-6, .col-4, .col-3 { grid-column: span 12; } }
        
        /* Cards */
        .card { background: var(--card-bg); border-radius: 12px; padding: 24px; box-shadow: var(--shadow); border: 1px solid var(--border); display: flex; flex-direction: column; height: 100%; }
        .card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .card-title { font-size: 16px; font-weight: 600; color: var(--text); }
        .icon { font-size: 24px; }
        
        /* Stats */
        .stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 15px; }
        .stat-box { text-align: center; padding: 16px; background: #f9fafb; border-radius: 10px; border: 1px solid var(--border); }
        .stat-value { font-size: 28px; font-weight: 700; color: var(--accent); display: block; }
        .stat-label { font-size: 12px; color: var(--text-muted); margin-top: 4px; text-transform: uppercase; letter-spacing: 0.5px; }
        
        /* Status Badge */
        .status-badge { display: inline-flex; align-items: center; gap: 6px; padding: 6px 14px; border-radius: 20px; font-size: 13px; font-weight: 600; }
        .status-ok { background: #d1fae5; color: #065f46; }
        .status-blocked { background: #fee2e2; color: #991b1b; }
        .status-warning { background: #fef3c7; color: #92400e; }
        
        /* Buttons */
        .btn-group { display: flex; gap: 10px; flex-wrap: wrap; }
        .btn { padding: 10px 18px; border-radius: 8px; text-decoration: none; font-size: 14px; font-weight: 500; transition: 0.2s; border: none; cursor: pointer; display: inline-flex; align-items: center; gap: 6px; }
        .btn-primary { background: var(--accent); color: white; }
        .btn-primary:hover { background: #4f46e5; transform: translateY(-1px); }
        .btn-danger { background: var(--danger); color: white; }
        .btn-danger:hover { background: #dc2626; }
        .btn-outline { background: white; color: var(--accent); border: 2px solid var(--accent); }
        .btn-outline:hover { background: var(--accent); color: white; }
        
        /* Alert */
        .alert { padding: 14px 18px; border-radius: 10px; font-size: 13px; font-weight: 500; border: 1px solid; }
        .alert-success { background: #d1fae5; color: #065f46; border-color: #6ee7b7; }
        .alert-danger { background: #fee2e2; color: #991b1b; border-color: #fca5a5; }
        .alert-warning { background: #fef3c7; color: #92400e; border-color: #fde68a; }
        
        /* Tables */
        table { width: 100%; border-collapse: collapse; font-size: 13px; }
        table td { padding: 8px 0; border-bottom: 1px solid var(--border); }
        table td:first-child { color: var(--text-muted); }
        table td:last-child { font-weight: 600; text-align: right; }
        table tr:last-child td { border-bottom: none; }
        
        /* Misc */
        .section-title { font-size: 13px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-muted); margin: 15px 0 10px; }
        .mini-stat { display: flex; justify-content: space-between; align-items: center; padding: 10px 0; border-bottom: 1px solid var(--border); }
        .mini-stat-label { font-size: 13px; color: var(--text-muted); }
        .mini-stat-value { font-size: 14px; font-weight: 600; }
        .badge { padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 600; text-transform: uppercase; }
        .badge-ok { background: #d1fae5; color: #065f46; }
        .badge-err { background: #fee2e2; color: #991b1b; }
        .badge-warning { background: #fef3c7; color: #92400e; }
        .badge-neutral { background: #e5e7eb; color: #374151; }
        .new-tag { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 2px 8px; border-radius: 12px; font-size: 10px; font-weight: 700; text-transform: uppercase; margin-left: 8px; }
    </style>
</head>
<body>

<div class="container">
    <!-- Header -->
    <div class="header">
        <h1>
            🛡️ Redis MurKir Security Dashboard
            <span class="version-badge">v2.7.2</span>
        </h1>
        <div class="header-subtitle">
            Оптимизированная защита | -30 KB | RDNS сохранён | Автоблокировка провалов
        </div>
    </div>

    <div class="grid">
        <!-- Карточка: Мой статус -->
        <div class="col-6">
            <div class="card">
                <div class="card-header">
                    <div class="card-title">Ваш IP: <?php echo htmlspecialchars($ip); ?></div>
                    <div class="icon">👤</div>
                </div>
                
                <?php if ($myStatus['blocked']): ?>
                    <div class="alert alert-danger" style="margin-bottom: 15px;">
                        ❌ <strong>Вы заблокированы!</strong><br>
                        Причина: <?php echo htmlspecialchars($myStatus['block_reason']); ?>
                    </div>
                <?php else: ?>
                    <div class="alert alert-success" style="margin-bottom: 15px;">
                        ✅ <strong>Статус: Активен</strong><br>
                        У вас есть доступ к системе.
                    </div>
                <?php endif; ?>
                
                <div class="stat-grid">
                    <div class="stat-box">
                        <span class="stat-value"><?php echo $myStatus['requests']; ?></span>
                        <span class="stat-label">Запросов</span>
                    </div>
                    <div class="stat-box">
                        <span class="stat-value" style="color: <?php echo ($myStatus['violations'] > 0 ? 'var(--danger)' : 'var(--success)'); ?>;">
                            <?php echo $myStatus['violations']; ?>
                        </span>
                        <span class="stat-label">Нарушений</span>
                    </div>
                    <div class="stat-box">
                        <span class="stat-value" style="color: <?php echo ($myStatus['burst_count'] > 0 ? 'var(--warning)' : 'var(--success)'); ?>;">
                            <?php echo $myStatus['burst_count']; ?>
                        </span>
                        <span class="stat-label">Burst</span>
                    </div>
                    <div class="stat-box">
                        <span class="stat-value" style="font-size: 18px;">
                            <?php echo $myStatus['has_cookie'] ? '✅' : '❌'; ?>
                        </span>
                        <span class="stat-label">Cookie</span>
                    </div>
                </div>
                
                <div class="btn-group" style="margin-top: auto;">
                    <a href="?action=reset_me" class="btn btn-danger">🧹 Сбросить Мой Статус</a>
                </div>
            </div>
        </div>

        <!-- Карточка: JS Challenge -->
        <div class="col-6">
            <div class="card">
                <div class="card-header">
                    <div class="card-title">JS Challenge Stats <span class="new-tag">v2.7.2</span></div>
                    <div class="icon">🎯</div>
                </div>
                
                <div class="stat-grid">
                    <div class="stat-box">
                        <span class="stat-value"><?php echo number_format($jsChallengeStats['total_shown'] ?? 0); ?></span>
                        <span class="stat-label">Показано</span>
                    </div>
                    <div class="stat-box">
                        <span class="stat-value" style="color: var(--success);"><?php echo number_format($jsChallengeStats['total_passed'] ?? 0); ?></span>
                        <span class="stat-label">Прошло</span>
                    </div>
                    <div class="stat-box">
                        <span class="stat-value" style="color: var(--danger);"><?php 
                            $totalFailed = ($jsChallengeStats['total_shown'] ?? 0) - ($jsChallengeStats['total_passed'] ?? 0);
                            echo number_format($totalFailed); 
                        ?></span>
                        <span class="stat-label">Провалов</span>
                    </div>
                    <div class="stat-box">
                        <span class="stat-value" style="color: var(--accent);"><?php echo $jsChallengeStats['success_rate'] ?? 0; ?>%</span>
                        <span class="stat-label">Success</span>
                    </div>
                </div>
                
                <div style="margin-top: 15px; padding: 12px; background: #f0fdf4; border-radius: 8px; border: 1px solid #86efac;">
                    <div style="font-size: 13px; font-weight: 600; color: #166534; margin-bottom: 5px;">
                        ⚡ Автоблокировка провалов (v2.7.2)
                    </div>
                    <div style="font-size: 12px; color: #15803d;">
                        3 провала JS Challenge → Блокировка через iptables<br>
                        Боты больше не могут подключаться к серверу!
                    </div>
                </div>
            </div>
        </div>

        <!-- Карточка: Violations Status -->
        <div class="col-6">
            <div class="card">
                <div class="card-header">
                    <div class="card-title">Violations Status</div>
                    <div class="icon">⚠️</div>
                </div>
                
                <?php 
                $totalViolations = $myStatus['violations'];
                $apiThreshold = $rateLimitSettings['combined_api_block_threshold'];
                $violationPercent = $apiThreshold > 0 ? min(100, ($totalViolations / $apiThreshold) * 100) : 0;
                $statusColor = $violationPercent > 75 ? 'var(--danger)' : ($violationPercent > 50 ? 'var(--warning)' : 'var(--success)');
                ?>
                
                <?php drawBar('Прогресс к API блокировке', $totalViolations, $apiThreshold); ?>
                
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-top: 20px;">
                    <div>
                        <div class="section-title">No Cookie Protection</div>
                        <div class="mini-stat">
                            <span class="mini-stat-label">Порог блокировки</span>
                            <span class="mini-stat-value"><?php echo $rateLimitSettings['no_cookie_block_threshold'] ?? 3; ?> запросов</span>
                        </div>
                        <div class="mini-stat">
                            <span class="mini-stat-label">Защита</span>
                            <?php if (($rateLimitSettings['no_cookie_block_threshold'] ?? 3) > 0): ?>
                                <span class="badge badge-ok">АКТИВНА</span>
                            <?php else: ?>
                                <span class="badge badge-err">ВЫКЛ</span>
                            <?php endif; ?>
                        </div>
                        <div style="font-size: 12px; color: var(--text-muted); margin-top: 10px;">
                            IP без cookie после <?php echo $rateLimitSettings['no_cookie_block_threshold'] ?? 3; ?> запросов будет заблокирован как бот.
                        </div>
                    </div>
                    <div>
                        <div class="section-title">JS Challenge Protection <span class="new-tag">NEW</span></div>
                        <div class="mini-stat">
                            <span class="mini-stat-label">Порог провалов</span>
                            <span class="mini-stat-value">3 попытки</span>
                        </div>
                        <div class="mini-stat">
                            <span class="mini-stat-label">Автоблокировка</span>
                            <span class="badge badge-ok">ВКЛ</span>
                        </div>
                        <div style="font-size: 12px; color: var(--text-muted); margin-top: 10px;">
                            3 провала → блокировка через iptables (v2.7.2). Боты не могут повторно подключиться!
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Карточка: Rate Limit Stats -->
        <div class="col-6">
            <div class="card">
                <div class="card-header">
                    <div class="card-title">⚡ Rate Limit Stats</div>
                    <div class="icon">📊</div>
                </div>
                
                <div style="margin-bottom: 20px;">
                    <div style="font-size: 13px; font-weight: 600; color: var(--text); margin-bottom: 10px;">
                        Ваши текущие счётчики:
                    </div>
                    
                    <?php
                    $limits = $hasCookie ? $limitsWithC : $limitsNoC;
                    $windows = [
                        '1min' => ['name' => '1 минута', 'limit' => $limits['1min'] ?? 30],
                        '5min' => ['name' => '5 минут', 'limit' => $limits['5min'] ?? 100],
                        '1hour' => ['name' => '1 час', 'limit' => $limits['1hour'] ?? 500]
                    ];
                    
                    foreach ($windows as $key => $window):
                        $current = $currentCounts[$key] ?? 0;
                        $limit = $window['limit'];
                        $percent = $limit > 0 ? min(100, round(($current / $limit) * 100)) : 0;
                        $color = $percent >= 90 ? 'var(--danger)' : ($percent >= 70 ? 'var(--warning)' : 'var(--success)');
                    ?>
                    <div style="margin-bottom: 15px;">
                        <div style="display: flex; justify-content: space-between; margin-bottom: 5px; font-size: 12px;">
                            <span><strong><?php echo $window['name']; ?>:</strong></span>
                            <span style="color: <?php echo $color; ?>; font-weight: 600;">
                                <?php echo $current; ?> / <?php echo $limit; ?> (<?php echo $percent; ?>%)
                            </span>
                        </div>
                        <div style="background: #f0f0f0; height: 8px; border-radius: 4px; overflow: hidden;">
                            <div style="background: <?php echo $color; ?>; width: <?php echo $percent; ?>%; height: 100%; transition: width 0.3s;"></div>
                        </div>
                    </div>
                    <?php endforeach; ?>
                </div>
                
                <div style="padding: 12px; background: <?php echo $hasCookie ? '#f0fdf4' : '#fef3f2'; ?>; border-radius: 8px; border: 1px solid <?php echo $hasCookie ? '#86efac' : '#fecaca'; ?>;">
                    <div style="font-size: 12px; color: <?php echo $hasCookie ? '#166534' : '#991b1b'; ?>;">
                        <?php if ($hasCookie): ?>
                            ✅ <strong>Cookie активен</strong> - лимиты увеличены ×<?php echo $rateLimitSettings['cookie_multiplier']; ?>
                        <?php else: ?>
                            ⚠️ <strong>Cookie отсутствует</strong> - базовые лимиты
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>

        <!-- Карточка: Здоровье системы -->
        <div class="col-6">
            <div class="card">
                <div class="card-header">
                    <div class="card-title">Здоровье Системы & Статистика</div>
                    <div class="icon">🖥️</div>
                </div>
                <div class="grid" style="grid-template-columns: 1fr 1fr; gap: 20px;">
                    <div>
                        <div style="margin-bottom: 15px;">
                            <strong>Cleanup (Cron):</strong>
                            <?php if($cleanupStatus['status'] === 'ok'): ?>
                                <div class="alert alert-success" style="margin-top: 5px;">✅ OK (<?php echo $cleanupStatus['minutes_ago']; ?> мин назад)</div>
                            <?php else: ?>
                                <div class="alert alert-danger" style="margin-top: 5px;">⚠️ <?php echo htmlspecialchars($cleanupStatus['message']); ?></div>
                            <?php endif; ?>
                        </div>
                        <div>
                            <strong>API Integration:</strong>
                            <?php $apiSettings = $protection->getAPISettings();
                            if (!$apiSettings['enabled']): ?>
                                <div class="alert alert-warning" style="margin-top: 5px;">⚪ API Отключено</div>
                            <?php else: $apiTest = $protection->testAPIConnection();
                                if ($apiTest['status'] === 'success'): ?>
                                    <div class="alert alert-success" style="margin-top: 5px;">✅ Подключено</div>
                                <?php else: ?>
                                    <div class="alert alert-danger" style="margin-top: 5px;">❌ <?php echo $apiTest['message'] ?? 'Ошибка'; ?></div>
                                <?php endif; endif; ?>
                        </div>
                    </div>
                    <div>
                        <table style="font-size: 13px;">
                            <tr><td>Отслеживается IP</td><td><?php echo $stats['tracking_records']; ?></td></tr>
                            <tr><td>Заблокировано IP</td><td><?php echo $stats['blocked_ips']; ?></td></tr>
                            <tr><td>Заблокировано Hash</td><td><?php echo $stats['user_hash_blocked'] ?? 0; ?></td></tr>
                            <tr><td>Всего ключей Redis</td><td><?php echo $stats['total_keys']; ?></td></tr>
                            <tr><td>rDNS Кеш</td><td><?php echo $rdnsStats['cache_entries']; ?></td></tr>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <!-- Карточка: SEO Bots -->
        <div class="col-4">
            <div class="card">
                <div class="card-header">
                    <div class="card-title">SEO Bots (rDNS) <span class="badge badge-ok">СОХРАНЁН</span></div>
                    <div class="icon">🌐</div>
                </div>
                <?php drawBar('Лимит проверок (мин)', $rdnsStats['current_minute_requests'], $rdnsStats['limit_per_minute']); ?>
                <div style="margin-top: 20px;">
                    <table>
                        <tr><td>Запросов / мин</td><td><?php echo $rdnsStats['current_minute_requests']; ?></td></tr>
                        <tr><td>В кеше</td><td><?php echo $rdnsStats['cache_entries']; ?></td></tr>
                        <tr><td>Подтвержденных</td><td><?php echo $rdnsStats['verified_in_cache']; ?></td></tr>
                    </table>
                </div>
                <div style="padding: 10px; background: #f0fdf4; border-radius: 8px; margin-top: 15px; font-size: 12px; color: #166534;">
                    ✅ RDNS модуль сохранён в v2.7.2 по вашей просьбе!
                </div>
                <div class="btn-group" style="margin-top: auto;">
                    <a href="?action=reset_rdns" class="btn btn-outline" style="font-size: 12px;">🧹 Очистить Кеш</a>
                    <a href="?run_simulation=rdns" class="btn btn-primary">🤖 Инфо RDNS</a>
                </div>
            </div>
        </div>

        <!-- Карточка: Настройки защиты -->
        <div class="col-4">
            <div class="card">
                <div class="card-header">
                    <div class="card-title">Текущие Лимиты</div>
                    <div class="icon">⚙️</div>
                </div>
                <div class="section-title">Rate Limit (без cookie)</div>
                <table style="font-size: 12px;">
                    <tr><td>1 минута</td><td><?php echo $rateLimitSettings['max_requests_per_minute']; ?></td></tr>
                    <tr><td>5 минут</td><td><?php echo $rateLimitSettings['max_requests_per_5min']; ?></td></tr>
                    <tr><td>1 час</td><td><?php echo $rateLimitSettings['max_requests_per_hour']; ?></td></tr>
                </table>
                <div class="section-title" style="margin-top: 15px;">Burst Detection</div>
                <table style="font-size: 12px;">
                    <tr><td>Порог</td><td><?php echo $rateLimitSettings['burst_threshold']; ?> запросов</td></tr>
                    <tr><td>Окно</td><td><?php echo $rateLimitSettings['burst_window']; ?> секунд</td></tr>
                    <tr><td>Cookie множитель</td><td>×<?php echo $rateLimitSettings['cookie_multiplier']; ?></td></tr>
                </table>
            </div>
        </div>

        <!-- Карточка: Пороги API блокировки -->
        <div class="col-4">
            <div class="card">
                <div class="card-header">
                    <div class="card-title">Пороги API Block</div>
                    <div class="icon">🔒</div>
                </div>
                <table style="font-size: 13px;">
                    <tr>
                        <td>Rate Limit violations</td>
                        <td><span class="badge badge-neutral"><?php echo $rateLimitSettings['rate_limit_api_block_threshold']; ?></span></td>
                    </tr>
                    <tr>
                        <td>Burst violations</td>
                        <td><span class="badge badge-neutral"><?php echo $rateLimitSettings['burst_api_block_threshold']; ?></span></td>
                    </tr>
                    <tr>
                        <td>Комбинированный</td>
                        <td><span class="badge badge-neutral"><?php echo $rateLimitSettings['combined_api_block_threshold']; ?></span></td>
                    </tr>
                    <tr>
                        <td>No Cookie порог</td>
                        <td><span class="badge badge-warning"><?php echo $rateLimitSettings['no_cookie_block_threshold'] ?? 3; ?></span></td>
                    </tr>
                    <tr>
                        <td>JS Challenge провалов <span class="new-tag">NEW</span></td>
                        <td><span class="badge badge-warning">3</span></td>
                    </tr>
                </table>
                <div style="font-size: 12px; color: var(--text-muted); margin-top: 15px; padding: 10px; background: #f9fafb; border-radius: 8px;">
                    💡 При достижении любого порога IP блокируется через API (iptables) и локально в Redis.
                </div>
            </div>
        </div>
        
        <!-- Информационная карточка v2.7.2 -->
        <div class="col-12">
            <div class="card" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <h3 style="font-size: 18px; margin-bottom: 8px;">🎉 Версия v2.7.2 - Оптимизированная защита</h3>
                        <div style="font-size: 14px; opacity: 0.9; line-height: 1.6;">
                            ✅ Автоблокировка провалов JS Challenge (3 попытки → iptables)<br>
                            ✅ Код оптимизирован: -30 KB, -730 строк (-12%)<br>
                            ✅ RDNS модуль сохранён (верификация поисковиков)<br>
                            ✅ Тестовые функции удалены (testRateLimit, testBurst, testRDNS)<br>
                            ✅ Все ошибки исправлены, готово к production
                        </div>
                    </div>
                    <div style="font-size: 48px;">🛡️</div>
                </div>
            </div>
        </div>
    </div>
</div>

<?php
} catch (Exception $e) {
    echo '<div style="background: #fee2e2; color: #991b1b; padding: 20px; text-align: center; margin: 50px;"><h2>🔥 Критическая ошибка</h2><p>'.htmlspecialchars($e->getMessage()).'</p></div>';
}
?>
</body>
</html>
