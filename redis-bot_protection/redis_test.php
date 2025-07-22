<?php
// /home/kinoprostor/kinoprostor15.2/dos/bot_protection/redis_test.php

// Подключаем обновленную Redis-версию защиты
require_once 'inline_check.php';

// Инициализируем защиту (новый класс без сессий)
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
    error_log("Redis protection initialization failed: " . $e->getMessage());
}

// Вспомогательные функции (обновленные для новой версии)
function getCurrentIP() {
    $ipHeaders = [
        'HTTP_CF_CONNECTING_IP',
        'HTTP_X_REAL_IP', 
        'HTTP_X_FORWARDED_FOR',
        'REMOTE_ADDR'
    ];
    
    foreach ($ipHeaders as $header) {
        if (!empty($_SERVER[$header])) {
            $ips = explode(',', $_SERVER[$header]);
            return trim($ips[0]);
        }
    }
    
    return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

function getRedisStats($protection) {
    if (!$protection) return null;
    
    try {
        return $protection->getStats();
    } catch (Exception $e) {
        return null;
    }
}

function getRedisInfo($protection, $ip) {
    if (!$protection) return null;
    
    try {
        return $protection->getBlockedIPInfo($ip);
    } catch (Exception $e) {
        return null;
    }
}

function getUserHashInfo($protection) {
    if (!$protection) return null;
    
    try {
        return $protection->getUserHashInfo();
    } catch (Exception $e) {
        return null;
    }
}

function getUserHashStats($protection) {
    if (!$protection) return null;
    
    try {
        return $protection->getUserHashStats();
    } catch (Exception $e) {
        return null;
    }
}

function getUserHashDiagnosis($protection) {
    if (!$protection) return null;
    
    try {
        return $protection->diagnoseUserHash();
    } catch (Exception $e) {
        return null;
    }
}

function getTTLSettings($protection) {
    if (!$protection) return null;
    
    try {
        return $protection->getTTLSettings();
    } catch (Exception $e) {
        return null;
    }
}

function isMobileDevice($userAgent) {
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
    return preg_match($mobileRegex, $userAgent);
}

function isSuspiciousUserAgent($userAgent) {
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

function getBrowserInfo($userAgent) {
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

// Получаем данные
$currentIP = getCurrentIP();
$currentUA = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
$isMobile = isMobileDevice($currentUA);
$browserInfo = getBrowserInfo($currentUA);
$isSuspiciousUA = isSuspiciousUserAgent($currentUA);
$redisStats = $protectionActive ? getRedisStats($protection) : null;
$ipInfo = $protectionActive ? getRedisInfo($protection, $currentIP) : null;
$userHashInfo = $protectionActive ? getUserHashInfo($protection) : null;
$userHashStats = $protectionActive ? getUserHashStats($protection) : null;
$userHashDiagnosis = $protectionActive ? getUserHashDiagnosis($protection) : null;
$ttlSettings = $protectionActive ? getTTLSettings($protection) : null;

// Определяем статус защиты
$protectionLevel = 'basic';
if ($protectionActive && $userHashInfo) {
    $protectionLevel = 'maximum';
} elseif ($protectionActive) {
    $protectionLevel = 'enhanced';
}

// Определяем, есть ли visitor cookie
$hasVisitorCookie = isset($_COOKIE['visitor_verified']);
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ Redis MurKir Security Test v2.0 - No Sessions Protection</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }
        .container {
            max-width: 1600px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        .header {
            text-align: center;
            border-bottom: 3px solid #007bff;
            padding-bottom: 20px;
            margin-bottom: 30px;
            background: linear-gradient(135deg, #007bff, #0056b3);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin: -30px -30px 30px -30px;
            position: relative;
        }
        .version-badge {
            position: absolute;
            top: 15px;
            right: 15px;
            background: rgba(255, 255, 255, 0.9);
            color: #007bff;
            padding: 8px 15px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .status-indicator {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: bold;
            margin: 5px;
        }
        .status-connected {
            background: rgba(40, 167, 69, 0.2);
            color: #155724;
            border: 1px solid #28a745;
        }
        .status-disconnected {
            background: rgba(220, 53, 69, 0.2);
            color: #721c24;
            border: 1px solid #dc3545;
        }
        .status-card {
            background: linear-gradient(135deg, #e8f5e8, #d4edda);
            border: 1px solid #28a745;
            border-radius: 12px;
            padding: 25px;
            margin: 20px 0;
            box-shadow: 0 4px 15px rgba(40, 167, 69, 0.1);
            position: relative;
            overflow: hidden;
        }
        .status-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, #28a745, #20c997);
        }
        .status-card.warning {
            background: linear-gradient(135deg, #fff3cd, #ffeaa7);
            border-color: #ffc107;
            color: #856404;
        }
        .status-card.warning::before {
            background: linear-gradient(90deg, #ffc107, #ffca2c);
        }
        .status-card.error {
            background: linear-gradient(135deg, #f8d7da, #fab1a0);
            border-color: #dc3545;
            color: #721c24;
        }
        .status-card.error::before {
            background: linear-gradient(90deg, #dc3545, #e74c3c);
        }
        .status-card.redis {
            background: linear-gradient(135deg, #e3f2fd, #bbdefb);
            border-color: #2196f3;
            color: #0d47a1;
        }
        .status-card.redis::before {
            background: linear-gradient(90deg, #2196f3, #03a9f4);
        }
        .status-card.user-hash {
            background: linear-gradient(135deg, #f3e5f5, #e1bee7);
            border-color: #9c27b0;
            color: #4a148c;
        }
        .status-card.user-hash::before {
            background: linear-gradient(90deg, #9c27b0, #ab47bc);
        }
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 25px;
            margin: 25px 0;
        }
        .info-box {
            background: #f8f9fa;
            border-left: 4px solid #007bff;
            padding: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            transition: transform 0.3s ease;
        }
        .info-box:hover {
            transform: translateY(-3px);
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
        }
        .info-box h3 {
            margin-top: 0;
            color: #007bff;
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 1.2em;
        }
        .metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }
        .metric {
            text-align: center;
            padding: 25px;
            background: linear-gradient(135deg, #f8f9fa, #e9ecef);
            border-radius: 12px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }
        .metric::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, #007bff, #0056b3);
        }
        .metric:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.15);
        }
        .metric .number {
            font-size: 2.8em;
            font-weight: bold;
            color: #007bff;
            margin-bottom: 8px;
            text-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .metric .label {
            color: #6c757d;
            font-weight: 500;
            font-size: 0.95em;
        }
        .device-indicator {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            margin: 5px;
        }
        .device-mobile {
            background: rgba(33, 150, 243, 0.2);
            color: #01579b;
            border: 1px solid #2196f3;
        }
        .device-desktop {
            background: rgba(156, 39, 176, 0.2);
            color: #4a148c;
            border: 1px solid #9c27b0;
        }
        .hash-display {
            font-family: 'Consolas', 'Monaco', monospace;
            background: linear-gradient(135deg, #e9ecef, #f8f9fa);
            padding: 12px 16px;
            border-radius: 8px;
            border: 1px solid #dee2e6;
            word-break: break-all;
            font-size: 0.9em;
            line-height: 1.5;
            box-shadow: inset 0 2px 4px rgba(0,0,0,0.05);
            cursor: pointer;
            transition: all 0.3s ease;
        }
        .hash-display:hover {
            background: linear-gradient(135deg, #007bff, #0056b3);
            color: white;
            transform: scale(1.02);
        }
        .tabs {
            display: flex;
            background: #f8f9fa;
            border-radius: 12px;
            padding: 8px;
            margin-bottom: 25px;
            flex-wrap: wrap;
            box-shadow: inset 0 2px 4px rgba(0,0,0,0.05);
        }
        .tab {
            flex: 1;
            text-align: center;
            padding: 12px 16px;
            background: transparent;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s ease;
            min-width: 140px;
            font-size: 0.9em;
            font-weight: 500;
        }
        .tab.active {
            background: linear-gradient(135deg, #007bff, #0056b3);
            color: white;
            box-shadow: 0 4px 15px rgba(0, 123, 255, 0.3);
            transform: translateY(-2px);
        }
        .tab:hover:not(.active) {
            background: rgba(0, 123, 255, 0.1);
            color: #007bff;
        }
        .tab-content {
            display: none;
            animation: fadeIn 0.3s ease;
        }
        .tab-content.active {
            display: block;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            border-radius: 12px;
            overflow: hidden;
            background: white;
        }
        .table th, .table td {
            border: 1px solid #dee2e6;
            padding: 15px 18px;
            text-align: left;
        }
        .table th {
            background: linear-gradient(135deg, #007bff, #0056b3);
            color: white;
            font-weight: bold;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .table tr:nth-child(even) {
            background: #f8f9fa;
        }
        .table tr:hover {
            background: linear-gradient(135deg, #e3f2fd, #f1f8ff);
            transform: scale(1.01);
            transition: all 0.2s ease;
        }
        .btn {
            display: inline-block;
            padding: 12px 24px;
            background: linear-gradient(135deg, #007bff, #0056b3);
            color: white;
            text-decoration: none;
            border-radius: 8px;
            margin: 5px;
            transition: all 0.3s ease;
            border: none;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            box-shadow: 0 2px 10px rgba(0, 123, 255, 0.2);
        }
        .btn:hover {
            transform: translateY(-3px);
            box-shadow: 0 6px 20px rgba(0, 123, 255, 0.4);
        }
        .btn.secondary {
            background: linear-gradient(135deg, #6c757d, #495057);
            box-shadow: 0 2px 10px rgba(108, 117, 125, 0.2);
        }
        .btn.danger {
            background: linear-gradient(135deg, #dc3545, #c82333);
            box-shadow: 0 2px 10px rgba(220, 53, 69, 0.2);
        }
        .btn.success {
            background: linear-gradient(135deg, #28a745, #1e7e34);
            box-shadow: 0 2px 10px rgba(40, 167, 69, 0.2);
        }
        .btn.warning {
            background: linear-gradient(135deg, #ffc107, #e0a800);
            color: #212529;
            box-shadow: 0 2px 10px rgba(255, 193, 7, 0.2);
        }
        .protection-level {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 8px 16px;
            border-radius: 25px;
            font-weight: bold;
            font-size: 0.9em;
            margin: 10px 0;
        }
        .protection-basic {
            background: rgba(255, 193, 7, 0.2);
            color: #856404;
            border: 1px solid #ffc107;
        }
        .protection-enhanced {
            background: rgba(23, 162, 184, 0.2);
            color: #0c5460;
            border: 1px solid #17a2b8;
        }
        .protection-maximum {
            background: rgba(40, 167, 69, 0.2);
            color: #155724;
            border: 1px solid #28a745;
        }
        .redis-key {
            font-family: 'Consolas', 'Monaco', monospace;
            background: linear-gradient(135deg, #e9ecef, #f8f9fa);
            padding: 4px 8px;
            border-radius: 6px;
            font-size: 0.85em;
            border: 1px solid #dee2e6;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        .redis-key:hover {
            background: linear-gradient(135deg, #007bff, #0056b3);
            color: white;
        }
        pre {
            background: linear-gradient(135deg, #2d3748, #1a202c);
            color: #e2e8f0;
            border: 1px solid #4a5568;
            padding: 20px;
            border-radius: 12px;
            overflow-x: auto;
            font-size: 13px;
            font-family: 'Consolas', 'Monaco', monospace;
            max-height: 500px;
            line-height: 1.5;
            box-shadow: inset 0 2px 10px rgba(0,0,0,0.3);
        }
        .security-badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 4px 10px;
            border-radius: 15px;
            font-size: 0.8em;
            font-weight: bold;
            margin: 2px;
        }
        .security-safe {
            background: rgba(40, 167, 69, 0.2);
            color: #155724;
            border: 1px solid #28a745;
        }
        .security-suspicious {
            background: rgba(255, 193, 7, 0.2);
            color: #856404;
            border: 1px solid #ffc107;
        }
        .security-danger {
            background: rgba(220, 53, 69, 0.2);
            color: #721c24;
            border: 1px solid #dc3545;
        }
        .highlight-box {
            background: linear-gradient(135deg, #fff3cd, #ffeaa7);
            border: 1px solid #ffc107;
            border-radius: 8px;
            padding: 15px;
            margin: 15px 0;
            box-shadow: 0 2px 10px rgba(255, 193, 7, 0.1);
        }
        .new-feature {
            position: relative;
            overflow: hidden;
        }
        .new-feature::after {
            content: 'v2.0';
            position: absolute;
            top: 10px;
            right: 10px;
            background: linear-gradient(135deg, #ff6b6b, #ee5a52);
            color: white;
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 0.7em;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            box-shadow: 0 2px 6px rgba(255, 107, 107, 0.3);
        }
        @media (max-width: 768px) {
            .container {
                padding: 15px;
            }
            .info-grid {
                grid-template-columns: 1fr;
            }
            .metrics {
                grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            }
            .tabs {
                flex-direction: column;
            }
            .tab {
                flex: none;
                margin: 2px 0;
            }
            .version-badge {
                position: relative;
                top: 0;
                right: 0;
                margin-bottom: 15px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="version-badge">🛡️ No Sessions v2.0</div>
            
            <h1>🛡️ Redis MurKir Security System v2.0</h1>
            <p>Система защиты без сессий с блокировкой по хешу пользователя</p>
            
            <div style="margin-top: 20px; display: flex; flex-wrap: wrap; justify-content: center; gap: 10px;">
                <div class="status-indicator <?php echo $protectionActive ? 'status-connected' : 'status-disconnected'; ?>">
                    <?php echo $protectionActive ? '✅ Redis Connected' : '❌ Redis Disconnected'; ?>
                </div>
                
                <div class="device-indicator <?php echo $isMobile ? 'device-mobile' : 'device-desktop'; ?>">
                    <?php echo $isMobile ? '📱 Mobile Device' : '🖥️ Desktop Device'; ?>
                </div>
                
                <div class="security-badge <?php echo $isSuspiciousUA ? 'security-danger' : 'security-safe'; ?>">
                    <?php echo $isSuspiciousUA ? '⚠️ Suspicious UA' : '✅ Normal UA'; ?>
                </div>
                
                <div class="protection-level protection-<?php echo $protectionLevel; ?>">
                    <?php 
                    switch($protectionLevel) {
                        case 'maximum': echo '🛡️ Maximum Protection'; break;
                        case 'enhanced': echo '🔒 Enhanced Protection'; break;
                        default: echo '⚠️ Basic Protection'; break;
                    }
                    ?>
                </div>

                <div class="security-badge <?php echo $hasVisitorCookie ? 'security-safe' : 'security-suspicious'; ?>">
                    <?php echo $hasVisitorCookie ? '🍪 Cookie Set' : '⚠️ No Cookie'; ?>
                </div>
            </div>
        </div>

        <!-- Статус Redis v2.0 -->
        <div class="status-card redis <?php echo !$protectionActive ? 'error' : ''; ?>">
            <h2>📊 Статус Redis Protection v2.0 (No Sessions)</h2>
            <?php if ($protectionActive): ?>
                <p><strong>✅ Redis подключен и работает</strong></p>
                <div class="protection-level protection-maximum">🛡️ Максимальная защита активна без сессий</div>
                
                <?php if ($redisStats): ?>
                    <div class="metrics">
                        <div class="metric">
                            <div class="number"><?php echo $redisStats['blocked_ips'] ?? 0; ?></div>
                            <div class="label">Заблокированных IP</div>
                        </div>
                        <div class="metric">
                            <div class="number"><?php echo $redisStats['blocked_cookies'] ?? 0; ?></div>
                            <div class="label">Заблокированных cookies</div>
                        </div>
                        <div class="metric new-feature">
                            <div class="number"><?php echo $redisStats['blocked_user_hashes'] ?? 0; ?></div>
                            <div class="label">Заблокированных хешей</div>
                        </div>
                        <div class="metric new-feature">
                            <div class="number"><?php echo $redisStats['tracked_user_hashes'] ?? 0; ?></div>
                            <div class="label">Активный трекинг хешей</div>
                        </div>
                        <div class="metric">
                            <div class="number"><?php echo $redisStats['tracking_records'] ?? 0; ?></div>
                            <div class="label">Записей трекинга IP</div>
                        </div>
                        <div class="metric">
                            <div class="number"><?php echo $redisStats['total_keys'] ?? 0; ?></div>
                            <div class="label">Всего ключей Redis</div>
                        </div>
                        <div class="metric">
                            <div class="number"><?php echo is_string($redisStats['memory_usage'] ?? '') ? $redisStats['memory_usage'] : 'N/A'; ?></div>
                            <div class="label">Использование памяти</div>
                        </div>
                    </div>
                <?php endif; ?>
                
                <div class="highlight-box">
                    <strong>🚀 Особенности версии без сессий v2.0:</strong>
                    <ul>
                        <li>✅ Стабильная работа без зависимости от PHP сессий</li>
                        <li>🔐 Продвинутая система хеш-блокировки пользователей</li>
                        <li>📱 Оптимизация для мобильных устройств</li>
                        <li>⚡ Улучшенная производительность и скорость</li>
                        <li>🛡️ Более стабильная блокировка через отпечатки</li>
                        <li>🧹 Автоматическая очистка старых данных</li>
                    </ul>
                </div>
            <?php else: ?>
                <p><strong>❌ Redis недоступен</strong></p>
                <div class="protection-level protection-basic">⚠️ Базовая защита</div>
                <p>Проверьте подключение к Redis серверу. Система защиты не активна.</p>
            <?php endif; ?>
        </div>

        <!-- Информация о хеше пользователя v2.0 -->
        <?php if ($userHashInfo): ?>
        <div class="status-card user-hash <?php echo $userHashInfo['blocked'] ? 'error' : ''; ?> new-feature">
            <h2>🔐 Хеш пользователя (главная особенность v2.0)</h2>
            <div class="info-grid">
                <div>
                    <p><strong>Статус хеша:</strong> 
                        <?php if ($userHashInfo['blocked']): ?>
                            <span class="security-badge security-danger">🚫 Заблокирован</span>
                        <?php else: ?>
                            <span class="security-badge security-safe">✅ Активен</span>
                        <?php endif; ?>
                    </p>
                    
                    <p><strong>Превью хеша:</strong></p>
                    <div class="hash-display" onclick="copyToClipboard(this)" title="Нажмите для копирования">
                        <?php echo htmlspecialchars($userHashInfo['hash_preview']); ?>
                    </div>
                    
                    <div style="margin: 15px 0;">
                        <p><strong>Устройство:</strong> 
                            <span class="device-indicator <?php echo $isMobile ? 'device-mobile' : 'device-desktop'; ?>">
                                <?php echo $isMobile ? '📱 Мобильное' : '🖥️ Десктоп'; ?>
                            </span>
                        </p>
                        
                        <p><strong>Браузер:</strong> 
                            <span class="security-badge security-safe">
                                <?php echo $browserInfo['name'] . ' ' . $browserInfo['version']; ?>
                            </span>
                        </p>
                        
                        <p><strong>Платформа:</strong> 
                            <span class="security-badge security-safe">
                                <?php echo $browserInfo['platform']; ?>
                            </span>
                        </p>
                    </div>
                    
                    <?php if ($userHashInfo['blocked'] && $userHashInfo['block_ttl'] > 0): ?>
                        <div class="highlight-box">
                            <strong>⏰ Время до разблокировки:</strong> 
                            <span style="font-family: monospace; font-size: 1.1em;">
                                <?php echo gmdate('H:i:s', $userHashInfo['block_ttl']); ?>
                            </span>
                        </div>
                    <?php endif; ?>
                </div>
                
                <?php if ($userHashInfo['tracking_data']): ?>
                <div>
                    <h4>📊 Данные трекинга хеша:</h4>
                    <table class="table">
                        <tr>
                            <td><strong>Запросов:</strong></td>
                            <td><?php echo $userHashInfo['tracking_data']['requests'] ?? 0; ?></td>
                        </tr>
                        <tr>
                            <td><strong>Первый визит:</strong></td>
                            <td><?php echo date('Y-m-d H:i:s', $userHashInfo['tracking_data']['first_seen'] ?? time()); ?></td>
                        </tr>
                        <tr>
                            <td><strong>Последняя активность:</strong></td>
                            <td><?php echo date('Y-m-d H:i:s', $userHashInfo['tracking_data']['last_activity'] ?? time()); ?></td>
                        </tr>
                        <tr>
                            <td><strong>Уникальных IP:</strong></td>
                            <td><?php echo count(array_unique($userHashInfo['tracking_data']['ips'] ?? [])); ?></td>
                        </tr>
                        <tr>
                            <td><strong>Страниц посещено:</strong></td>
                            <td><?php echo count(array_unique($userHashInfo['tracking_data']['pages'] ?? [])); ?></td>
                        </tr>
                        <tr>
                            <td><strong>User-Agent'ов:</strong></td>
                            <td><?php echo count(array_unique($userHashInfo['tracking_data']['user_agents'] ?? [])); ?></td>
                        </tr>
                    </table>
                </div>
                <?php endif; ?>
            </div>
            
            <?php if ($userHashInfo['block_data']): ?>
            <div style="margin-top: 20px;">
                <h4>⚠️ Данные блокировки хеша:</h4>
                <pre><?php echo json_encode($userHashInfo['block_data'], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE); ?></pre>
            </div>
            <?php endif; ?>
        </div>
        <?php endif; ?>

        <!-- Диагностика хеша пользователя v2.0 -->
        <?php if ($userHashDiagnosis): ?>
        <div class="status-card new-feature">
            <h2>🔬 Диагностика хеша пользователя v2.0</h2>
            <div class="info-grid">
                <div>
                    <h4>🔍 Компоненты хеша:</h4>
                    <table class="table">
                        <tr>
                            <td><strong>Стабильный хеш:</strong></td>
                            <td><span class="redis-key"><?php echo $userHashDiagnosis['stable_hash']; ?></span></td>
                        </tr>
                        <tr>
                            <td><strong>IP отпечаток:</strong></td>
                            <td><span class="redis-key"><?php echo $userHashDiagnosis['ip_fingerprint']; ?></span></td>
                        </tr>
                        <tr>
                            <td><strong>Тип устройства:</strong></td>
                            <td><?php echo $userHashDiagnosis['device_type']; ?></td>
                        </tr>
                    </table>
                </div>
                <div>
                    <h4>🌐 Браузерная информация:</h4>
                    <table class="table">
                        <tr>
                            <td><strong>Браузер:</strong></td>
                            <td><?php echo $userHashDiagnosis['browser']['name']; ?></td>
                        </tr>
                        <tr>
                            <td><strong>Версия:</strong></td>
                            <td><?php echo $userHashDiagnosis['browser']['version']; ?></td>
                        </tr>
                        <tr>
                            <td><strong>Платформа:</strong></td>
                            <td><?php echo $userHashDiagnosis['browser']['platform']; ?></td>
                        </tr>
                        <tr>
                            <td><strong>Язык:</strong></td>
                            <td><?php echo substr($userHashDiagnosis['accept_language'], 0, 20); ?>...</td>
                        </tr>
                    </table>
                </div>
            </div>
        </div>
        <?php endif; ?>

        <!-- Информация о текущем IP -->
        <?php if ($ipInfo): ?>
        <div class="status-card <?php echo $ipInfo['blocked'] ? 'error' : ''; ?>">
            <h2>🌐 Информация о IP адресе</h2>
            <div class="info-grid">
                <div>
                    <p><strong>IP адрес:</strong> 
                        <span class="redis-key" onclick="copyToClipboard(this)"><?php echo htmlspecialchars($currentIP); ?></span>
                    </p>
                    <p><strong>Статус:</strong> 
                        <?php if ($ipInfo['blocked']): ?>
                            <span class="security-badge security-danger">🚫 Заблокирован</span>
                        <?php else: ?>
                            <span class="security-badge security-safe">✅ Разрешен</span>
                        <?php endif; ?>
                    </p>
                    <?php if ($ipInfo['blocked'] && $ipInfo['ttl'] > 0): ?>
                        <div class="highlight-box">
                            <strong>⏰ Время до разблокировки:</strong> 
                            <span style="font-family: monospace; font-size: 1.1em;">
                                <?php echo gmdate('H:i:s', $ipInfo['ttl']); ?>
                            </span>
                        </div>
                    <?php endif; ?>
                </div>
                
                <?php if ($ipInfo['block_data']): ?>
                <div>
                    <h4>⚠️ Данные блокировки IP:</h4>
                    <pre><?php echo json_encode($ipInfo['block_data'], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE); ?></pre>
                </div>
                <?php endif; ?>
            </div>
            
            <?php if ($ipInfo['tracking_data']): ?>
            <div style="margin-top: 20px;">
                <h4>📊 Данные трекинга IP:</h4>
                <pre><?php echo json_encode($ipInfo['tracking_data'], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE); ?></pre>
            </div>
            <?php endif; ?>
        </div>
        <?php endif; ?>

        <!-- Visitor Cookie Information -->
        <?php if ($hasVisitorCookie): ?>
        <div class="status-card">
            <h2>🍪 Информация о Visitor Cookie</h2>
            <p><strong>✅ Visitor Cookie установлена</strong></p>
            <div class="hash-display" onclick="copyToClipboard(this)" style="margin: 15px 0;">
                <?php echo htmlspecialchars(substr($_COOKIE['visitor_verified'], 0, 100)); ?>...
            </div>
            <p><em>Cookie обеспечивает дополнительную идентификацию пользователя</em></p>
        </div>
        <?php else: ?>
        <div class="status-card warning">
            <h2>🍪 Visitor Cookie</h2>
            <p><strong>⚠️ Visitor Cookie не установлена</strong></p>
            <p>Cookie будет установлена автоматически системой защиты при следующем запросе.</p>
        </div>
        <?php endif; ?>

        <!-- Табы -->
        <div class="tabs">
            <button class="tab active" onclick="showTab('request-info')">🌐 Запрос</button>
            <button class="tab" onclick="showTab('redis-keys')">🔑 Redis ключи</button>
            <button class="tab" onclick="showTab('user-hash-stats')">📊 Статистика хешей</button>
            <button class="tab" onclick="showTab('ttl-settings')">⏱️ TTL настройки</button>
            <button class="tab" onclick="showTab('testing')">🧪 Тестирование</button>
            <button class="tab" onclick="showTab('debug')">🔍 Debug</button>
        </div>

        <!-- Информация о запросе -->
        <div id="request-info" class="tab-content active">
            <div class="info-box">
                <h3>🌐 Детали запроса</h3>
                <table class="table">
                    <tr>
                        <td><strong>IP адрес:</strong></td>
                        <td>
                            <span class="redis-key" onclick="copyToClipboard(this)"><?php echo htmlspecialchars($currentIP); ?></span>
                        </td>
                    </tr>
                    <tr>
                        <td><strong>User-Agent:</strong></td>
                        <td>
                            <?php echo htmlspecialchars(substr($currentUA, 0, 100)) . (strlen($currentUA) > 100 ? '...' : ''); ?>
                            <?php if ($isSuspiciousUA): ?>
                                <span class="security-badge security-danger">⚠️ Подозрительный</span>
                            <?php else: ?>
                                <span class="security-badge security-safe">✅ Нормальный</span>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <tr>
                        <td><strong>Браузер:</strong></td>
                        <td><?php echo $browserInfo['name'] . ' ' . $browserInfo['version'] . ' (' . $browserInfo['platform'] . ')'; ?></td>
                    </tr>
                    <tr>
                        <td><strong>Устройство:</strong></td>
                        <td>
                            <span class="device-indicator <?php echo $isMobile ? 'device-mobile' : 'device-desktop'; ?>">
                                <?php echo $isMobile ? '📱 Мобильное устройство' : '🖥️ Десктопное устройство'; ?>
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <td><strong>Метод:</strong></td>
                        <td><?php echo $_SERVER['REQUEST_METHOD'] ?? 'GET'; ?></td>
                    </tr>
                    <tr>
                        <td><strong>Время:</strong></td>
                        <td><?php echo date('Y-m-d H:i:s'); ?></td>
                    </tr>
                    <tr>
                        <td><strong>URI:</strong></td>
                        <td><?php echo htmlspecialchars($_SERVER['REQUEST_URI'] ?? '/'); ?></td>
                    </tr>
                    <tr>
                        <td><strong>Referer:</strong></td>
                        <td><?php echo htmlspecialchars(substr($_SERVER['HTTP_REFERER'] ?? 'Прямой переход', 0, 60)); ?></td>
                    </tr>
                    <tr>
                        <td><strong>Accept Language:</strong></td>
                        <td><?php echo htmlspecialchars(substr($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? 'N/A', 0, 40)); ?></td>
                    </tr>
                    <tr>
                        <td><strong>Accept Encoding:</strong></td>
                        <td><?php echo htmlspecialchars($_SERVER['HTTP_ACCEPT_ENCODING'] ?? 'N/A'); ?></td>
                    </tr>
                    <tr>
                        <td><strong>Visitor Cookie:</strong></td>
                        <td>
                            <?php if ($hasVisitorCookie): ?>
                                <span class="security-badge security-safe">✅ Установлена</span>
                            <?php else: ?>
                                <span class="security-badge security-suspicious">⚠️ Отсутствует</span>
                            <?php endif; ?>
                        </td>
                    </tr>
                </table>
            </div>
        </div>

        <!-- Redis ключи -->
        <div id="redis-keys" class="tab-content">
            <div class="info-box">
                <h3>🔑 Redis ключи для текущего пользователя v2.0</h3>
                
                <?php if ($hasVisitorCookie): ?>
                    <h4>🍪 Visitor Cookie:</h4>
                    <div class="hash-display" onclick="copyToClipboard(this)" style="margin-bottom: 20px;">
                        <?php echo htmlspecialchars(substr($_COOKIE['visitor_verified'], 0, 150)); ?>...
                    </div>
                <?php else: ?>
                    <div class="highlight-box">
                        <p><strong>❌ Visitor Cookie не найдена</strong></p>
                        <p>Cookie будет установлена при следующем обновлении страницы, если система защиты активна.</p>
                    </div>
                <?php endif; ?>
                
                <h4>📋 Структура Redis ключей v2.0 (No Sessions):</h4>
                <table class="table">
                    <thead>
                        <tr>
                            <th>Тип ключа</th>
                            <th>Префикс</th>
                            <th>Пример ключа</th>
                            <th>Назначение</th>
                            <th>Статус</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>IP Tracking</td>
                            <td><code>bot_protection:tracking:ip:</code></td>
                            <td><span class="redis-key"><?php echo substr(hash('md5', $currentIP), 0, 12); ?>...</span></td>
                            <td>Отслеживание активности IP</td>
                            <td><span class="security-badge security-safe">Active</span></td>
                        </tr>
                        <tr>
                            <td>IP Block</td>
                            <td><code>bot_protection:blocked:ip:</code></td>
                            <td><span class="redis-key"><?php echo substr(hash('md5', $currentIP), 0, 12); ?>...</span></td>
                            <td>Блокировка IP адреса</td>
                            <td>
                                <?php if ($ipInfo && $ipInfo['blocked']): ?>
                                    <span class="security-badge security-danger">Blocked</span>
                                <?php else: ?>
                                    <span class="security-badge security-safe">Free</span>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <tr class="new-feature" style="background: rgba(156, 39, 176, 0.1);">
                            <td><strong>User Hash Block</strong></td>
                            <td><code>bot_protection:user_hash:blocked:</code></td>
                            <td><span class="redis-key"><?php echo $userHashInfo ? substr($userHashInfo['user_hash'], 0, 12) . '...' : 'N/A'; ?></span></td>
                            <td><strong>Блокировка по хешу пользователя (v2.0)</strong></td>
                            <td>
                                <?php if ($userHashInfo && $userHashInfo['blocked']): ?>
                                    <span class="security-badge security-danger">Blocked</span>
                                <?php else: ?>
                                    <span class="security-badge security-safe">Free</span>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <tr class="new-feature" style="background: rgba(156, 39, 176, 0.1);">
                            <td><strong>User Hash Tracking</strong></td>
                            <td><code>bot_protection:user_hash:tracking:</code></td>
                            <td><span class="redis-key"><?php echo $userHashInfo ? substr($userHashInfo['user_hash'], 0, 12) . '...' : 'N/A'; ?></span></td>
                            <td><strong>Трекинг активности хеша (v2.0)</strong></td>
                            <td><span class="security-badge security-safe">Active</span></td>
                        </tr>
                        <tr class="new-feature" style="background: rgba(156, 39, 176, 0.1);">
                            <td><strong>User Hash Stats</strong></td>
                            <td><code>bot_protection:user_hash:stats:</code></td>
                            <td><span class="redis-key"><?php echo $userHashInfo ? substr($userHashInfo['user_hash'], 0, 12) . '...' : 'N/A'; ?></span></td>
                            <td><strong>Статистика хеша (v2.0)</strong></td>
                            <td><span class="security-badge security-safe">Active</span></td>
                        </tr>
                        <tr>
                            <td>Cookie Block</td>
                            <td><code>bot_protection:cookie:blocked:</code></td>
                            <td><span class="redis-key">hash_md5...</span></td>
                            <td>Блокировка cookie</td>
                            <td><span class="security-badge security-safe">Free</span></td>
                        </tr>
                        <tr>
                            <td>rDNS Cache</td>
                            <td><code>bot_protection:rdns:cache:</code></td>
                            <td><span class="redis-key"><?php echo substr(hash('md5', $currentIP), 0, 12); ?>...</span></td>
                            <td>Кеш rDNS запросов</td>
                            <td><span class="security-badge security-safe">Active</span></td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Статистика хешей пользователей v2.0 -->
        <div id="user-hash-stats" class="tab-content">
            <div class="info-box new-feature">
                <h3>📊 Статистика хешей пользователей v2.0</h3>
                
                <?php if ($userHashStats): ?>
                    <div class="metrics" style="margin-bottom: 30px;">
                        <div class="metric">
                            <div class="number"><?php echo $userHashStats['blocked_user_hashes'] ?? 0; ?></div>
                            <div class="label">Заблокированных хешей</div>
                        </div>
                        <div class="metric">
                            <div class="number"><?php echo $userHashStats['tracked_user_hashes'] ?? 0; ?></div>
                            <div class="label">Отслеживаемых хешей</div>
                        </div>
                        <div class="metric">
                            <div class="number"><?php echo $userHashStats['total_hash_blocks'] ?? 0; ?></div>
                            <div class="label">Всего блокировок хешей</div>
                        </div>
                    </div>
                    
                    <div class="highlight-box">
                        <h4>💡 Что такое хеш пользователя без сессий?</h4>
                        <p>Хеш пользователя - это уникальный идентификатор, создаваемый на основе:</p>
                        <ul>
                            <li>🌐 User-Agent браузера</li>
                            <li>🗣️ Языковых настроек (Accept-Language)</li>
                            <li>⚙️ Настроек кодировки (Accept-Encoding)</li>
                            <li>📄 HTTP Accept заголовков</li>
                            <li>📱 Типа устройства (мобильное/десктоп)</li>
                            <li>🔗 Части IP-адреса (для стабильности на мобильных)</li>
                            <li>🔐 Секретного ключа</li>
                        </ul>
                        <p><strong>Преимущества v2.0:</strong> Работает без сессий PHP, более стабильная блокировка, лучшая производительность.</p>
                    </div>
                <?php else: ?>
                    <div class="highlight-box">
                        <p style="color: #856404; margin: 0;">⚠️ Статистика хешей недоступна</p>
                        <p style="margin: 10px 0 0 0;">Возможно, Redis не подключен или функция хеш-блокировки не активна.</p>
                    </div>
                <?php endif; ?>

                <?php if ($userHashInfo && $userHashInfo['stats']): ?>
                    <h4>📈 Статистика текущего хеша:</h4>
                    <table class="table">
                        <?php foreach ($userHashInfo['stats'] as $key => $value): ?>
                            <tr>
                                <td><strong><?php echo ucfirst(str_replace('_', ' ', $key)); ?>:</strong></td>
                                <td>
                                    <?php 
                                    if (strpos($key, 'time') !== false || strpos($key, 'blocked') !== false) {
                                        echo is_numeric($value) ? date('Y-m-d H:i:s', $value) : $value;
                                    } else {
                                        echo $value;
                                    }
                                    ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </table>
                <?php endif; ?>
            </div>
        </div>

        <!-- TTL настройки -->
        <div id="ttl-settings" class="tab-content">
            <div class="info-box">
                <h3>⏱️ TTL настройки системы v2.0 (No Sessions)</h3>
                <?php if ($ttlSettings): ?>
                    <div class="highlight-box">
                        <p><strong>🚀 Оптимизированные временные настройки v2.0:</strong></p>
                        <p>Настройки были существенно сокращены для улучшения производительности и снижения нагрузки на Redis.</p>
                        <p><strong>Без сессий:</strong> Исключены все ключи, связанные с PHP сессиями для лучшей производительности.</p>
                    </div>
                    
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Параметр</th>
                                <th>Время (сек)</th>
                                <th>Время (читаемо)</th>
                                <th>Описание</th>
                                <th>Статус</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($ttlSettings as $key => $value): ?>
                                <tr <?php if (strpos($key, 'user_hash') !== false) echo 'class="new-feature" style="background: rgba(156, 39, 176, 0.05);"'; ?>>
                                    <td>
                                        <code><?php echo htmlspecialchars($key); ?></code>
                                        <?php if (strpos($key, 'user_hash') !== false): ?>
                                            <span class="security-badge security-safe" style="margin-left: 5px;">v2.0</span>
                                        <?php endif; ?>
                                    </td>
                                    <td style="font-family: monospace;"><?php echo $value; ?></td>
                                    <td style="font-weight: bold; color: #007bff;">
                                        <?php 
                                        if ($value >= 3600) {
                                            echo round($value/3600, 1) . ' ч';
                                        } elseif ($value >= 60) {
                                            echo round($value/60) . ' мин';
                                        } else {
                                            echo $value . ' сек';
                                        }
                                        ?>
                                    </td>
                                    <td>
                                        <?php
                                        $descriptions = [
                                            'tracking_ip' => 'Отслеживание IP активности (сокращено)',
                                            'cookie_blocked' => 'Блокировка cookie (сокращено)',
                                            'ip_blocked' => 'Базовая блокировка IP',
                                            'ip_blocked_repeat' => 'Блокировка повторных нарушителей',
                                            'rdns_cache' => 'Кеш rDNS запросов',
                                            'logs' => 'Хранение логов',
                                            'cleanup_interval' => 'Интервал автоочистки',
                                            'user_hash_blocked' => '🆕 Блокировка хеша пользователя',
                                            'user_hash_tracking' => '🆕 Трекинг хеша пользователя',
                                            'user_hash_stats' => '🆕 Статистика хеша пользователя'
                                        ];
                                        echo $descriptions[$key] ?? 'Другие настройки';
                                        ?>
                                    </td>
                                    <td>
                                        <?php if ($value <= 1800): ?>
                                            <span class="security-badge security-safe">Быстро</span>
                                        <?php elseif ($value <= 7200): ?>
                                            <span class="security-badge security-suspicious">Средне</span>
                                        <?php else: ?>
                                            <span class="security-badge security-danger">Долго</span>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                    
                    <div style="margin-top: 20px; padding: 15px; background: rgba(40, 167, 69, 0.1); border-radius: 8px; border-left: 4px solid #28a745;">
                        <h5 style="margin-top: 0; color: #155724;">🎯 Преимущества оптимизации v2.0 без сессий:</h5>
                        <ul style="margin-bottom: 0; color: #155724;">
                            <li>⚡ Улучшенная производительность Redis</li>
                            <li>💾 Сниженное потребление памяти</li>
                            <li>🧹 Автоматическая очистка каждые 15 минут</li>
                            <li>🔐 Стабильная система хеш-блокировки</li>
                            <li>📱 Оптимизация для мобильных устройств</li>
                            <li>🚫 Исключены PHP сессии для лучшей стабильности</li>
                        </ul>
                    </div>
                <?php else: ?>
                    <div class="highlight-box">
                        <p style="color: #856404; margin: 0;">⚠️ TTL настройки недоступны</p>
                        <p style="margin: 10px 0 0 0;">Возможно, Redis не подключен или произошла ошибка.</p>
                    </div>
                <?php endif; ?>
            </div>
        </div>

        <!-- Тестирование -->
        <div id="testing" class="tab-content">
            <div class="info-box">
                <h3>🧪 Тестирование системы v2.0 (No Sessions)</h3>
                <p>Используйте эти инструменты для тестирования различных сценариев защиты:</p>
                
                <div style="margin: 25px 0;">
                    <h4>🔗 Базовые тесты:</h4>
                    <a href="redis_test.php" class="btn">🔄 Обновить страницу</a>
                    <a href="redis_test.php?page=2" class="btn secondary">📄 Страница 2</a>
                    <a href="redis_test.php?page=3" class="btn secondary">📄 Страница 3</a>
                    <a href="redis_test.php?heavy=1" class="btn secondary">⚡ Тяжелая операция</a>
                    <a href="redis_test.php?mobile_test=1" class="btn secondary">📱 Тест мобильного</a>
                    
                    <?php if (isset($_GET['debug']) && $_GET['debug'] === '1'): ?>
                        <a href="redis_test.php" class="btn">🔍 Скрыть debug</a>
                    <?php else: ?>
                        <a href="redis_test.php?debug=1" class="btn">🔍 Debug режим</a>
                    <?php endif; ?>
                </div>

                <div style="margin: 25px 0;">
                    <h4>⚙️ Административные тесты:</h4>
                    <?php if (isset($_GET['admin']) && $_GET['admin'] === '1'): ?>
                        <a href="redis_test.php" class="btn">👁️ Обычный режим</a>
                        <a href="redis_test.php?admin=1&action=user_hash_info" class="btn secondary">🔐 Инфо о хеше</a>
                        <a href="redis_test.php?admin=1&action=diagnose_hash" class="btn secondary">🔬 Диагностика хеша</a>
                    <?php else: ?>
                        <a href="redis_test.php?admin=1" class="btn danger">⚙️ Админ режим</a>
                    <?php endif; ?>
                </div>

                <div style="margin: 25px 0;">
                    <h4>🤖 JavaScript тесты в браузере:</h4>
                    <button onclick="botProtectionTest.simulateBot()" class="btn warning">🤖 Симулировать бота</button>
                    <button onclick="botProtectionTest.simulateHuman()" class="btn success">👤 Симулировать человека</button>
                    <button onclick="botProtectionTest.testUserHash()" class="btn secondary">🔐 Тест хеша пользователя</button>
                    <button onclick="botProtectionTest.performanceTest()" class="btn secondary">🚀 Тест производительности</button>
                    <button onclick="botProtectionTest.analyzeUserHash()" class="btn secondary">🔍 Анализ отпечатка</button>
                    <button onclick="botProtectionTest.clearLocalData()" class="btn danger">🧹 Очистить данные</button>
                </div>

                <h4>💻 Командная строка (curl тесты):</h4>
                <pre style="font-size: 11px;">
# Тест с подозрительным User-Agent (должен заблокироваться быстро)
for i in {1..10}; do
  curl -H "User-Agent: python-requests/2.28.1" \
       "<?php echo (isset($_SERVER['HTTPS']) ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']; ?>"
  sleep 0.5
done

# Тест с браузерным User-Agent (больше запросов для блокировки)
for i in {1..25}; do
  curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
       -c cookies.txt -b cookies.txt \
       "<?php echo (isset($_SERVER['HTTPS']) ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']; ?>"
  sleep 0.2
done

# Тест мобильного User-Agent
curl -H "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15" \
     -c mobile_cookies.txt -b mobile_cookies.txt \
     "<?php echo (isset($_SERVER['HTTPS']) ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']; ?>"

# Мониторинг Redis (в отдельном терминале)
redis-cli monitor

# Проверка ключей защиты
redis-cli keys "bot_protection:*"

# Проверка хешей пользователей (v2.0)
redis-cli keys "bot_protection:user_hash:*"

# Проверка заблокированных хешей
redis-cli keys "bot_protection:user_hash:blocked:*"

# Получить TTL блокировки
redis-cli ttl "bot_protection:user_hash:blocked:HASH_HERE"
                </pre>

                <h4>📊 Redis команды для анализа v2.0:</h4>
                <pre style="font-size: 11px;">
# Статистика ключей
redis-cli info keyspace

# Использование памяти
redis-cli info memory

# Количество ключей по типам
redis-cli eval "return #redis.call('keys', 'bot_protection:user_hash:blocked:*')" 0
redis-cli eval "return #redis.call('keys', 'bot_protection:user_hash:tracking:*')" 0
redis-cli eval "return #redis.call('keys', 'bot_protection:blocked:ip:*')" 0

# Очистка всех ключей защиты (ОСТОРОЖНО!)
redis-cli keys "bot_protection:*" | xargs redis-cli del

# Очистка только хешей пользователей
redis-cli keys "bot_protection:user_hash:*" | xargs redis-cli del
                </pre>
            </div>
        </div>

        <!-- Debug информация -->
        <div id="debug" class="tab-content">
            <div class="info-box">
                <h3>🔍 Debug информация v2.0 (No Sessions)</h3>
                
                <h4>📡 Redis Connection Test:</h4>
                <?php
                if ($protectionActive) {
                    echo "<div style='color: #28a745; padding: 10px; background: rgba(40, 167, 69, 0.1); border-radius: 8px; margin-bottom: 15px;'>";
                    echo "✅ Redis подключение активно и работает корректно";
                    echo "</div>";
                    
                    try {
                        $testKey = 'bot_protection:test:' . time();
                        $redis = new Redis();
                        $redis->connect('127.0.0.1', 6379);
                        $redis->setex($testKey, 10, json_encode([
                            'test' => 'data', 
                            'timestamp' => time(),
                            'version' => '2.0',
                            'no_sessions' => true,
                            'user_hash_support' => true
                        ]));
                        $testData = $redis->get($testKey);
                        $redis->del($testKey);
                        $redis->close();
                        
                        echo "<div style='color: #28a745; padding: 10px; background: rgba(40, 167, 69, 0.1); border-radius: 8px; margin-bottom: 15px;'>";
                        echo "✅ Redis операции записи/чтения работают корректно";
                        echo "</div>";
                        
                        echo "<h5>📄 Тестовые данные Redis:</h5>";
                        echo "<pre>" . json_encode(json_decode($testData, true), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "</pre>";
                        
                    } catch (Exception $e) {
                        echo "<div style='color: #dc3545; padding: 10px; background: rgba(220, 53, 69, 0.1); border-radius: 8px; margin-bottom: 15px;'>";
                        echo "❌ Ошибка Redis операций: " . htmlspecialchars($e->getMessage());
                        echo "</div>";
                    }
                } else {
                    echo "<div style='color: #dc3545; padding: 10px; background: rgba(220, 53, 69, 0.1); border-radius: 8px; margin-bottom: 15px;'>";
                    echo "❌ Redis недоступен - проверьте подключение";
                    echo "</div>";
                }
                ?>
                
                <h4>🔐 User Hash Analysis v2.0:</h4>
                <?php if ($userHashInfo): ?>
                    <div class="highlight-box">
                        <strong>🎯 Полная информация о хеше пользователя:</strong>
                    </div>
                    <pre><?php echo json_encode($userHashInfo, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE); ?></pre>
                <?php else: ?>
                    <div style="color: #856404; padding: 10px; background: rgba(255, 193, 7, 0.1); border-radius: 8px;">
                        ⚠️ Информация о хеше пользователя недоступна (Redis не подключен или ошибка)
                    </div>
                <?php endif; ?>
                
                <h4>🔬 User Hash Diagnosis v2.0:</h4>
                <?php if ($userHashDiagnosis): ?>
                    <div class="highlight-box">
                        <strong>🧬 Диагностика компонентов хеша:</strong>
                    </div>
                    <pre><?php echo json_encode($userHashDiagnosis, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE); ?></pre>
                <?php else: ?>
                    <div style="color: #856404; padding: 10px; background: rgba(255, 193, 7, 0.1); border-radius: 8px;">
                        ⚠️ Диагностика хеша недоступна
                    </div>
                <?php endif; ?>
                
                <h4>📊 Global User Hash Stats:</h4>
                <?php if ($userHashStats): ?>
                    <pre><?php echo json_encode($userHashStats, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE); ?></pre>
                <?php else: ?>
                    <div style="color: #856404; padding: 10px; background: rgba(255, 193, 7, 0.1); border-radius: 8px;">
                        ⚠️ Глобальная статистика хешей недоступна
                    </div>
                <?php endif; ?>
                
                <h4>🌐 $_SERVER переменные (HTTP):</h4>
                <pre><?php 
                $serverVars = [];
                foreach ($_SERVER as $key => $value) {
                    if (strpos($key, 'HTTP_') === 0 || in_array($key, ['REMOTE_ADDR', 'REQUEST_URI', 'REQUEST_METHOD', 'QUERY_STRING', 'REQUEST_TIME', 'SERVER_SOFTWARE'])) {
                        $serverVars[$key] = $value;
                    }
                }
                echo json_encode($serverVars, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE); 
                ?></pre>
                
                <h4>🍪 Все cookies:</h4>
                <pre><?php echo json_encode($_COOKIE, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE); ?></pre>
                
                <h4>🛡️ Browser Security Analysis v2.0 (No Sessions):</h4>
                <pre><?php 
                $securityAnalysis = [
                    'user_agent_suspicious' => $isSuspiciousUA,
                    'device_type' => $isMobile ? 'mobile' : 'desktop',
                    'browser_info' => $browserInfo,
                    'sessions_enabled' => false,
                    'visitor_cookie_set' => $hasVisitorCookie,
                    'protection_level' => $protectionLevel,
                    'timestamp' => date('Y-m-d H:i:s'),
                    'ip_location' => $currentIP,
                    'version' => '2.0-no-sessions'
                ];
                echo json_encode($securityAnalysis, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE); 
                ?></pre>
                
                <?php if ($protectionActive && $redisStats): ?>
                <h4>📈 Полная статистика Redis v2.0:</h4>
                <pre><?php echo json_encode($redisStats, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE); ?></pre>
                <?php endif; ?>
                
                <h4>⚙️ PHP Environment:</h4>
                <pre><?php 
                $phpInfo = [
                    'php_version' => PHP_VERSION,
                    'redis_extension' => extension_loaded('redis'),
                    'sessions_disabled' => true,
                    'memory_limit' => ini_get('memory_limit'),
                    'max_execution_time' => ini_get('max_execution_time'),
                    'date_timezone' => date_default_timezone_get(),
                    'server_time' => date('Y-m-d H:i:s'),
                    'upload_max_filesize' => ini_get('upload_max_filesize'),
                    'post_max_size' => ini_get('post_max_size')
                ];
                echo json_encode($phpInfo, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE); 
                ?></pre>
            </div>
        </div>

        <!-- Административные действия -->
        <?php if (isset($_GET['admin']) && $_GET['admin'] === '1'): ?>
        <div class="info-box" style="border-left-color: #dc3545;">
            <h3>⚙️ Административные действия v2.0</h3>
            <div style="margin: 20px 0;">
                <?php
                if (isset($_GET['action']) && $protectionActive) {
                    switch ($_GET['action']) {
                        case 'unblock_ip':
                            $result = $protection->unblockIP($currentIP);
                            echo "<div class='highlight-box'>";
                            echo "<strong>🔓 Результат разблокировки IP:</strong><br>";
                            echo "IP разблокирован: " . ($result['ip_unblocked'] ? '✅ Да' : '❌ Нет') . "<br>";
                            echo "Трекинг очищен: " . ($result['tracking_cleared'] ? '✅ Да' : '❌ Нет');
                            echo "</div>";
                            break;
                        case 'unblock_user_hash':
                            $result = $protection->unblockUserHash();
                            echo "<div class='highlight-box'>";
                            echo "<strong>🔐 Результат разблокировки хеша пользователя:</strong><br>";
                            echo "Хеш разблокирован: " . ($result['unblocked'] ? '✅ Да' : '❌ Нет') . "<br>";
                            echo "Трекинг очищен: " . ($result['tracking_cleared'] ? '✅ Да' : '❌ Нет');
                            echo "</div>";
                            break;
                        case 'user_hash_info':
                            $hashInfo = $protection->getUserHashInfo();
                            echo "<div class='highlight-box'>";
                            echo "<strong>🔐 Подробная информация о хеше:</strong><br>";
                            echo "<pre style='margin-top: 10px;'>" . json_encode($hashInfo, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "</pre>";
                            echo "</div>";
                            break;
                        case 'diagnose_hash':
                            $diagnosis = $protection->diagnoseUserHash();
                            echo "<div class='highlight-box'>";
                            echo "<strong>🔬 Диагностика хеша пользователя:</strong><br>";
                            echo "<pre style='margin-top: 10px;'>" . json_encode($diagnosis, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "</pre>";
                            echo "</div>";
                            break;
                        case 'cleanup':
                            $cleaned = $protection->cleanup();
                            echo "<div class='highlight-box'>";
                            echo "<strong>🧹 Очистка выполнена:</strong><br>";
                            echo "Удалено элементов: " . ($cleaned !== false ? $cleaned : 'Ошибка');
                            echo "</div>";
                            break;
                        case 'deep_cleanup':
                            $cleaned = $protection->deepCleanup();
                            echo "<div class='highlight-box'>";
                            echo "<strong>🗑️ Глубокая очистка выполнена:</strong><br>";
                            echo "Удалено элементов: " . ($cleaned !== false ? $cleaned : 'Ошибка');
                            echo "</div>";
                            break;
                    }
                }
                ?>
                
                <h4>🔓 Разблокировка:</h4>
                <a href="redis_test.php?admin=1&action=unblock_ip" class="btn success">🌐 Разблокировать IP</a>
                <a href="redis_test.php?admin=1&action=unblock_user_hash" class="btn success">🔐 Разблокировать хеш</a>
                
                <h4>📊 Анализ:</h4>
                <a href="redis_test.php?admin=1&action=user_hash_info" class="btn secondary">🔐 Инфо о хеше</a>
                <a href="redis_test.php?admin=1&action=diagnose_hash" class="btn secondary">🔬 Диагностика хеша</a>
                
                <h4>🧹 Очистка:</h4>
                <a href="redis_test.php?admin=1&action=cleanup" class="btn warning">🧹 Обычная очистка</a>
                <a href="redis_test.php?admin=1&action=deep_cleanup" class="btn danger">🗑️ Глубокая очистка</a>
                
                <h4>🔧 Навигация:</h4>
                <a href="redis_test.php" class="btn">👁️ Обычный режим</a>
            </div>
        </div>
        <?php endif; ?>

        <!-- Обработка специальных запросов -->
        <?php if (isset($_GET['heavy'])): ?>
        <div class="status-card">
            <h3>⚡ Тяжелая операция выполнена</h3>
            <?php
            $start = microtime(true);
            // Имитация тяжелой операции
            for ($i = 0; $i < 100000; $i++) {
                $temp = md5($i);
            }
            $end = microtime(true);
            $duration = round(($end - $start) * 1000, 2);
            
            echo "<p>✅ Операция выполнена за <strong>{$duration} мс</strong></p>";
            echo "<p>🕒 Время выполнения: " . date('H:i:s') . "</p>";
            echo "<p>🔢 Выполнено операций: 100,000 MD5 хешей</p>";
            ?>
        </div>
        <?php endif; ?>

        <?php if (isset($_GET['mobile_test'])): ?>
        <div class="status-card">
            <h3>📱 Тест мобильного устройства</h3>
            <p>Текущее устройство определено как: 
                <span class="device-indicator <?php echo $isMobile ? 'device-mobile' : 'device-desktop'; ?>">
                    <?php echo $isMobile ? '📱 Мобильное устройство' : '🖥️ Десктопное устройство'; ?>
                </span>
            </p>
            <p>User-Agent: <code><?php echo htmlspecialchars(substr($currentUA, 0, 100)); ?>...</code></p>
            <p>Браузер: <strong><?php echo $browserInfo['name'] . ' ' . $browserInfo['version']; ?></strong></p>
            <p>Платформа: <strong><?php echo $browserInfo['platform']; ?></strong></p>
        </div>
        <?php endif; ?>

        <hr style="margin: 40px 0; border: none; height: 1px; background: linear-gradient(90deg, transparent, #dee2e6, transparent);">
        
        <div style="text-align: center; color: #6c757d; font-size: 0.9em;">
            <div style="margin-bottom: 10px;">
                🛡️ <strong>Redis MurKir Security System v2.0</strong> - No Sessions Protection
            </div>
            <div style="display: flex; flex-wrap: wrap; justify-content: center; gap: 15px; font-size: 0.85em;">
                <span>📅 Generated: <?php echo date('Y-m-d H:i:s'); ?></span>
                <span>🐘 PHP: <?php echo PHP_VERSION; ?></span>
                <span>📡 Redis: <?php echo $protectionActive ? '✅ Active' : '❌ Inactive'; ?></span>
                <span>📱 Device: <?php echo $isMobile ? 'Mobile' : 'Desktop'; ?></span>
                <span>🛡️ Protection: <?php echo ucfirst($protectionLevel); ?></span>
                <span>🚫 Sessions: Disabled</span>
                <?php if ($userHashInfo): ?>
                    <span>🔐 Hash: <?php echo $userHashInfo['blocked'] ? '🚫 Blocked' : '✅ Active'; ?></span>
                <?php endif; ?>
                <span>🍪 Cookie: <?php echo $hasVisitorCookie ? '✅ Set' : '❌ None'; ?></span>
            </div>
        </div>
    </div>

    <script>
        // Функция переключения табов
        function showTab(tabId) {
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            
            document.querySelectorAll('.tab').forEach(btn => {
                btn.classList.remove('active');
            });
            
            document.getElementById(tabId).classList.add('active');
            event.target.classList.add('active');
        }

        // Функция копирования в буфер обмена
        function copyToClipboard(element) {
            const text = element.textContent;
            navigator.clipboard.writeText(text).then(() => {
                const original = element.style.background;
                element.style.background = '#28a745';
                element.style.color = 'white';
                element.style.transform = 'scale(1.05)';
                
                setTimeout(() => {
                    element.style.background = original;
                    element.style.color = '';
                    element.style.transform = '';
                }, 800);
                
                botProtectionTest.showNotification('📋 Скопировано: ' + text.substring(0, 20) + '...', 'success');
            }).catch(err => {
                console.log('Copy failed:', err);
                botProtectionTest.showNotification('❌ Ошибка копирования', 'error');
            });
        }

        // Активность пользователя для демонстрации человеческого поведения
        let userActivity = {
            mouseMovements: 0,
            clicks: 0,
            scrolls: 0,
            keyPresses: 0,
            startTime: Date.now(),
            lastActivity: Date.now(),
            uniquePages: new Set(),
            tabSwitches: 0
        };

        // Отслеживание активности
        document.addEventListener('mousemove', () => {
            userActivity.mouseMovements++;
            userActivity.lastActivity = Date.now();
        });

        document.addEventListener('click', () => {
            userActivity.clicks++;
            userActivity.lastActivity = Date.now();
        });

        document.addEventListener('scroll', () => {
            userActivity.scrolls++;
            userActivity.lastActivity = Date.now();
        });

        document.addEventListener('keydown', () => {
            userActivity.keyPresses++;
            userActivity.lastActivity = Date.now();
        });

        // Отслеживание смены табов
        document.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', () => {
                userActivity.tabSwitches++;
            });
        });

        // Кастомные функции для тестирования v2.0
        window.botProtectionTest = {
            // Симуляция bot-подобного поведения
            simulateBot: function() {
                console.log('🤖 Simulating bot behavior v2.0 (no sessions)...');
                this.showNotification('🤖 Запуск симуляции бота...', 'warning');
                
                // Быстрые запросы без пауз
                for(let i = 0; i < 15; i++) {
                    setTimeout(() => {
                        fetch(window.location.href + '?bot_test=' + i + '&timestamp=' + Date.now() + '&rapid_fire=1')
                            .then(response => {
                                console.log(`Bot request ${i}: ${response.status}`);
                                if (response.status === 429) {
                                    this.showNotification('🚫 Бот заблокирован!', 'error');
                                }
                            })
                            .catch(err => console.log(`Bot request ${i} failed:`, err));
                    }, i * 50); // Очень быстрые запросы
                }
            },
            
            // Симуляция человеческого поведения
            simulateHuman: function() {
                console.log('👤 Simulating human behavior v2.0 (no sessions)...');
                this.showNotification('👤 Симуляция человеческого поведения...', 'info');
                
                const pages = [
                    '?page=1&human=1', 
                    '?page=2&human=1', 
                    '?page=3&human=1', 
                    '?about=1&human=1', 
                    '?contact=1&human=1'
                ];
                
                pages.forEach((page, index) => {
                    setTimeout(() => {
                        fetch(window.location.origin + window.location.pathname + page + '&human_test=' + index)
                            .then(response => console.log(`Human request ${index}: ${response.status}`))
                            .catch(err => console.log(`Human request ${index} failed:`, err));
                    }, index * 2000 + Math.random() * 1000); // Случайные интервалы
                });
            },
            
            // Тест хеша пользователя v2.0
            testUserHash: function() {
                console.log('🔐 Testing user hash v2.0 (no sessions)...');
                this.showNotification('🔐 Тестирование хеша пользователя...', 'info');
                
                fetch(window.location.href + '?hash_test=1&timestamp=' + Date.now())
                    .then(response => response.text())
                    .then(data => {
                        console.log('User hash test completed');
                        
                        // Анализируем ответ на наличие блокировки
                        if (data.includes('Rate limit exceeded') || data.includes('429')) {
                            this.showNotification('🚫 Хеш заблокирован системой!', 'error');
                        } else {
                            this.showNotification('✅ Тест хеша пройден успешно', 'success');
                        }
                    })
                    .catch(err => {
                        console.log('Hash test failed:', err);
                        this.showNotification('❌ Ошибка тестирования хеша', 'error');
                    });
            },
            
            // Тест производительности v2.0
            performanceTest: function() {
                console.log('🚀 Starting performance test v2.0 (no sessions)...');
                this.showNotification('🚀 Запуск теста производительности...', 'info');
                
                const startTime = performance.now();
                const requests = [];
                
                // Серия запросов для тестирования производительности
                for (let i = 0; i < 8; i++) {
                    requests.push(
                        fetch(window.location.href + '?perf_test=' + i + '&t=' + Date.now())
                            .then(response => ({
                                request: i,
                                status: response.status,
                                time: performance.now() - startTime,
                                blocked: response.status === 429
                            }))
                    );
                }
                
                Promise.all(requests).then(results => {
                    const avgTime = results.reduce((sum, r) => sum + r.time, 0) / results.length;
                    const blockedCount = results.filter(r => r.blocked).length;
                    
                    console.log('Performance test results:', results);
                    
                    if (blockedCount > 0) {
                        this.showNotification(`⚠️ ${blockedCount} запросов заблокировано из ${results.length}`, 'warning');
                    } else {
                        this.showNotification(`🚀 Тест завершен: ${avgTime.toFixed(2)}ms среднее время`, 'success');
                    }
                });
            },
            
            // Анализ отпечатка браузера v2.0
            analyzeUserHash: function() {
                const userAgent = navigator.userAgent;
                const language = navigator.language;
                const platform = navigator.platform;
                const cookiesEnabled = navigator.cookieEnabled;
                
                const fingerprint = {
                    userAgent: userAgent,
                    language: language,
                    platform: platform,
                    cookiesEnabled: cookiesEnabled,
                    screenResolution: screen.width + 'x' + screen.height,
                    colorDepth: screen.colorDepth,
                    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                    timestamp: Date.now(),
                    // Дополнительные параметры v2.0
                    hardwareConcurrency: navigator.hardwareConcurrency,
                    deviceMemory: navigator.deviceMemory || 'unknown',
                    connection: navigator.connection ? {
                        effectiveType: navigator.connection.effectiveType,
                        downlink: navigator.connection.downlink
                    } : 'unknown',
                    webGL: this.getWebGLInfo(),
                    canvas: this.getCanvasFingerprint(),
                    sessionsDisabled: true
                };
                
                console.log('🔍 Advanced browser fingerprint analysis v2.0 (no sessions):', fingerprint);
                this.showNotification('🔍 Расширенный анализ отпечатка завершен (см. консоль)', 'info');
                
                return fingerprint;
            },
            
            // Получение информации WebGL
            getWebGLInfo: function() {
                try {
                    const canvas = document.createElement('canvas');
                    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
                    if (!gl) return 'not supported';
                    
                    return {
                        vendor: gl.getParameter(gl.VENDOR),
                        renderer: gl.getParameter(gl.RENDERER),
                        version: gl.getParameter(gl.VERSION)
                    };
                } catch (e) {
                    return 'error';
                }
            },
            
            // Получение отпечатка Canvas
            getCanvasFingerprint: function() {
                try {
                    const canvas = document.createElement('canvas');
                    const ctx = canvas.getContext('2d');
                    ctx.textBaseline = 'top';
                    ctx.font = '14px Arial';
                    ctx.fillText('BotProtection v2.0 NoSessions 🛡️', 2, 2);
                    return canvas.toDataURL().substring(0, 50) + '...';
                } catch (e) {
                    return 'error';
                }
            },
            
            // Получение данных Redis v2.0
            getRedisStats: function() {
                return <?php echo json_encode($redisStats ?: []); ?>;
            },
            
            // Информация о текущем IP
            getCurrentIPInfo: function() {
                return <?php echo json_encode($ipInfo ?: []); ?>;
            },
            
            // Информация о хеше пользователя v2.0
            getUserHashInfo: function() {
                return <?php echo json_encode($userHashInfo ?: []); ?>;
            },
            
            // Диагностика хеша v2.0
            getUserHashDiagnosis: function() {
                return <?php echo json_encode($userHashDiagnosis ?: []); ?>;
            },
            
            // Очистка локальных данных
            clearLocalData: function() {
                localStorage.clear();
                sessionStorage.clear();
                
                // Очистка cookies (только те, которые можем)
                document.cookie.split(";").forEach(function(c) { 
                    document.cookie = c.replace(/^ +/, "").replace(/=.*/, "=;expires=" + new Date().toUTCString() + ";path=/"); 
                });
                
                console.log('🧹 All local data cleared (no sessions mode)');
                this.showNotification('🧹 Все локальные данные очищены', 'success');
                
                setTimeout(() => {
                    this.showNotification('🔄 Перезагрузка через 3 секунды...', 'info');
                    setTimeout(() => window.location.reload(), 3000);
                }, 1000);
            },
            
            // Показ уведомлений с улучшенным дизайном
            showNotification: function(message, type = 'info') {
                const notification = document.createElement('div');
                const colors = {
                    error: { bg: '#dc3545', shadow: 'rgba(220, 53, 69, 0.3)' },
                    success: { bg: '#28a745', shadow: 'rgba(40, 167, 69, 0.3)' },
                    warning: { bg: '#ffc107', shadow: 'rgba(255, 193, 7, 0.3)', text: '#212529' },
                    info: { bg: '#007bff', shadow: 'rgba(0, 123, 255, 0.3)' }
                };
                
                const color = colors[type] || colors.info;
                
                notification.style.cssText = `
                    position: fixed;
                    top: 20px;
                    right: 20px;
                    background: linear-gradient(135deg, ${color.bg}, ${color.bg}dd);
                    color: ${color.text || 'white'};
                    padding: 15px 25px;
                    border-radius: 12px;
                    font-weight: 500;
                    z-index: 1000;
                    box-shadow: 0 8px 32px ${color.shadow};
                    max-width: 350px;
                    opacity: 0;
                    transform: translateX(100%) scale(0.8);
                    transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
                    border: 1px solid rgba(255,255,255,0.2);
                    backdrop-filter: blur(10px);
                `;
                notification.innerHTML = message;
                document.body.appendChild(notification);

                setTimeout(() => {
                    notification.style.opacity = '1';
                    notification.style.transform = 'translateX(0) scale(1)';
                }, 100);

                const hideNotification = () => {
                    notification.style.opacity = '0';
                    notification.style.transform = 'translateX(100%) scale(0.8)';
                    setTimeout(() => notification.remove(), 400);
                };

                // Клик для закрытия
                notification.addEventListener('click', hideNotification);
                
                // Автоскрытие
                setTimeout(hideNotification, 5000);
            },
            
            // Стресс-тест системы v2.0
            stressTest: function() {
                console.log('💥 Starting stress test v2.0 (no sessions)...');
                this.showNotification('💥 Запуск стресс-теста системы...', 'warning');
                
                let requestCount = 0;
                const maxRequests = 30;
                const interval = 100; // мс между запросами
                
                const stressInterval = setInterval(() => {
                    if (requestCount >= maxRequests) {
                        clearInterval(stressInterval);
                        this.showNotification('💥 Стресс-тест завершен', 'info');
                        return;
                    }
                    
                    fetch(window.location.href + '?stress_test=' + requestCount + '&timestamp=' + Date.now())
                        .then(response => {
                            if (response.status === 429) {
                                clearInterval(stressInterval);
                                this.showNotification(`🚫 Система заблокировала после ${requestCount} запросов`, 'error');
                            }
                        })
                        .catch(err => console.log('Stress test request failed:', err));
                    
                    requestCount++;
                }, interval);
            }
        };

        // Мониторинг активности пользователя v2.0
        setInterval(() => {
            const timeSpent = Math.floor((Date.now() - userActivity.startTime) / 1000);
            const timeSinceLastActivity = Math.floor((Date.now() - userActivity.lastActivity) / 1000);
            
            const activityData = {
                ...userActivity,
                timeSpent: timeSpent + 's',
                timeSinceLastActivity: timeSinceLastActivity + 's',
                activityScore: userActivity.mouseMovements + userActivity.clicks + userActivity.scrolls + userActivity.keyPresses,
                isActive: timeSinceLastActivity < 30,
                humanScore: Math.min(100, (userActivity.mouseMovements * 0.1 + userActivity.clicks * 2 + userActivity.scrolls * 0.5 + userActivity.keyPresses * 1.5 + userActivity.tabSwitches * 5)),
                sessionsDisabled: true
            };
            
            console.log('👤 User Activity Analysis v2.0 (no sessions):', activityData);
        }, 20000); // Каждые 20 секунд

        // Обновление прогресс-баров с анимацией
        function updateProgressBars() {
            document.querySelectorAll('.progress-fill').forEach(bar => {
                const width = parseInt(bar.style.width);
                if (width > 0) {
                    bar.style.width = '0%';
                    setTimeout(() => {
                        bar.style.width = width + '%';
                    }, 200);
                }
            });
        }

        // Анимация метрик с эффектом подсчета
        function animateMetrics() {
            document.querySelectorAll('.metric .number').forEach(element => {
                const finalValue = parseInt(element.textContent) || 0;
                if (finalValue === 0) return;
                
                let currentValue = 0;
                const increment = finalValue / 30;
                const isText = isNaN(finalValue);
                
                if (!isText) {
                    element.textContent = '0';
                    
                    const timer = setInterval(() => {
                        currentValue += increment;
                        if (currentValue >= finalValue) {
                            currentValue = finalValue;
                            clearInterval(timer);
                        }
                        element.textContent = Math.floor(currentValue);
                    }, 50);
                }
            });
        }

        // Клавиатурные сочетания v2.0
        document.addEventListener('keydown', (e) => {
            if (e.ctrlKey || e.metaKey) {
                switch(e.key) {
                    case '1': e.preventDefault(); showTab('request-info'); break;
                    case '2': e.preventDefault(); showTab('redis-keys'); break;
                    case '3': e.preventDefault(); showTab('user-hash-stats'); break;
                    case '4': e.preventDefault(); showTab('ttl-settings'); break;
                    case '5': e.preventDefault(); showTab('testing'); break;
                    case '6': e.preventDefault(); showTab('debug'); break;
                    case 'b': e.preventDefault(); botProtectionTest.simulateBot(); break;
                    case 'h': e.preventDefault(); botProtectionTest.simulateHuman(); break;
                    case 'p': e.preventDefault(); botProtectionTest.performanceTest(); break;
                    case 'u': e.preventDefault(); botProtectionTest.testUserHash(); break;
                    case 'k': e.preventDefault(); botProtectionTest.clearLocalData(); break;
                    case 's': e.preventDefault(); botProtectionTest.stressTest(); break;
                }
            }
        });

        // Детектор бездействия пользователя
        let idleTimer;
        const maxIdleTime = 300; // 5 минут

        function resetIdleTimer() {
            clearTimeout(idleTimer);
            idleTimer = setTimeout(() => {
                console.log('👤 User is idle for 5 minutes');
                botProtectionTest.showNotification('😴 Вы неактивны уже 5 минут', 'info');
            }, maxIdleTime * 1000);
        }

        // Сбрасываем таймер при любой активности
        ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart', 'click'].forEach(event => {
            document.addEventListener(event, resetIdleTimer, true);
        });

        // Инициализация при загрузке страницы
        document.addEventListener('DOMContentLoaded', () => {
            resetIdleTimer();
            
            setTimeout(() => {
                animateMetrics();
                updateProgressBars();
            }, 500);
            
            // Показываем приветственное сообщение
            setTimeout(() => {
                <?php if (!$protectionActive): ?>
                botProtectionTest.showNotification('⚠️ Redis недоступен! Система защиты не активна.', 'error');
                <?php elseif ($userHashInfo && $userHashInfo['blocked']): ?>
                botProtectionTest.showNotification('🚫 Ваш хеш пользователя заблокирован системой защиты v2.0!', 'error');
                <?php elseif ($ipInfo && $ipInfo['blocked']): ?>
                botProtectionTest.showNotification('🚫 Ваш IP заблокирован системой защиты!', 'error');
                <?php elseif ($isMobile): ?>
                botProtectionTest.showNotification('📱 Мобильное устройство! Система v2.0 оптимизирована для мобильных.', 'info');
                <?php elseif ($protectionLevel === 'maximum'): ?>
                botProtectionTest.showNotification('🛡️ Bot Protection v2.0 (без сессий) с максимальной защитой активна!', 'success');
                <?php else: ?>
                botProtectionTest.showNotification('🛡️ Bot Protection v2.0 (без сессий) активна!', 'info');
                <?php endif; ?>
            }, 1200);
            
            // Показываем горячие клавиши
            setTimeout(() => {
                botProtectionTest.showNotification('💡 Горячие клавиши: Ctrl+1-6 (табы), Ctrl+B (бот), Ctrl+H (человек), Ctrl+P (производительность)', 'info');
            }, 4000);
        });

        // Мониторинг производительности страницы
        window.addEventListener('load', () => {
            const loadTime = performance.timing.loadEventEnd - performance.timing.navigationStart;
            console.log(`📊 Page load time: ${loadTime}ms`);
            
            if (loadTime > 3000) {
                botProtectionTest.showNotification('⚠️ Страница загружалась медленно (' + Math.round(loadTime/1000) + 's)', 'warning');
            }

            // Логируем информацию о системе v2.0
            console.log(`
█▀▀▄ █▀▀█ ▀▀█▀▀   █▀▀█ █▀▀█ █▀▀█ ▀▀█▀▀ █▀▀ █▀▀ ▀▀█▀▀ ─▀─ █▀▀█ █▀▀▄   ▄█ █ ▄█    █▄ █ █▀▀█   █▀▀ █▀▀ █▀▀ █▀▀ ─▀─ █▀▀█ █▀▀▄ █▀▀
█▀▀▄ █  █   █     █  █ █▄▄▀ █  █   █   █▄▄ █     █    ▀█▀ █  █ █  █    █ █▄▀ ▄█    █ ▀█ █  █   █▄▄ █▄▄ █▄▄ █▄▄ ▀█▀ █  █ █  █ █▄▄
▀▀▀  ▀▀▀▀   ▀     █▀▀▀ ▀ ▀▀ ▀▀▀▀   ▀   ▀▀▀ ▀▀▀   ▀   ▀▀▀ ▀▀▀▀ ▀  ▀   ▀▀▀ ▀▀▀      ▀  ▀ ▀▀▀▀   ▀▀▀ ▀▀▀ ▀▀▀ ▀▀▀ ▀▀▀ ▀▀▀▀ ▀  ▀ ▀▀▀

🚀 Version 2.0 - No Sessions Protection System
📊 Advanced Test Page Loaded Successfully!

✨ New Features v2.0:
✅ User Hash Blocking & Tracking     🔐 Stable Cross-Session Protection
✅ Mobile Device Optimization        📱 Enhanced Mobile Support  
✅ Advanced TTL Settings            ⏱️ Optimized Performance
✅ Improved Analytics               📊 Detailed Monitoring
✅ Enhanced Browser Fingerprinting  🔍 Advanced Detection
✅ Session-Free Architecture        🚫 No PHP Sessions Dependency

🖥️ Current Session:
Device: <?php echo $isMobile ? 'Mobile' : 'Desktop'; ?>
Protection: <?php echo $protectionActive ? 'Active' : 'Inactive'; ?>
Level: <?php echo ucfirst($protectionLevel); ?>
User Hash: <?php echo $userHashInfo ? (strlen($userHashInfo['user_hash']) > 0 ? 'Generated' : 'N/A') : 'N/A'; ?>
Sessions: Disabled
Cookie Set: <?php echo $hasVisitorCookie ? 'Yes' : 'No'; ?>
            `);
        });

        // Добавляем CSS анимации
        const style = document.createElement('style');
        style.textContent = `
            @keyframes pulse {
                0% { transform: scale(1); }
                50% { transform: scale(1.1); }
                100% { transform: scale(1); }
            }
            
            @keyframes bounce {
                0%, 20%, 53%, 80%, 100% { transform: translate3d(0,0,0); }
                40%, 43% { transform: translate3d(0,-30px,0); }
                70% { transform: translate3d(0,-15px,0); }
                90% { transform: translate3d(0,-4px,0); }
            }
            
            .metric:hover .number {
                animation: bounce 1s ease-in-out;
                color: #0056b3;
            }
            
            .table tr:hover {
                background: linear-gradient(135deg, #f1f3f4, #e8f4f8) !important;
                transform: scale(1.01);
                box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            }
            
            .btn:active {
                transform: scale(0.95) translateY(-2px);
            }
            
            .hash-display:hover, .redis-key:hover {
                background: linear-gradient(135deg, #007bff, #0056b3) !important;
                color: white !important;
                transform: scale(1.02);
                box-shadow: 0 4px 15px rgba(0, 123, 255, 0.3);
            }
            
            .new-feature {
                position: relative;
                overflow: visible;
            }
            
            .new-feature::after {
                animation: pulse 2s infinite;
            }
            
            .status-card {
                transition: all 0.3s ease;
            }
            
            .status-card:hover {
                transform: translateY(-3px);
                box-shadow: 0 8px 25px rgba(0,0,0,0.15);
            }
        `;
        document.head.appendChild(style);

        // Функции для клика по элементам
        document.querySelectorAll('.redis-key, .hash-display').forEach(element => {
            element.style.cursor = 'pointer';
            element.title = 'Click to copy';
        });

        console.log('🛡️ Bot Protection Test Page v2.0 (No Sessions) fully loaded and initialized');
        console.log('🔧 Available functions:', Object.keys(window.botProtectionTest));
        console.log('📊 System status:', {
            redis: <?php echo $protectionActive ? 'true' : 'false'; ?>,
            userHash: <?php echo $userHashInfo ? 'true' : 'false'; ?>,
            mobile: <?php echo $isMobile ? 'true' : 'false'; ?>,
            protectionLevel: '<?php echo $protectionLevel; ?>',
            sessionsDisabled: true,
            visitorCookie: <?php echo $hasVisitorCookie ? 'true' : 'false'; ?>
        });
    </script>
</body>
</html>
