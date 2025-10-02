<?php
// /home/kinoprostor/kinoprostor15.2/dos/bot_protection/redis_test.php

// Підключаємо оновлену Redis-версію захисту
require_once 'inline_check.php';

// Ініціалізуємо захист (новий клас без сесій)
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

// Допоміжні функції (оновлені для нової версії)
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

// НОВІ ФУНКЦІЇ для Rate Limiting
function getRateLimitStats($protection, $ip) {
    if (!$protection) return null;
    
    try {
        return $protection->getRateLimitStats($ip);
    } catch (Exception $e) {
        return null;
    }
}

function getTopRateLimitViolators($protection, $limit = 10) {
    if (!$protection) return null;
    
    try {
        return $protection->getTopRateLimitViolators($limit);
    } catch (Exception $e) {
        return null;
    }
}

function getRateLimitSettings($protection) {
    if (!$protection) return null;
    
    try {
        return $protection->getRateLimitSettings();
    } catch (Exception $e) {
        return null;
    }
}

function getSlowBotSettings($protection) {
    if (!$protection) return null;
    
    try {
        return $protection->getSlowBotSettings();
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
    
    // Визначаємо браузер
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
    
    // Визначаємо платформу
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

// Функції для роботи з рівнем довіри на основі Redis даних
function isVerifiedUser($userHashInfo) {
    return $userHashInfo && !$userHashInfo['blocked'] && isset($userHashInfo['tracking_data']);
}

function getUserVisitInfo($userHashInfo) {
    if (!$userHashInfo || !isset($userHashInfo['tracking_data'])) {
        return null;
    }
    
    $trackingData = $userHashInfo['tracking_data'];
    
    return [
        'first_visit' => $trackingData['first_seen'] ?? time(),
        'pages_visited' => count(array_unique($trackingData['pages'] ?? [])),
        'total_requests' => $trackingData['requests'] ?? 0,
        'last_activity' => $trackingData['last_activity'] ?? time(),
        'unique_ips' => count(array_unique($trackingData['ips'] ?? [])),
        'user_agents' => count(array_unique($trackingData['user_agents'] ?? [])),
        'time_spent' => time() - ($trackingData['first_seen'] ?? time())
    ];
}

function getVisitorTrustScore($userHashInfo, $ipInfo = null) {
    $visitInfo = getUserVisitInfo($userHashInfo);
    if (!$visitInfo) return 0;
    
    $score = 0;
    $timeOnSite = $visitInfo['time_spent'];
    $pagesVisited = $visitInfo['pages_visited'];
    $totalRequests = $visitInfo['total_requests'];
    
    // Базовий бал за час
    if ($timeOnSite > 300) $score += 20;       // 5 хвилин
    if ($timeOnSite > 900) $score += 25;       // 15 хвилин
    if ($timeOnSite > 1800) $score += 30;      // 30 хвилин
    if ($timeOnSite > 3600) $score += 25;      // 1 година - максимальний бонус за час
    
    // Бал за різноманітність сторінок
    if ($pagesVisited > 2) $score += 15;
    if ($pagesVisited > 5) $score += 20;
    if ($pagesVisited > 10) $score += 25;
    if ($pagesVisited > 20) $score += 15;
    
    // Бал за помірну активність
    if ($totalRequests > 5 && $totalRequests < 50) $score += 10;
    if ($totalRequests >= 50 && $totalRequests < 200) $score += 15;
    if ($totalRequests >= 200 && $totalRequests < 500) $score += 10;
    
    // Штраф за підозрілу поведінку
    if ($visitInfo['unique_ips'] > 3) $score -= 20;
    if ($visitInfo['user_agents'] > 2) $score -= 15;
    
    // Бонус за стабільність
    if ($visitInfo['unique_ips'] === 1 && $visitInfo['user_agents'] === 1) $score += 20;
    
    // Перевіряємо IP блокування
    if ($ipInfo && $ipInfo['blocked']) $score -= 50;
    
    // Нормалізуємо в діапазон 0-100
    $score = max(0, min(100, $score));
    
    return $score;
}

// Отримуємо дані
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

// НОВІ ДАНІ для Rate Limiting
$rateLimitStats = $protectionActive ? getRateLimitStats($protection, $currentIP) : null;
$topViolators = $protectionActive ? getTopRateLimitViolators($protection, 10) : null;
$rateLimitSettings = $protectionActive ? getRateLimitSettings($protection) : null;
$slowBotSettings = $protectionActive ? getSlowBotSettings($protection) : null;

// Обчислюємо рівень довіри та статус користувача на основі Redis даних
$isVerified = isVerifiedUser($userHashInfo);
$visitInfo = getUserVisitInfo($userHashInfo);
$trustScore = getVisitorTrustScore($userHashInfo, $ipInfo);

// Визначаємо статус захисту
$protectionLevel = 'basic';
if ($protectionActive && $userHashInfo) {
    $protectionLevel = 'maximum';
} elseif ($protectionActive) {
    $protectionLevel = 'enhanced';
}

// Визначаємо, чи є visitor cookie
$hasVisitorCookie = isset($_COOKIE['visitor_verified']);
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ Redis MurKir Security Test v2.1 - Advanced Rate Limiting</title>
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
        .rate-limit-badge {
            position: absolute;
            top: 15px;
            left: 15px;
            background: rgba(255, 193, 7, 0.9);
            color: #212529;
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
        .status-card.rate-limit {
            background: linear-gradient(135deg, #fff3e0, #ffe0b2);
            border-color: #ff9800;
            color: #e65100;
        }
        .status-card.rate-limit::before {
            background: linear-gradient(90deg, #ff9800, #fb8c00);
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
        .progress-bar {
            width: 100%;
            height: 16px;
            background: #e9ecef;
            border-radius: 8px;
            overflow: hidden;
            margin: 15px 0;
            box-shadow: inset 0 2px 4px rgba(0,0,0,0.1);
        }
        .progress-fill {
            height: 100%;
            transition: width 0.8s ease;
            border-radius: 8px;
            background: linear-gradient(90deg, #28a745, #20c997);
            box-shadow: 0 2px 4px rgba(40, 167, 69, 0.3);
            position: relative;
        }
        .progress-fill::after {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent);
            animation: shimmer 2s infinite;
        }
        @keyframes shimmer {
            0% { transform: translateX(-100%); }
            100% { transform: translateX(100%); }
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
            content: 'v2.1';
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
            .version-badge, .rate-limit-badge {
                position: relative;
                top: 0;
                right: 0;
                left: 0;
                margin-bottom: 15px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="version-badge">🛡️ No Sessions v2.1</div>
            <div class="rate-limit-badge">⚡ Rate Limiting</div>
            
            <h1>🛡️ Redis MurKir Security System v2.1</h1>
            <p>Система защиты с Rate Limiting и продвинутой блокировкой</p>
            
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

        <!-- НОВЫЙ БЛОК: Статус Rate Limiting v2.1 -->
        <?php if ($rateLimitStats): ?>
        <div class="status-card rate-limit new-feature">
            <h2>⚡ Статус Rate Limiting (v2.1)</h2>
            
            <?php 
            $currentStats = $rateLimitStats['current_stats'] ?? null;
            $blockHistory = $rateLimitStats['block_history'] ?? null;
            $isBlocked = $rateLimitStats['is_blocked'] ?? false;
            ?>
            
            <?php if ($isBlocked): ?>
                <div style="color: #dc3545; padding: 10px; background: rgba(220, 53, 69, 0.1); border-radius: 8px; margin-bottom: 15px;">
                    <strong>🚫 IP заблокирован системой Rate Limiting!</strong>
                </div>
            <?php else: ?>
                <div style="color: #28a745; padding: 10px; background: rgba(40, 167, 69, 0.1); border-radius: 8px; margin-bottom: 15px;">
                    <strong>✅ Rate Limiting активен - статус нормальный</strong>
                </div>
            <?php endif; ?>
            
            <?php if ($currentStats): ?>
                <div class="metrics">
                    <div class="metric">
                        <div class="number"><?php echo $currentStats['requests_1min'] ?? 0; ?></div>
                        <div class="label">Запросов/минуту</div>
                    </div>
                    <div class="metric">
                        <div class="number"><?php echo $currentStats['requests_5min'] ?? 0; ?></div>
                        <div class="label">Запросов/5 мин</div>
                    </div>
                    <div class="metric">
                        <div class="number"><?php echo $currentStats['requests_1hour'] ?? 0; ?></div>
                        <div class="label">Запросов/час</div>
                    </div>
                    <div class="metric">
                        <div class="number"><?php echo $currentStats['violations'] ?? 0; ?></div>
                        <div class="label">Нарушений</div>
                    </div>
                </div>
                
                <div class="highlight-box">
                    <strong>📊 Лимиты для <?php echo $isMobile ? 'мобильных' : 'десктопных'; ?> устройств:</strong>
                    <?php if ($rateLimitSettings): ?>
                        <ul style="margin: 10px 0;">
                            <li>🔢 Максимум в минуту: <strong><?php echo $rateLimitSettings['max_requests_per_minute']; ?></strong></li>
                            <li>🔢 Максимум за 5 минут: <strong><?php echo $rateLimitSettings['max_requests_per_5min']; ?></strong></li>
                            <li>🔢 Максимум в час: <strong><?php echo $rateLimitSettings['max_requests_per_hour']; ?></strong></li>
                            <li>💥 Порог всплеска: <strong><?php echo $rateLimitSettings['burst_threshold']; ?> запросов / <?php echo $rateLimitSettings['burst_window']; ?> сек</strong></li>
                            <li>🔄 Максимум смен UA: <strong><?php echo $rateLimitSettings['ua_change_threshold']; ?></strong></li>
                        </ul>
                    <?php endif; ?>
                </div>
            <?php else: ?>
                <p style="color: #6c757d; text-align: center; padding: 20px;">
                    ℹ️ Данные Rate Limiting еще не собраны для вашего IP
                </p>
            <?php endif; ?>
            
            <?php if ($blockHistory && $blockHistory['count'] > 0): ?>
                <div class="highlight-box">
                    <strong>⚠️ История блокировок:</strong><br>
                    Всего блокировок: <strong><?php echo $blockHistory['count']; ?></strong><br>
                    Последняя блокировка: <strong><?php echo date('Y-m-d H:i:s', $blockHistory['last_block']); ?></strong>
                </div>
            <?php endif; ?>
        </div>
        <?php endif; ?>

        <!-- Статус Redis v2.1 -->
        <div class="status-card redis <?php echo !$protectionActive ? 'error' : ''; ?>">
            <h2>📊 Статус Redis Protection v2.1 (Rate Limiting)</h2>
            <?php if ($protectionActive): ?>
                <p><strong>✅ Redis подключен и работает</strong></p>
                <div class="protection-level protection-maximum">🛡️ Максимальная защита с Rate Limiting активна</div>
                
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
                        <div class="metric new-feature">
                            <div class="number"><?php echo $redisStats['rate_limit_tracking'] ?? 0; ?></div>
                            <div class="label">Rate Limit трекинг</div>
                        </div>
                        <div class="metric new-feature">
                            <div class="number"><?php echo $redisStats['rate_limit_violations'] ?? 0; ?></div>
                            <div class="label">Нарушений лимитов</div>
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
                    <strong>🚀 Особенности версии v2.1 с Rate Limiting:</strong>
                    <ul>
                        <li>✅ Стабильная работа без зависимости от PHP сессий</li>
                        <li>🔒 Продвинутая система хеш-блокировки пользователей</li>
                        <li>📱 Оптимизация для мобильных устройств</li>
                        <li>⚡ Улучшенная производительность и скорость</li>
                        <li>🛡️ Более стабильная блокировка через отпечатки</li>
                        <li>🧹 Автоматическая очистка старых данных</li>
                        <li>🌟 Система VIP пользователей на основе Redis данных</li>
                        <li>🎯 Интеллектуальная оценка уровня доверия</li>
                        <li>⚡ <strong>НОВОЕ: Advanced Rate Limiting с прогрессивной блокировкой</strong></li>
                        <li>💥 <strong>НОВОЕ: Детекция всплесков активности</strong></li>
                        <li>🔄 <strong>НОВОЕ: Обнаружение смены User-Agent</strong></li>
                        <li>📊 <strong>НОВОЕ: Детальная статистика нарушений</strong></li>
                    </ul>
                </div>
            <?php else: ?>
                <p><strong>❌ Redis недоступен</strong></p>
                <div class="protection-level protection-basic">⚠️ Базовая защита</div>
                <p>Проверьте подключение к Redis серверу. Система защиты не активна.</p>
            <?php endif; ?>
        </div>

        <!-- Статус пользователя с уровнем доверия -->
        <div class="status-card <?php echo $isVerified ? '' : 'warning'; ?>">
            <h2>👤 Статус пользователя (Redis-based)</h2>
            <?php if ($isVerified): ?>
                <p><strong>✅ Верифицированный пользователь</strong></p>
                <div style="margin: 15px 0;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                        <strong>🎯 Уровень доверия:</strong> 
                        <span style="font-size: 1.2em; font-weight: bold; color: #007bff;"><?php echo $trustScore; ?>%</span>
                    </div>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: <?php echo $trustScore; ?>%;"></div>
                    </div>
                </div>
                
                <?php if ($trustScore >= 90): ?>
                    <div style="color: #28a745; font-weight: bold; margin-top: 15px; padding: 10px; background: rgba(40, 167, 69, 0.1); border-radius: 8px;">
                        🌟 VIP пользователь - максимальный уровень доверия!
                    </div>
                <?php elseif ($trustScore >= 70): ?>
                    <div style="color: #28a745; font-weight: bold; margin-top: 15px; padding: 10px; background: rgba(40, 167, 69, 0.1); border-radius: 8px;">
                        ⭐ Доверенный пользователь - высокий уровень доверия!
                    </div>
                <?php elseif ($visitInfo && $visitInfo['time_spent'] < 300): ?>
                    <div style="color: #007bff; margin-top: 15px; padding: 10px; background: rgba(0, 123, 255, 0.1); border-radius: 8px;">
                        👋 Добро пожаловать, новый посетитель!
                    </div>
                <?php else: ?>
                    <div style="color: #6c757d; margin-top: 15px; padding: 10px; background: rgba(108, 117, 125, 0.1); border-radius: 8px;">
                        👤 Обычный пользователь
                    </div>
                <?php endif; ?>
                
                <?php if ($visitInfo): ?>
                <div style="margin-top: 20px; font-size: 0.9em; color: #6c757d;">
                    <p><strong>📊 Детали активности:</strong></p>
                    <ul style="margin: 10px 0;">
                        <li>⏱️ Время на сайте: <?php echo gmdate('H:i:s', $visitInfo['time_spent']); ?></li>
                        <li>📄 Страниц посещено: <?php echo $visitInfo['pages_visited']; ?></li>
                        <li>🔄 Всего запросов: <?php echo $visitInfo['total_requests']; ?></li>
                        <li>🌐 Уникальных IP: <?php echo $visitInfo['unique_ips']; ?></li>
                        <li>🎭 User-Agent'ов: <?php echo $visitInfo['user_agents']; ?></li>
                    </ul>
                </div>
                <?php endif; ?>
            <?php else: ?>
                <p><strong>⚠️ Пользователь не верифицирован</strong></p>
                <p>Система защиты не активна, заблокирован или недостаточно данных для анализа.</p>
                <div style="margin-top: 15px; padding: 10px; background: rgba(255, 193, 7, 0.1); border-radius: 8px;">
                    <strong>💡 Для получения VIP статуса:</strong>
                    <ul style="margin: 10px 0;">
                        <li>Проводите больше времени на сайте (5+ минут)</li>
                        <li>Посещайте разные страницы (3+ страницы)</li>
                        <li>Избегайте подозрительной активности</li>
                        <li>Используйте стабильное подключение</li>
                    </ul>
                </div>
            <?php endif; ?>
        </div>

        <!-- Остальные секции остаются как в предыдущей версии, добавляю только новые табы -->

        <!-- Табы -->
        <div class="tabs">
            <button class="tab active" onclick="showTab('request-info')">🌐 Запрос</button>
            <button class="tab" onclick="showTab('rate-limiting')">⚡ Rate Limiting</button>
            <button class="tab" onclick="showTab('redis-keys')">🔑 Redis ключи</button>
            <button class="tab" onclick="showTab('user-hash-stats')">📊 Статистика хешей</button>
            <button class="tab" onclick="showTab('ttl-settings')">⏱️ TTL настройки</button>
            <button class="tab" onclick="showTab('testing')">🧪 Тестирование</button>
            <button class="tab" onclick="showTab('debug')">🔍 Debug</button>
        </div>

        <!-- НОВЫЙ ТАБ: Rate Limiting v2.1 -->
        <div id="rate-limiting" class="tab-content">
            <div class="info-box new-feature">
                <h3>⚡ Rate Limiting & Progressive Blocking v2.1</h3>
                
                <?php if ($rateLimitSettings): ?>
                    <h4>📋 Текущие настройки Rate Limiting:</h4>
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Параметр</th>
                                <th>Значение</th>
                                <th>Описание</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td><code>max_requests_per_minute</code></td>
                                <td><strong><?php echo $rateLimitSettings['max_requests_per_minute']; ?></strong></td>
                                <td>Макс. запросов в минуту</td>
                            </tr>
                            <tr>
                                <td><code>max_requests_per_5min</code></td>
                                <td><strong><?php echo $rateLimitSettings['max_requests_per_5min']; ?></strong></td>
                                <td>Макс. запросов за 5 минут</td>
                            </tr>
                            <tr>
                                <td><code>max_requests_per_hour</code></td>
                                <td><strong><?php echo $rateLimitSettings['max_requests_per_hour']; ?></strong></td>
                                <td>Макс. запросов в час</td>
                            </tr>
                            <tr style="background: rgba(255, 193, 7, 0.1);">
                                <td><code>burst_threshold</code></td>
                                <td><strong><?php echo $rateLimitSettings['burst_threshold']; ?></strong></td>
                                <td>Порог всплеска активности</td>
                            </tr>
                            <tr>
                                <td><code>burst_window</code></td>
                                <td><strong><?php echo $rateLimitSettings['burst_window']; ?> сек</strong></td>
                                <td>Окно детекции всплеска</td>
                            </tr>
                            <tr style="background: rgba(255, 193, 7, 0.1);">
                                <td><code>ua_change_threshold</code></td>
                                <td><strong><?php echo $rateLimitSettings['ua_change_threshold']; ?></strong></td>
                                <td>Макс. смен User-Agent</td>
                            </tr>
                            <tr>
                                <td><code>ua_change_time_window</code></td>
                                <td><strong><?php echo round($rateLimitSettings['ua_change_time_window']/60); ?> мин</strong></td>
                                <td>Окно детекции смены UA</td>
                            </tr>
                            <tr style="background: rgba(220, 53, 69, 0.1);">
                                <td><code>progressive_block_duration</code></td>
                                <td><strong><?php echo round($rateLimitSettings['progressive_block_duration']/60); ?> мин</strong></td>
                                <td>Прогрессивная блокировка</td>
                            </tr>
                            <tr style="background: rgba(220, 53, 69, 0.1);">
                                <td><code>aggressive_block_duration</code></td>
                                <td><strong><?php echo round($rateLimitSettings['aggressive_block_duration']/3600, 1); ?> ч</strong></td>
                                <td>Агрессивная блокировка</td>
                            </tr>
                        </tbody>
                    </table>
                    
                    <div class="highlight-box">
                        <h4>🎯 Как работает прогрессивная блокировка:</h4>
                        <ul>
                            <li>📌 <strong>1-е нарушение:</strong> Блокировка на <?php echo round($rateLimitSettings['progressive_block_duration']/60); ?> минут</li>
                            <li>📌 <strong>2-е нарушение:</strong> Блокировка увеличивается в 2 раза</li>
                            <li>📌 <strong>3+ нарушения:</strong> Блокировка на <?php echo round($rateLimitSettings['aggressive_block_duration']/3600, 1); ?>+ часов (растет с каждым разом)</li>
                            <li>🔄 История нарушений хранится 7 дней</li>
                            <li>✅ После 7 дней без нарушений счетчик сбрасывается</li>
                        </ul>
                    </div>
                <?php endif; ?>
                
                <?php if ($topViolators && count($topViolators) > 0): ?>
                    <h4>🚨 Топ-<?php echo count($topViolators); ?> нарушителей Rate Limiting:</h4>
                    <table class="table">
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>Нарушений</th>
                                <th>1 мин</th>
                                <th>5 мин</th>
                                <th>1 час</th>
                                <th>Последний запрос</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($topViolators as $idx => $violator): ?>
                                <tr>
                                    <td><?php echo $idx + 1; ?></td>
                                    <td><span class="security-badge security-danger"><?php echo $violator['violations']; ?></span></td>
                                    <td><?php echo $violator['requests_1min']; ?></td>
                                    <td><?php echo $violator['requests_5min']; ?></td>
                                    <td><?php echo $violator['requests_1hour']; ?></td>
                                    <td><?php echo $violator['last_request']; ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php else: ?>
                    <div style="text-align: center; padding: 30px; color: #28a745;">
                        <strong>✅ Нарушений Rate Limiting не обнаружено!</strong><br>
                        <span style="font-size: 0.9em; color: #6c757d;">Все пользователи ведут себя в рамках установленных лимитов.</span>
                    </div>
                <?php endif; ?>
                
                <div class="highlight-box">
                    <h4>💡 Советы по настройке Rate Limiting:</h4>
                    <ul>
                        <li><strong>Для небольших сайтов:</strong> Оставьте настройки по умолчанию</li>
                        <li><strong>Для крупных сайтов:</strong> Увеличьте лимиты в 1.5-2 раза</li>
                        <li><strong>Для API:</strong> Установите более высокие лимиты (200-300/мин)</li>
                        <li><strong>Для защиты от DDoS:</strong> Уменьшите burst_threshold до 10-15</li>
                        <li><strong>Мониторинг:</strong> Регулярно проверяйте топ нарушителей</li>
                    </ul>
                </div>
            </div>
        </div>

        <!-- Информация о запросе (оставляем как есть) -->
        <div id="request-info" class="tab-content active">
            <!-- Содержимое остается без изменений -->
        </div>

        <!-- Остальные табы остаются без изменений, но добавлю новые тесты -->

        <!-- Обновленный таб Testing -->
        <div id="testing" class="tab-content">
            <div class="info-box">
                <h3>🧪 Тестирование системы v2.1 (Rate Limiting)</h3>
                <p>Используйте эти инструменты для тестирования различных сценариев защиты:</p>
                
                <div style="margin: 25px 0;">
                    <h4>🔗 Базовые тесты:</h4>
                    <a href="redis_test.php" class="btn">🔄 Обновить страницу</a>
                    <a href="redis_test.php?page=2" class="btn secondary">📄 Страница 2</a>
                    <a href="redis_test.php?page=3" class="btn secondary">📄 Страница 3</a>
                    <a href="redis_test.php?heavy=1" class="btn secondary">⚡ Тяжелая операция</a>
                    <a href="redis_test.php?mobile_test=1" class="btn secondary">📱 Тест мобильного</a>
                </div>

                <div style="margin: 25px 0;">
                    <h4>⚡ Тесты Rate Limiting (v2.1):</h4>
                    <button onclick="botProtectionTest.testRateLimitNormal()" class="btn success">✅ Нормальная нагрузка</button>
                    <button onclick="botProtectionTest.testRateLimitModerate()" class="btn warning">⚠️ Умеренная нагрузка</button>
                    <button onclick="botProtectionTest.testRateLimitHeavy()" class="btn danger">🔥 Высокая нагрузка</button>
                    <button onclick="botProtectionTest.testBurstDetection()" class="btn danger">💥 Тест всплеска</button>
                    <button onclick="botProtectionTest.testUASwitching()" class="btn danger">🔄 Смена UA</button>
                </div>

                <div style="margin: 25px 0;">
                    <h4>⚙️ Административные тесты:</h4>
                    <?php if (isset($_GET['admin']) && $_GET['admin'] === '1'): ?>
                        <a href="redis_test.php" class="btn">👁️ Обычный режим</a>
                        <a href="redis_test.php?admin=1&action=reset_rate_limit" class="btn warning">🔄 Сбросить Rate Limit</a>
                        <a href="redis_test.php?admin=1&action=rate_limit_stats" class="btn secondary">📊 Статистика лимитов</a>
                    <?php else: ?>
                        <a href="redis_test.php?admin=1" class="btn danger">⚙️ Админ режим</a>
                    <?php endif; ?>
                </div>

                <div style="margin: 25px 0;">
                    <h4>🤖 JavaScript тесты в браузере:</h4>
                    <button onclick="botProtectionTest.simulateBot()" class="btn warning">🤖 Симулировать бота</button>
                    <button onclick="botProtectionTest.simulateHuman()" class="btn success">👤 Симулировать человека</button>
                    <button onclick="botProtectionTest.testUserHash()" class="btn secondary">🔒 Тест хеша пользователя</button>
                    <button onclick="botProtectionTest.performanceTest()" class="btn secondary">🚀 Тест производительности</button>
                    <button onclick="botProtectionTest.analyzeUserHash()" class="btn secondary">🔍 Анализ отпечатка</button>
                    <button onclick="botProtectionTest.clearLocalData()" class="btn danger">🧹 Очистить данные</button>
                    <button onclick="botProtectionTest.stressTest()" class="btn danger">💣 Стресс-тест</button>
                </div>

                <!-- curl тесты обновлены с примерами Rate Limiting -->
                <h4>💻 Командная строка (curl тесты Rate Limiting):</h4>
                <pre style="font-size: 11px;">
# Тест превышения лимита запросов в минуту
for i in {1..70}; do
  curl -s "<?php echo (isset($_SERVER['HTTPS']) ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']; ?>?rate_test=$i" &
  sleep 0.8
done
wait

# Тест всплеска активности (burst detection)
for i in {1..25}; do
  curl -s "<?php echo (isset($_SERVER['HTTPS']) ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']; ?>?burst_test=$i" &
done
wait

# Тест смены User-Agent (должен заблокировать)
UA_LIST=("Mozilla/5.0 (Windows)" "curl/7.68.0" "python-requests/2.28" "wget/1.21" "Go-http-client/1.1" "PostmanRuntime/7.29")
for ua in "${UA_LIST[@]}"; do
  curl -H "User-Agent: $ua" "<?php echo (isset($_SERVER['HTTPS']) ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']; ?>?ua_test=1"
  sleep 1
done

# Мониторинг Redis Rate Limiting (в отдельном терминале)
redis-cli monitor | grep "bot_protection:ratelimit"

# Проверка текущих лимитов
redis-cli keys "bot_protection:tracking:ratelimit:*"

# Получить статистику для конкретного IP
redis-cli get "bot_protection:tracking:ratelimit:<?php echo hash('md5', $currentIP); ?>"
                </pre>
            </div>
        </div>

        <!-- Остальные табы (redis-keys, user-hash-stats, ttl-settings, debug) -->
        <!-- Код этих табов остается без изменений, добавляем только информацию о Rate Limiting где нужно -->

        <!-- Административные действия с Rate Limiting -->
        <?php if (isset($_GET['admin']) && $_GET['admin'] === '1'): ?>
        <div class="info-box" style="border-left-color: #dc3545;">
            <h3>⚙️ Административные действия v2.1</h3>
            <div style="margin: 20px 0;">
                <?php
                if (isset($_GET['action']) && $protectionActive) {
                    switch ($_GET['action']) {
                        case 'reset_rate_limit':
                            $result = $protection->resetRateLimit($currentIP);
                            echo "<div class='highlight-box'>";
                            echo "<strong>🔄 Результат сброса Rate Limit:</strong><br>";
                            echo "Rate Limit очищен: " . ($result['rate_limit_cleared'] ? '✅ Да' : '❌ Нет') . "<br>";
                            echo "История очищена: " . ($result['history_cleared'] ? '✅ Да' : '❌ Нет');
                            echo "</div>";
                            break;
                        case 'rate_limit_stats':
                            $stats = $protection->getRateLimitStats($currentIP);
                            echo "<div class='highlight-box'>";
                            echo "<strong>📊 Статистика Rate Limiting:</strong><br>";
                            echo "<pre style='margin-top: 10px;'>" . json_encode($stats, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "</pre>";
                            echo "</div>";
                            break;
                        // ... остальные action cases остаются без изменений
                    }
                }
                ?>
                
                <h4>⚡ Rate Limiting действия:</h4>
                <a href="redis_test.php?admin=1&action=reset_rate_limit" class="btn warning">🔄 Сбросить Rate Limit</a>
                <a href="redis_test.php?admin=1&action=rate_limit_stats" class="btn secondary">📊 Статистика лимитов</a>
                
                <!-- Остальные кнопки действий остаются без изменений -->
            </div>
        </div>
        <?php endif; ?>

        <hr style="margin: 40px 0; border: none; height: 1px; background: linear-gradient(90deg, transparent, #dee2e6, transparent);">
        
        <div style="text-align: center; color: #6c757d; font-size: 0.9em;">
            <div style="margin-bottom: 10px;">
                🛡️ <strong>Redis MurKir Security System v2.1</strong> - Advanced Rate Limiting Protection
            </div>
            <div style="display: flex; flex-wrap: wrap; justify-content: center; gap: 15px; font-size: 0.85em;">
                <span>📅 Generated: <?php echo date('Y-m-d H:i:s'); ?></span>
                <span>🐘 PHP: <?php echo PHP_VERSION; ?></span>
                <span>📡 Redis: <?php echo $protectionActive ? '✅ Active' : '❌ Inactive'; ?></span>
                <span>📱 Device: <?php echo $isMobile ? 'Mobile' : 'Desktop'; ?></span>
                <span>🛡️ Protection: <?php echo ucfirst($protectionLevel); ?></span>
                <span>🚫 Sessions: Disabled</span>
                <span>⚡ Rate Limiting: <?php echo $protectionActive ? '✅ Active' : '❌ Inactive'; ?></span>
                <?php if ($rateLimitStats && isset($rateLimitStats['current_stats'])): ?>
                    <span>🔢 Requests: <?php echo $rateLimitStats['current_stats']['requests_1min'] ?? 0; ?>/min</span>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <script>
// Функція перемикання табів
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

// Функція копіювання в буфер обміну
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
        
        botProtectionTest.showNotification('📋 Скопійовано: ' + text.substring(0, 20) + '...', 'success');
    }).catch(err => {
        console.log('Copy failed:', err);
        botProtectionTest.showNotification('❌ Помилка копіювання', 'error');
    });
}

// Відстеження активності користувача
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

// Слухачі подій активності
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

// Відстеження перемикання табів
document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
        userActivity.tabSwitches++;
    });
});

// Головний об'єкт тестування системи захисту
window.botProtectionTest = {
    // Симуляція бот-подібної поведінки
    simulateBot: function() {
        console.log('🤖 Simulating bot behavior v2.1...');
        this.showNotification('🤖 Запуск симуляції бота...', 'warning');
        
        // Швидкі запити без пауз
        for(let i = 0; i < 15; i++) {
            setTimeout(() => {
                fetch(window.location.href + '?bot_test=' + i + '&timestamp=' + Date.now() + '&rapid_fire=1')
                    .then(response => {
                        console.log(`Bot request ${i}: ${response.status}`);
                        if (response.status === 429) {
                            this.showNotification('🚫 Бот заблокований!', 'error');
                        }
                    })
                    .catch(err => console.log(`Bot request ${i} failed:`, err));
            }, i * 50);
        }
    },
    
    // Симуляція людської поведінки
    simulateHuman: function() {
        console.log('👤 Simulating human behavior v2.1...');
        this.showNotification('👤 Симуляція людської поведінки...', 'info');
        
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
            }, index * 2000 + Math.random() * 1000);
        });
    },
    
    // НОВА ФУНКЦІЯ: Тест нормальної навантаження
    testRateLimitNormal: function() {
        console.log('✅ Testing normal load (within limits)...');
        this.showNotification('✅ Тест нормального навантаження...', 'success');
        
        let count = 0;
        const maxRequests = 10;
        const interval = 2000;
        
        const testInterval = setInterval(() => {
            if (count >= maxRequests) {
                clearInterval(testInterval);
                this.showNotification('✅ Тест нормального навантаження завершено', 'success');
                return;
            }
            
            fetch(window.location.href + '?normal_load=' + count + '&t=' + Date.now())
                .then(response => {
                    console.log(`Normal load request ${count}: ${response.status}`);
                    if (response.status === 429) {
                        clearInterval(testInterval);
                        this.showNotification('⚠️ Несподівано заблоковано!', 'warning');
                    }
                })
                .catch(err => console.log('Request failed:', err));
            
            count++;
        }, interval);
    },
    
    // НОВА ФУНКЦІЯ: Тест помірного навантаження
    testRateLimitModerate: function() {
        console.log('⚠️ Testing moderate load...');
        this.showNotification('⚠️ Тест помірного навантаження...', 'warning');
        
        let count = 0;
        const maxRequests = 45;
        const interval = 1000;
        
        const testInterval = setInterval(() => {
            if (count >= maxRequests) {
                clearInterval(testInterval);
                this.showNotification('⚠️ Тест помірного навантаження завершено', 'info');
                return;
            }
            
            fetch(window.location.href + '?moderate_load=' + count + '&t=' + Date.now())
                .then(response => {
                    console.log(`Moderate load request ${count}: ${response.status}`);
                    if (response.status === 429) {
                        clearInterval(testInterval);
                        this.showNotification(`🚫 Заблоковано після ${count} запитів!`, 'error');
                    }
                })
                .catch(err => console.log('Request failed:', err));
            
            count++;
        }, interval);
    },
    
    // НОВА ФУНКЦІЯ: Тест високого навантаження
    testRateLimitHeavy: function() {
        console.log('🔥 Testing heavy load (should block)...');
        this.showNotification('🔥 Тест високого навантаження - очікується блокування...', 'danger');
        
        let count = 0;
        const maxRequests = 70;
        const interval = 800;
        
        const testInterval = setInterval(() => {
            if (count >= maxRequests) {
                clearInterval(testInterval);
                this.showNotification('🔥 Тест завершено - система повинна була заблокувати', 'info');
                return;
            }
            
            fetch(window.location.href + '?heavy_load=' + count + '&t=' + Date.now())
                .then(response => {
                    console.log(`Heavy load request ${count}: ${response.status}`);
                    if (response.status === 429) {
                        clearInterval(testInterval);
                        this.showNotification(`🚫 ЗАБЛОКОВАНО після ${count} запитів! Rate Limiting працює!`, 'error');
                    }
                })
                .catch(err => console.log('Request failed:', err));
            
            count++;
        }, interval);
    },
    
    // НОВА ФУНКЦІЯ: Тест детекції сплеску
    testBurstDetection: function() {
        console.log('💥 Testing burst detection...');
        this.showNotification('💥 Тест детекції сплеску...', 'danger');
        
        const promises = [];
        for (let i = 0; i < 25; i++) {
            promises.push(
                fetch(window.location.href + '?burst_test=' + i + '&t=' + Date.now())
                    .then(response => ({
                        request: i,
                        status: response.status,
                        blocked: response.status === 429
                    }))
            );
        }
        
        Promise.all(promises).then(results => {
            const blockedCount = results.filter(r => r.blocked).length;
            console.log('Burst test results:', results);
            
            if (blockedCount > 0) {
                this.showNotification(`💥 Сплеск виявлено! ${blockedCount} запитів заблоковано`, 'error');
            } else {
                this.showNotification('💥 Сплеск не виявлено - можливо ліміт занадто високий', 'warning');
            }
        });
    },
    
    // НОВА ФУНКЦІЯ: Тест зміни User-Agent
    testUASwitching: function() {
        console.log('🔄 Testing User-Agent switching detection...');
        this.showNotification('🔄 Тест детекції зміни User-Agent...', 'warning');
        
        const testUA = [
            'Mozilla/5.0 (Test1)',
            'Mozilla/5.0 (Test2)',
            'Mozilla/5.0 (Test3)',
            'Mozilla/5.0 (Test4)',
            'Mozilla/5.0 (Test5)',
            'Mozilla/5.0 (Test6)'
        ];
        
        testUA.forEach((ua, index) => {
            setTimeout(() => {
                fetch(window.location.href + '?ua_test=' + index + '&simulated_ua=' + encodeURIComponent(ua) + '&t=' + Date.now())
                    .then(response => {
                        console.log(`UA test ${index}: ${response.status}`);
                        if (response.status === 429) {
                            this.showNotification(`🚫 Зміна UA виявлена після ${index + 1} змін!`, 'error');
                        }
                    })
                    .catch(err => console.log('UA test failed:', err));
            }, index * 1000);
        });
        
        setTimeout(() => {
            this.showNotification('ℹ️ Для реального тесту зміни UA використовуйте curl', 'info');
        }, 7000);
    },
    
    // Тест хешу користувача
    testUserHash: function() {
        console.log('🔒 Testing user hash v2.1...');
        this.showNotification('🔒 Тестування хешу користувача...', 'info');
        
        fetch(window.location.href + '?hash_test=1&timestamp=' + Date.now())
            .then(response => response.text())
            .then(data => {
                console.log('User hash test completed');
                
                if (data.includes('Rate limit exceeded') || data.includes('429')) {
                    this.showNotification('🚫 Хеш заблокований системою!', 'error');
                } else {
                    this.showNotification('✅ Тест хешу пройдено успішно', 'success');
                }
            })
            .catch(err => {
                console.log('Hash test failed:', err);
                this.showNotification('❌ Помилка тестування хешу', 'error');
            });
    },
    
    // Тест продуктивності
    performanceTest: function() {
        console.log('🚀 Starting performance test v2.1...');
        this.showNotification('🚀 Запуск тесту продуктивності...', 'info');
        
        const startTime = performance.now();
        const requests = [];
        
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
                this.showNotification(`⚠️ ${blockedCount} запитів заблоковано з ${results.length}`, 'warning');
            } else {
                this.showNotification(`🚀 Тест завершено: ${avgTime.toFixed(2)}ms середній час`, 'success');
            }
        });
    },
    
    // Аналіз відбитка браузера
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
        
        console.log('🔍 Advanced browser fingerprint analysis v2.1:', fingerprint);
        this.showNotification('🔍 Розширений аналіз відбитка завершено (див. консоль)', 'info');
        
        return fingerprint;
    },
    
    // Отримання інформації WebGL
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
    
    // Отримання відбитка Canvas
    getCanvasFingerprint: function() {
        try {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            ctx.textBaseline = 'top';
            ctx.font = '14px Arial';
            ctx.fillText('BotProtection v2.1 NoSessions 🛡️', 2, 2);
            return canvas.toDataURL().substring(0, 50) + '...';
        } catch (e) {
            return 'error';
        }
    },
    
    // Стрес-тест системи
    stressTest: function() {
        console.log('💣 Starting stress test v2.1 (Rate Limiting)...');
        this.showNotification('💣 Запуск стрес-тесту з Rate Limiting...', 'danger');
        
        let requestCount = 0;
        const maxRequests = 50;
        const interval = 500;
        
        const stressInterval = setInterval(() => {
            if (requestCount >= maxRequests) {
                clearInterval(stressInterval);
                this.showNotification('💣 Стрес-тест завершено', 'info');
                return;
            }
            
            fetch(window.location.href + '?stress_test=' + requestCount + '&timestamp=' + Date.now())
                .then(response => {
                    console.log(`Stress test request ${requestCount}: ${response.status}`);
                    if (response.status === 429) {
                        clearInterval(stressInterval);
                        this.showNotification(`🚫 Rate Limiting заблокував після ${requestCount} запитів!`, 'error');
                    }
                })
                .catch(err => console.log('Stress test request failed:', err));
            
            requestCount++;
        }, interval);
    },
    
    // Очищення локальних даних
    clearLocalData: function() {
        localStorage.clear();
        sessionStorage.clear();
        
        document.cookie.split(";").forEach(function(c) { 
            document.cookie = c.replace(/^ +/, "").replace(/=.*/, "=;expires=" + new Date().toUTCString() + ";path=/"); 
        });
        
        console.log('🧹 All local data cleared (no sessions mode)');
        this.showNotification('🧹 Всі локальні дані очищено', 'success');
        
        setTimeout(() => {
            this.showNotification('🔄 Перезавантаження через 3 секунди...', 'info');
            setTimeout(() => window.location.reload(), 3000);
        }, 1000);
    },
    
    // Показ повідомлень з покращеним дизайном
    showNotification: function(message, type = 'info') {
        const notification = document.createElement('div');
        const colors = {
            error: { bg: '#dc3545', shadow: 'rgba(220, 53, 69, 0.3)' },
            success: { bg: '#28a745', shadow: 'rgba(40, 167, 69, 0.3)' },
            warning: { bg: '#ffc107', shadow: 'rgba(255, 193, 7, 0.3)', text: '#212529' },
            info: { bg: '#007bff', shadow: 'rgba(0, 123, 255, 0.3)' },
            danger: { bg: '#ff6b6b', shadow: 'rgba(255, 107, 107, 0.3)' }
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

        notification.addEventListener('click', hideNotification);
        setTimeout(hideNotification, 5000);
    }
};

// Моніторинг активності користувача
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
    
    console.log('👤 User Activity Analysis v2.1:', activityData);
}, 20000);

// Оновлення прогрес-барів з анімацією
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

// Анімація метрик з ефектом підрахунку
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

// Клавіатурні комбінації
document.addEventListener('keydown', (e) => {
    if (e.ctrlKey || e.metaKey) {
        switch(e.key) {
            case '1': e.preventDefault(); showTab('request-info'); break;
            case '2': e.preventDefault(); showTab('rate-limiting'); break;
            case '3': e.preventDefault(); showTab('redis-keys'); break;
            case '4': e.preventDefault(); showTab('user-hash-stats'); break;
            case '5': e.preventDefault(); showTab('ttl-settings'); break;
            case '6': e.preventDefault(); showTab('testing'); break;
            case '7': e.preventDefault(); showTab('debug'); break;
            case 'b': e.preventDefault(); botProtectionTest.simulateBot(); break;
            case 'h': e.preventDefault(); botProtectionTest.simulateHuman(); break;
            case 'p': e.preventDefault(); botProtectionTest.performanceTest(); break;
            case 'u': e.preventDefault(); botProtectionTest.testUserHash(); break;
            case 'k': e.preventDefault(); botProtectionTest.clearLocalData(); break;
            case 's': e.preventDefault(); botProtectionTest.stressTest(); break;
        }
    }
});

// Детектор бездіяльності користувача
let idleTimer;
const maxIdleTime = 300;

function resetIdleTimer() {
    clearTimeout(idleTimer);
    idleTimer = setTimeout(() => {
        console.log('💤 User is idle for 5 minutes');
        botProtectionTest.showNotification('😴 Ви неактивні вже 5 хвилин', 'info');
    }, maxIdleTime * 1000);
}

['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart', 'click'].forEach(event => {
    document.addEventListener(event, resetIdleTimer, true);
});

// Ініціалізація при завантаженні сторінки
document.addEventListener('DOMContentLoaded', () => {
    resetIdleTimer();
    
    setTimeout(() => {
        animateMetrics();
        updateProgressBars();
    }, 500);
    
    // Привітальне повідомлення
    setTimeout(() => {
        <?php if (!$protectionActive): ?>
        botProtectionTest.showNotification('⚠️ Redis недоступний! Система захисту не активна.', 'error');
        <?php elseif ($userHashInfo && $userHashInfo['blocked']): ?>
        botProtectionTest.showNotification('🚫 Ваш хеш користувача заблокований системою захисту v2.1!', 'error');
        <?php elseif ($ipInfo && $ipInfo['blocked']): ?>
        botProtectionTest.showNotification('🚫 Ваш IP заблокований системою захисту!', 'error');
        <?php elseif ($isVerified && $trustScore >= 90): ?>
        botProtectionTest.showNotification('🌟 Ласкаво просимо, VIP користувач! Рівень довіри: <?php echo $trustScore; ?>%', 'success');
        <?php elseif ($isVerified && $trustScore >= 70): ?>
        botProtectionTest.showNotification('⭐ Ласкаво просимо, довірений користувач! Рівень: <?php echo $trustScore; ?>%', 'success');
        <?php elseif ($isMobile): ?>
        botProtectionTest.showNotification('📱 Мобільний пристрій! Система v2.1 оптимізована для мобільних.', 'info');
        <?php elseif ($protectionLevel === 'maximum'): ?>
        botProtectionTest.showNotification('🛡️ Bot Protection v2.1 з максимальним захистом активна!', 'success');
        <?php else: ?>
        botProtectionTest.showNotification('🛡️ Bot Protection v2.1 з Rate Limiting активна!', 'info');
        <?php endif; ?>
    }, 1200);
    
    // Показуємо гарячі клавіші
    setTimeout(() => {
        botProtectionTest.showNotification('💡 Гарячі клавіші: Ctrl+1-7 (таби), Ctrl+B (бот), Ctrl+H (людина), Ctrl+P (продуктивність)', 'info');
    }, 4000);
});

// Моніторинг продуктивності сторінки
window.addEventListener('load', () => {
    const loadTime = performance.timing.loadEventEnd - performance.timing.navigationStart;
    console.log(`📊 Page load time: ${loadTime}ms`);
    
    if (loadTime > 3000) {
        botProtectionTest.showNotification('⚠️ Сторінка завантажувалась повільно (' + Math.round(loadTime/1000) + 's)', 'warning');
    }

    // Лого в консолі
    console.log(`
⚡ REDIS MURKIR SECURITY SYSTEM v2.1 ⚡
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🚀 NEW FEATURES v2.1:
✅ Advanced Rate Limiting
✅ Progressive Blocking System
✅ Burst Activity Detection
✅ User-Agent Switching Detection
✅ Detailed Violation Statistics

📊 Current Status:
- Protection: ${<?php echo $protectionActive ? 'true' : 'false'; ?>}
- Device: ${<?php echo $isMobile ? "'Mobile'" : "'Desktop'"; ?>}
- Trust Score: <?php echo $trustScore; ?>%
- Rate Limiting: ${<?php echo $protectionActive ? "'Active'" : "'Inactive'"; ?>}

🔧 Available Test Functions:
- botProtectionTest.testRateLimitNormal() 
- botProtectionTest.testRateLimitModerate()
- botProtectionTest.testRateLimitHeavy()
- botProtectionTest.testBurstDetection()
- botProtectionTest.testUASwitching()
- botProtectionTest.stressTest()
- botProtectionTest.performanceTest()
- botProtectionTest.analyzeUserHash()

⌨️ Keyboard Shortcuts:
- Ctrl+1-7: Switch tabs
- Ctrl+B: Simulate bot
- Ctrl+H: Simulate human
- Ctrl+P: Performance test
- Ctrl+S: Stress test

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    `);
});

// Додаткові CSS анімації
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

// Ініціалізація кликабельних елементів
document.querySelectorAll('.redis-key, .hash-display').forEach(element => {
    element.style.cursor = 'pointer';
    element.title = 'Click to copy';
});

console.log('🛡️ Bot Protection Test Page v2.1 fully loaded and initialized');
console.log('🔧 Available functions:', Object.keys(window.botProtectionTest));
console.log('📊 System status:', {
    redis: <?php echo $protectionActive ? 'true' : 'false'; ?>,
    userHash: <?php echo $userHashInfo ? 'true' : 'false'; ?>,
    mobile: <?php echo $isMobile ? 'true' : 'false'; ?>,
    protectionLevel: '<?php echo $protectionLevel; ?>',
    trustScore: <?php echo $trustScore; ?>,
    vipStatus: '<?php echo $trustScore >= 90 ? 'VIP' : ($trustScore >= 70 ? 'Trusted' : 'Regular'); ?>',
    sessionsDisabled: true,
    visitorCookie: <?php echo $hasVisitorCookie ? 'true' : 'false'; ?>,
    rateLimiting: <?php echo $protectionActive ? 'true' : 'false'; ?>
});
</script>
</body>
</html>
