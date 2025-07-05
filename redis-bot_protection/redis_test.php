<?php
// /home/kinoprostor/kinoprostor15.2/dos/bot_protection/redis_test.php

// Подключаем обновленную Redis-версию защиты
require_once 'inline_check.php';

// Инициализируем защиту
try {
   $protection = new RedisBotProtectionWithSessions(
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

// Функции для работы с Redis-системой защиты
function isVerifiedUser() {
   return isset($_SESSION['bot_protection']['verified']) && 
          $_SESSION['bot_protection']['verified'] === true;
}

function getUserVisitInfo() {
   if (!isset($_SESSION['bot_protection'])) {
       return null;
   }
   
   return [
       'first_visit' => $_SESSION['bot_protection']['first_visit'],
       'pages_visited' => $_SESSION['bot_protection']['pages_visited'] ?? 1,
       'visit_count' => $_SESSION['bot_protection']['visit_count'] ?? 1,
       'last_activity' => $_SESSION['bot_protection']['last_activity'] ?? time(),
       'ip' => $_SESSION['bot_protection']['ip'] ?? 'unknown',
       'user_agent' => $_SESSION['bot_protection']['user_agent'] ?? 'unknown'
   ];
}

function getVisitorTrustScore() {
   $info = getUserVisitInfo();
   if (!$info) return 0;
   
   $score = 0;
   $timeOnSite = time() - $info['first_visit'];
   
   if ($timeOnSite > 300) $score += 20;
   if ($timeOnSite > 900) $score += 30;
   if ($info['pages_visited'] > 3) $score += 20;
   if ($info['pages_visited'] > 10) $score += 30;
   if ($info['visit_count'] > 1) $score += 30;
   
   return min($score, 100);
}

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

// Получаем данные
$isVerified = isVerifiedUser();
$visitInfo = getUserVisitInfo();
$trustScore = getVisitorTrustScore();
$currentIP = getCurrentIP();
$currentUA = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
$isMobile = isMobileDevice($currentUA);
$redisStats = $protectionActive ? getRedisStats($protection) : null;
$ipInfo = $protectionActive ? getRedisInfo($protection, $currentIP) : null;
$userHashInfo = $protectionActive ? getUserHashInfo($protection) : null;
$userHashStats = $protectionActive ? getUserHashStats($protection) : null;
$ttlSettings = $protectionActive ? getTTLSettings($protection) : null;
?>
<!DOCTYPE html>
<html lang="ru">
<head>
   <meta charset="UTF-8">
   <meta name="viewport" content="width=device-width, initial-scale=1.0">
   <title>🛡️ Redis MurKir Security Test v2.0</title>
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
           max-width: 1400px;
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
       }
       .version-badge {
           position: absolute;
           top: 10px;
           right: 10px;
           background: rgba(255, 255, 255, 0.9);
           color: #007bff;
           padding: 5px 10px;
           border-radius: 15px;
           font-size: 0.8em;
           font-weight: bold;
       }
       .status-card {
           background: linear-gradient(135deg, #e8f5e8, #d4edda);
           border: 1px solid #28a745;
           border-radius: 12px;
           padding: 20px;
           margin: 20px 0;
           box-shadow: 0 4px 15px rgba(40, 167, 69, 0.1);
           position: relative;
       }
       .status-card.warning {
           background: linear-gradient(135deg, #fff3cd, #ffeaa7);
           border-color: #ffc107;
           color: #856404;
       }
       .status-card.error {
           background: linear-gradient(135deg, #f8d7da, #fab1a0);
           border-color: #dc3545;
           color: #721c24;
       }
       .status-card.redis {
           background: linear-gradient(135deg, #e3f2fd, #bbdefb);
           border-color: #2196f3;
           color: #0d47a1;
       }
       .status-card.user-hash {
           background: linear-gradient(135deg, #f3e5f5, #e1bee7);
           border-color: #9c27b0;
           color: #4a148c;
       }
       .info-grid {
           display: grid;
           grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
           gap: 20px;
           margin: 20px 0;
       }
       .info-box {
           background: #f8f9fa;
           border-left: 4px solid #007bff;
           padding: 20px;
           border-radius: 8px;
           box-shadow: 0 2px 10px rgba(0,0,0,0.05);
       }
       .info-box h3 {
           margin-top: 0;
           color: #007bff;
           display: flex;
           align-items: center;
           gap: 10px;
       }
       .metrics {
           display: grid;
           grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
           gap: 20px;
           margin: 30px 0;
       }
       .metric {
           text-align: center;
           padding: 20px;
           background: linear-gradient(135deg, #f8f9fa, #e9ecef);
           border-radius: 12px;
           box-shadow: 0 4px 15px rgba(0,0,0,0.1);
           transition: transform 0.3s ease;
       }
       .metric:hover {
           transform: translateY(-5px);
       }
       .metric .number {
           font-size: 2.5em;
           font-weight: bold;
           color: #007bff;
           margin-bottom: 5px;
       }
       .metric .label {
           color: #6c757d;
           font-weight: 500;
       }
       .redis-status {
           display: inline-block;
           padding: 4px 8px;
           border-radius: 4px;
           font-size: 0.8em;
           font-weight: bold;
       }
       .redis-status.connected {
           background: #d4edda;
           color: #155724;
       }
       .redis-status.disconnected {
           background: #f8d7da;
           color: #721c24;
       }
       .redis-key {
           font-family: monospace;
           background: #e9ecef;
           padding: 2px 6px;
           border-radius: 4px;
           font-size: 0.9em;
       }
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
           transition: width 0.5s ease;
           border-radius: 6px;
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
       }
       .btn:hover {
           transform: translateY(-2px);
           box-shadow: 0 4px 15px rgba(0, 123, 255, 0.3);
       }
       .btn.secondary {
           background: linear-gradient(135deg, #6c757d, #495057);
       }
       .btn.danger {
           background: linear-gradient(135deg, #dc3545, #c82333);
       }
       .btn.success {
           background: linear-gradient(135deg, #28a745, #1e7e34);
       }
       .btn.warning {
           background: linear-gradient(135deg, #ffc107, #e0a800);
           color: #212529;
       }
       .table {
           width: 100%;
           border-collapse: collapse;
           margin: 20px 0;
           box-shadow: 0 2px 10px rgba(0,0,0,0.1);
           border-radius: 8px;
           overflow: hidden;
       }
       .table th, .table td {
           border: 1px solid #dee2e6;
           padding: 12px 15px;
           text-align: left;
       }
       .table th {
           background: linear-gradient(135deg, #007bff, #0056b3);
           color: white;
           font-weight: bold;
       }
       .table tr:nth-child(even) {
           background: #f8f9fa;
       }
       .table tr:hover {
           background: #e2e6ea;
       }
       .device-indicator {
           display: inline-flex;
           align-items: center;
           gap: 5px;
           padding: 4px 8px;
           border-radius: 4px;
           font-size: 0.8em;
           font-weight: bold;
       }
       .device-mobile {
           background: #e1f5fe;
           color: #01579b;
       }
       .device-desktop {
           background: #f3e5f5;
           color: #4a148c;
       }
       .hash-display {
           font-family: monospace;
           background: #e9ecef;
           padding: 8px 12px;
           border-radius: 6px;
           border: 1px solid #dee2e6;
           word-break: break-all;
           font-size: 0.9em;
           line-height: 1.4;
       }
       .tabs {
           display: flex;
           background: #f8f9fa;
           border-radius: 8px;
           padding: 5px;
           margin-bottom: 20px;
           flex-wrap: wrap;
       }
       .tab {
           flex: 1;
           text-align: center;
           padding: 10px;
           background: transparent;
           border: none;
           border-radius: 6px;
           cursor: pointer;
           transition: all 0.3s ease;
           min-width: 120px;
           font-size: 0.9em;
       }
       .tab.active {
           background: white;
           box-shadow: 0 2px 4px rgba(0,0,0,0.1);
           color: #007bff;
           font-weight: bold;
       }
       .tab-content {
           display: none;
       }
       .tab-content.active {
           display: block;
       }
       pre {
           background: #2d3748;
           color: #e2e8f0;
           border: 1px solid #4a5568;
           padding: 15px;
           border-radius: 8px;
           overflow-x: auto;
           font-size: 12px;
           font-family: 'Consolas', 'Monaco', monospace;
           max-height: 400px;
       }
       .protection-level {
           display: inline-block;
           padding: 6px 12px;
           border-radius: 20px;
           font-weight: bold;
           font-size: 0.9em;
       }
       .protection-basic {
           background: #fff3cd;
           color: #856404;
       }
       .protection-enhanced {
           background: #d1ecf1;
           color: #0c5460;
       }
       .protection-maximum {
           background: #d4edda;
           color: #155724;
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
       }
   </style>
</head>
<body>
   <div class="container">
       <div class="version-badge">Bot Protection v2.0</div>
       
       <div class="header">
           <h1>🛡️ Redis MurKir Security System v2.0</h1>
           <p>Расширенная система защиты с блокировкой по хешу пользователя</p>
           <div class="redis-status <?php echo $protectionActive ? 'connected' : 'disconnected'; ?>">
               Redis: <?php echo $protectionActive ? 'Connected' : 'Disconnected'; ?>
           </div>
           <div class="device-indicator <?php echo $isMobile ? 'device-mobile' : 'device-desktop'; ?>">
               <?php echo $isMobile ? '📱 Mobile Device' : '🖥️ Desktop Device'; ?>
           </div>
       </div>

       <!-- Статус Redis -->
       <div class="status-card redis">
           <h2>📊 Статус Redis Protection v2.0</h2>
           <?php if ($protectionActive): ?>
               <p><strong>✅ Redis подключен и работает</strong></p>
               <div class="protection-level protection-maximum">🛡️ Максимальная защита активна</div>
               
               <?php if ($redisStats): ?>
                   <div class="metrics">
                       <div class="metric">
                           <div class="number"><?php echo $redisStats['blocked_ips']; ?></div>
                           <div class="label">Заблокированных IP</div>
                       </div>
                       <div class="metric">
                           <div class="number"><?php echo $redisStats['blocked_sessions']; ?></div>
                           <div class="label">Заблокированных сессий</div>
                       </div>
                       <div class="metric">
                           <div class="number"><?php echo $redisStats['blocked_cookies']; ?></div>
                           <div class="label">Заблокированных cookies</div>
                       </div>
                       <div class="metric">
                           <div class="number"><?php echo $redisStats['blocked_user_hashes'] ?? 0; ?></div>
                           <div class="label">Заблокированных хешей</div>
                       </div>
                       <div class="metric">
                           <div class="number"><?php echo $redisStats['user_hash_tracking'] ?? 0; ?></div>
                           <div class="label">Активный трекинг хешей</div>
                       </div>
                       <div class="metric">
                           <div class="number"><?php echo $redisStats['tracking_records']; ?></div>
                           <div class="label">Записей трекинга IP</div>
                       </div>
                   </div>
               <?php endif; ?>
           <?php else: ?>
               <p><strong>❌ Redis недоступен</strong></p>
               <div class="protection-level protection-basic">⚠️ Базовая защита</div>
               <p>Проверьте подключение к Redis серверу. Система защиты не активна.</p>
           <?php endif; ?>
       </div>

       <!-- Статус пользователя -->
       <div class="status-card <?php echo $isVerified ? '' : 'warning'; ?>">
           <h2>👤 Статус пользователя</h2>
           <?php if ($isVerified): ?>
               <p><strong>✅ Верифицированный пользователь</strong></p>
               <div style="margin: 15px 0;">
                   <div><strong>🎯 Уровень доверия:</strong> <?php echo $trustScore; ?>%</div>
                   <div class="progress-bar">
                       <div class="progress-fill" style="width: <?php echo $trustScore; ?>%; background: linear-gradient(90deg, #28a745, #20c997);"></div>
                   </div>
               </div>
               
               <?php if ($trustScore > 70): ?>
                   <div style="color: #28a745; font-weight: bold; margin-top: 10px;">🌟 VIP пользователь - высокий уровень доверия!</div>
               <?php elseif ($visitInfo && (time() - $visitInfo['first_visit']) < 300): ?>
                   <div style="color: #007bff; margin-top: 10px;">👋 Добро пожаловать, новый посетитель!</div>
               <?php else: ?>
                   <div style="color: #6c757d; margin-top: 10px;">👤 Обычный пользователь</div>
               <?php endif; ?>
           <?php else: ?>
               <p><strong>⚠️ Пользователь не верифицирован</strong></p>
               <p>Возможно, система защиты не активна или произошла ошибка.</p>
           <?php endif; ?>
       </div>

       <!-- Информация о хеше пользователя -->
       <?php if ($userHashInfo): ?>
       <div class="status-card user-hash <?php echo $userHashInfo['blocked'] ? 'error' : ''; ?>">
           <h2>🔐 Хеш пользователя (новая функция v2.0)</h2>
           <div class="info-grid">
               <div>
                   <p><strong>Статус хеша:</strong> 
                       <?php if ($userHashInfo['blocked']): ?>
                           <span style="color: #dc3545; font-weight: bold;">🚫 Заблокирован</span>
                       <?php else: ?>
                           <span style="color: #28a745; font-weight: bold;">✅ Активен</span>
                       <?php endif; ?>
                   </p>
                   
                   <p><strong>Хеш пользователя:</strong></p>
                   <div class="hash-display">
                       <?php echo htmlspecialchars(substr($userHashInfo['user_hash'], 0, 32)); ?>...
                   </div>
                   
                   <p><strong>Устройство:</strong> 
                       <span class="device-indicator <?php echo $isMobile ? 'device-mobile' : 'device-desktop'; ?>">
                           <?php echo $isMobile ? '📱 Мобильное' : '🖥️ Десктоп'; ?>
                       </span>
                   </p>
                   
                   <?php if ($userHashInfo['blocked'] && $userHashInfo['block_ttl'] > 0): ?>
                       <p><strong>Время до разблокировки:</strong> <?php echo gmdate('H:i:s', $userHashInfo['block_ttl']); ?></p>
                   <?php endif; ?>
               </div>
               
               <?php if ($userHashInfo['tracking_data']): ?>
               <div>
                   <h4>📊 Данные трекинга хеша:</h4>
                   <table class="table">
                       <tr><td><strong>Запросов:</strong></td><td><?php echo $userHashInfo['tracking_data']['requests'] ?? 0; ?></td></tr>
                       <tr><td><strong>Первый визит:</strong></td><td><?php echo date('H:i:s', $userHashInfo['tracking_data']['first_seen'] ?? time()); ?></td></tr>
                       <tr><td><strong>Последняя активность:</strong></td><td><?php echo date('H:i:s', $userHashInfo['tracking_data']['last_activity'] ?? time()); ?></td></tr>
                       <tr><td><strong>Уникальных IP:</strong></td><td><?php echo count(array_unique($userHashInfo['tracking_data']['ips'] ?? [])); ?></td></tr>
                       <tr><td><strong>Страниц посещено:</strong></td><td><?php echo count(array_unique($userHashInfo['tracking_data']['pages'] ?? [])); ?></td></tr>
                   </table>
               </div>
               <?php endif; ?>
           </div>
           
           <?php if ($userHashInfo['block_data']): ?>
           <div>
               <h4>⚠️ Данные блокировки хеша:</h4>
               <pre><?php echo json_encode($userHashInfo['block_data'], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE); ?></pre>
           </div>
           <?php endif; ?>
       </div>
       <?php endif; ?>

       <!-- Информация о текущем IP -->
       <?php if ($ipInfo): ?>
       <div class="status-card <?php echo $ipInfo['blocked'] ? 'error' : ''; ?>">
           <h2>🌐 Информация о IP адресе</h2>
           <div class="info-grid">
               <div>
                   <p><strong>IP адрес:</strong> <span class="redis-key"><?php echo htmlspecialchars($currentIP); ?></span></p>
                   <p><strong>Статус:</strong> 
                       <?php if ($ipInfo['blocked']): ?>
                           <span style="color: #dc3545; font-weight: bold;">🚫 Заблокирован</span>
                       <?php else: ?>
                           <span style="color: #28a745; font-weight: bold;">✅ Разрешен</span>
                       <?php endif; ?>
                   </p>
                   <?php if ($ipInfo['blocked'] && $ipInfo['ttl'] > 0): ?>
                       <p><strong>Время до разблокировки:</strong> <?php echo gmdate('H:i:s', $ipInfo['ttl']); ?></p>
                   <?php endif; ?>
               </div>
               
               <?php if ($ipInfo['block_data']): ?>
               <div>
                   <h4>Данные блокировки IP:</h4>
                   <pre><?php echo json_encode($ipInfo['block_data'], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE); ?></pre>
               </div>
               <?php endif; ?>
           </div>
           
           <?php if ($ipInfo['tracking_data']): ?>
           <div>
               <h4>Данные трекинга IP:</h4>
               <pre><?php echo json_encode($ipInfo['tracking_data'], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE); ?></pre>
           </div>
           <?php endif; ?>
       </div>
       <?php endif; ?>

       <!-- Метрики сессии -->
       <?php if ($visitInfo): ?>
       <div class="metrics">
           <div class="metric">
               <div class="number"><?php echo $visitInfo['pages_visited']; ?></div>
               <div class="label">Страниц посещено</div>
           </div>
           <div class="metric">
               <div class="number"><?php echo $visitInfo['visit_count']; ?></div>
               <div class="label">Всего визитов</div>
           </div>
           <div class="metric">
               <div class="number"><?php echo round((time() - $visitInfo['first_visit']) / 60, 1); ?></div>
               <div class="label">Минут на сайте</div>
           </div>
           <div class="metric">
               <div class="number"><?php echo $trustScore; ?>%</div>
               <div class="label">Уровень доверия</div>
           </div>
       </div>
       <?php endif; ?>

       <!-- Табы -->
       <div class="tabs">
           <button class="tab active" onclick="showTab('request-info')">🌐 Запрос</button>
           <button class="tab" onclick="showTab('session-info')">🔒 Сессия</button>
           <button class="tab" onclick="showTab('redis-keys')">🔑 Redis ключи</button>
           <button class="tab" onclick="showTab('ttl-settings')">⏱️ TTL настройки</button>
           <button class="tab" onclick="showTab('testing')">🧪 Тестирование</button>
           <button class="tab" onclick="showTab('debug')">🔍 Debug</button>
       </div>

       <!-- Информация о запросе -->
       <div id="request-info" class="tab-content active">
           <div class="info-box">
               <h3>🌐 Детали запроса</h3>
               <table class="table">
                   <tr><td><strong>IP адрес:</strong></td><td><span class="redis-key"><?php echo htmlspecialchars($currentIP); ?></span></td></tr>
                   <tr><td><strong>User-Agent:</strong></td><td><?php echo htmlspecialchars(substr($currentUA, 0, 80)) . (strlen($currentUA) > 80 ? '...' : ''); ?></td></tr>
                   <tr><td><strong>Устройство:</strong></td><td><?php echo $isMobile ? '📱 Мобильное устройство' : '🖥️ Десктопное устройство'; ?></td></tr>
                   <tr><td><strong>Метод:</strong></td><td><?php echo $_SERVER['REQUEST_METHOD'] ?? 'GET'; ?></td></tr>
                   <tr><td><strong>Время:</strong></td><td><?php echo date('Y-m-d H:i:s'); ?></td></tr>
                   <tr><td><strong>Session ID:</strong></td><td><span class="redis-key"><?php echo substr(session_id(), 0, 16); ?>...</span></td></tr>
                   <tr><td><strong>URI:</strong></td><td><?php echo htmlspecialchars($_SERVER['REQUEST_URI'] ?? '/'); ?></td></tr>
                   <tr><td><strong>Referer:</strong></td><td><?php echo htmlspecialchars($_SERVER['HTTP_REFERER'] ?? 'Прямой переход'); ?></td></tr>
               </table>
           </div>
       </div>

       <!-- Сессия -->
       <div id="session-info" class="tab-content">
           <div class="info-box">
               <h3>🔒 Данные сессии</h3>
               <?php if (isset($_SESSION['bot_protection'])): ?>
                   <pre><?php echo json_encode($_SESSION['bot_protection'], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE); ?></pre>
               <?php else: ?>
                   <p style="color: #6c757d;">Данные сессии недоступны</p>
               <?php endif; ?>
           </div>
       </div>

       <!-- Redis ключи -->
       <div id="redis-keys" class="tab-content">
           <div class="info-box">
               <h3>🔑 Redis ключи для текущего пользователя</h3>
               
               <?php if (isset($_COOKIE['visitor_verified'])): ?>
                   <h4>🍪 Visitor Cookie:</h4>
                   <div class="redis-key" style="word-break: break-all; margin-bottom: 15px;">
                       <?php echo htmlspecialchars(substr($_COOKIE['visitor_verified'], 0, 100)); ?>...
                   </div>
               <?php else: ?>
                   <p><strong>❌ Cookie не найдена</strong></p>
               <?php endif; ?>
               
               <h4>📋 Структура Redis ключей:</h4>
               <table class="table">
                   <thead>
                       <tr>
                           <th>Тип ключа</th>
                           <th>Префикс</th>
                           <th>Пример</th>
                           <th>Назначение</th>
                       </tr>
                   </thead>
                   <tbody>
                       <tr>
                           <td>IP Tracking</td>
                           <td>bot_protection:tracking:ip:</td>
                           <td><?php echo substr(hash('md5', $currentIP), 0, 8); ?>...</td>
                           <td>Отслеживание активности IP</td>
                       </tr>
                       <tr>
                           <td>IP Block</td>
                           <td>bot_protection:blocked:ip:</td>
                           <td><?php echo substr(hash('md5', $currentIP), 0, 8); ?>...</td>
                           <td>Блокировка IP адреса</td>
                       </tr>
                       <tr>
                           <td>Session Data</td>
                           <td>bot_protection:session:data:</td>
                           <td><?php echo substr(session_id(), 0, 8); ?>...</td>
                           <td>Данные сессии</td>
                       </tr>
                       <tr>
                           <td>Session Block</td>
                           <td>bot_protection:session:blocked:</td>
                           <td><?php echo substr(session_id(), 0, 8); ?>...</td>
                           <td>Блокировка сессии</td>
                       </tr>
                       <tr style="background: #e3f2fd;">
                           <td><strong>User Hash Block</strong></td>
                           <td>bot_protection:user_hash:blocked:</td>
                           <td><?php echo $userHashInfo ? substr($userHashInfo['user_hash'], 0, 8) . '...' : 'N/A'; ?></td>
                           <td><strong>Блокировка по хешу пользователя (v2.0)</strong></td>
                       </tr>
                       <tr style="background: #e3f2fd;">
                           <td><strong>User Hash Tracking</strong></td>
                           <td>bot_protection:user_hash:tracking:</td>
                           <td><?php echo $userHashInfo ? substr($userHashInfo['user_hash'], 0, 8) . '...' : 'N/A'; ?></td>
                           <td><strong>Трекинг активности хеша (v2.0)</strong></td>
                       </tr>
                       <tr>
                           <td>Cookie Block</td>
                           <td>bot_protection:cookie:blocked:</td>
                           <td>hash_md5...</td>
                           <td>Блокировка cookie</td>
                       </tr>
                       <tr>
                           <td>rDNS Cache</td>
                           <td>bot_protection:rdns:cache:</td>
                           <td><?php echo substr(hash('md5', $currentIP), 0, 8); ?>...</td>
                           <td>Кеш rDNS запросов</td>
                       </tr>
                   </tbody>
               </table>
           </div>
       </div>

       <!-- TTL настройки -->
       <div id="ttl-settings" class="tab-content">
           <div class="info-box">
               <h3>⏱️ TTL настройки системы</h3>
               <?php if ($ttlSettings): ?>
                   <p><strong>Оптимизированные временные настройки (v2.0):</strong></p>
                   <table class="table">
                       <thead>
                           <tr>
                               <th>Параметр</th>
                               <th>Время (сек)</th>
                               <th>Время (читаемо)</th>
                               <th>Описание</th>
                           </tr>
                       </thead>
                       <tbody>
                           <?php foreach ($ttlSettings as $key => $value): ?>
                               <tr>
                                   <td><code><?php echo htmlspecialchars($key); ?></code></td>
                                   <td><?php echo $value; ?></td>
                                   <td>
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
                                           'tracking_ip' => 'Отслеживание IP активности',
                                           'session_data' => 'Данные сессии пользователя',
                                           'session_blocked' => 'Блокировка сессии',
                                           'cookie_blocked' => 'Блокировка cookie',
                                           'ip_blocked' => 'Базовая блокировка IP',
                                           'ip_blocked_repeat' => 'Блокировка повторных нарушителей',
                                           'rdns_cache' => 'Кеш rDNS запросов',
                                           'logs' => 'Хранение логов',
                                           'cleanup_interval' => 'Интервал очистки',
                                           'user_hash_blocked' => 'Блокировка хеша пользователя (v2.0)',
                                           'user_hash_tracking' => 'Трекинг хеша пользователя (v2.0)'
                                       ];
                                       echo $descriptions[$key] ?? 'Другие настройки';
                                       ?>
                                   </td>
                               </tr>
                           <?php endforeach; ?>
                       </tbody>
                   </table>
               <?php else: ?>
                   <p style="color: #6c757d;">TTL настройки недоступны</p>
               <?php endif; ?>
           </div>
       </div>

       <!-- Тестирование -->
       <div id="testing" class="tab-content">
           <div class="info-box">
               <h3>🧪 Тестирование системы v2.0</h3>
               <p>Используйте эти ссылки для тестирования различных сценариев:</p>
               
               <div style="margin: 20px 0;">
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
                   
                   <?php if (isset($_GET['admin']) && $_GET['admin'] === '1'): ?>
                       <a href="redis_test.php" class="btn">👁️ Обычный режим</a>
                   <?php else: ?>
                       <a href="redis_test.php?admin=1" class="btn danger">⚙️ Админ режим</a>
                   <?php endif; ?>
               </div>

               <h4>Команды для тестирования ботов:</h4>
               <pre>
# Тест curl (должен заблокироваться после нескольких запросов)
for i in {1..15}; do
  curl -v "<?php echo (isset($_SERVER['HTTPS']) ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']; ?>"
  sleep 1
done

# Тест с браузерным User-Agent
curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
     -c cookies.txt -b cookies.txt \
     "<?php echo (isset($_SERVER['HTTPS']) ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']; ?>"

# Тест мобильного User-Agent
curl -H "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15" \
     -c mobile_cookies.txt -b mobile_cookies.txt \
     "<?php echo (isset($_SERVER['HTTPS']) ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']; ?>"

# Мониторинг Redis
redis-cli monitor

# Проверка ключей Redis
redis-cli keys "bot_protection:*"

# Проверка хешей пользователей (новое в v2.0)
redis-cli keys "bot_protection:user_hash:*"
               </pre>

               <h4>JavaScript тесты в браузере:</h4>
               <div style="margin: 15px 0;">
                   <button onclick="botProtectionTest.simulateBot()" class="btn warning">🤖 Симулировать бота</button>
                   <button onclick="botProtectionTest.simulateHuman()" class="btn success">👤 Симулировать человека</button>
                   <button onclick="botProtectionTest.testUserHash()" class="btn secondary">🔐 Тест хеша пользователя</button>
                   <button onclick="botProtectionTest.clearLocalData()" class="btn danger">🧹 Очистить данные</button>
               </div>
           </div>
       </div>

       <!-- Debug информация -->
       <div id="debug" class="tab-content">
           <div class="info-box">
               <h3>🔍 Debug информация v2.0</h3>
               
               <h4>Redis Connection Test:</h4>
               <?php
               if ($protectionActive) {
                   echo "<p style='color: green;'>✅ Redis подключение активно</p>";
                   
                   try {
                       $testKey = 'bot_protection:test:' . time();
                       $redis = new Redis();
                       $redis->connect('127.0.0.1', 6379);
                       $redis->setex($testKey, 10, json_encode(['test' => 'data', 'timestamp' => time()]));
                       $testData = $redis->get($testKey);
                       $redis->del($testKey);
                       $redis->close();
                       
                       echo "<p style='color: green;'>✅ Redis операции работают корректно</p>";
                       echo "<pre>" . json_encode(json_decode($testData, true), JSON_PRETTY_PRINT) . "</pre>";
                       
                   } catch (Exception $e) {
                       echo "<p style='color: red;'>❌ Ошибка Redis: " . htmlspecialchars($e->getMessage()) . "</p>";
                   }
               } else {
                   echo "<p style='color: red;'>❌ Redis недоступен</p>";
               }
               ?>
               
               <h4>User Hash Analysis (v2.0):</h4>
               <?php if ($userHashInfo): ?>
                   <pre><?php echo json_encode($userHashInfo, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE); ?></pre>
               <?php else: ?>
                   <p style="color: #6c757d;">Информация о хеше пользователя недоступна</p>
               <?php endif; ?>
               
               <h4>Global User Hash Stats:</h4>
               <?php if ($userHashStats): ?>
                   <pre><?php echo json_encode($userHashStats, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE); ?></pre>
               <?php else: ?>
                   <p style="color: #6c757d;">Статистика хешей недоступна</p>
               <?php endif; ?>
               
               <h4>$_SERVER переменные (HTTP):</h4>
               <pre><?php 
               $serverVars = [];
               foreach ($_SERVER as $key => $value) {
                   if (strpos($key, 'HTTP_') === 0 || in_array($key, ['REMOTE_ADDR', 'REQUEST_URI', 'REQUEST_METHOD', 'QUERY_STRING'])) {
                       $serverVars[$key] = $value;
                   }
               }
               echo json_encode($serverVars, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE); 
               ?></pre>
               
               <h4>Все cookies:</h4>
               <pre><?php echo json_encode($_COOKIE, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE); ?></pre>
               
               <?php if ($protectionActive && $redisStats): ?>
               <h4>Полная статистика Redis v2.0:</h4>
               <pre><?php echo json_encode($redisStats, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE); ?></pre>
               <?php endif; ?>
           </div>
       </div>

       <!-- Административные действия -->
       <?php if (isset($_GET['admin']) && $_GET['admin'] === '1'): ?>
       <div class="info-box">
           <h3>⚙️ Административные действия v2.0</h3>
           <div style="margin: 20px 0;">
               <?php
               if (isset($_GET['action']) && $protectionActive) {
                   switch ($_GET['action']) {
                       case 'unblock_ip':
                           $result = $protection->unblockIP($currentIP);
                           echo "<div class='status-card'>";
                           echo "<strong>Результат разблокировки IP:</strong><br>";
                           echo "IP разблокирован: " . ($result['ip_unblocked'] ? 'Да' : 'Нет') . "<br>";
                           echo "Трекинг очищен: " . ($result['tracking_cleared'] ? 'Да' : 'Нет');
                           echo "</div>";
                           break;
                       case 'unblock_session':
                           $result = $protection->unblockSession(session_id());
                           echo "<div class='status-card'>";
                           echo "<strong>Результат разблокировки сессии:</strong><br>";
                           echo "Сессия разблокирована: " . ($result['session_unblocked'] ? 'Да' : 'Нет') . "<br>";
                           echo "Данные очищены: " . ($result['session_data_cleared'] ? 'Да' : 'Нет');
                           echo "</div>";
                           break;
                       case 'unblock_user_hash':
                           $result = $protection->unblockUserHash();
                           echo "<div class='status-card'>";
                           echo "<strong>Результат разблокировки хеша пользователя:</strong><br>";
                           echo "Хеш разблокирован: " . ($result['unblocked'] ? 'Да' : 'Нет') . "<br>";
                           echo "Трекинг очищен: " . ($result['tracking_cleared'] ? 'Да' : 'Нет');
                           echo "</div>";
                           break;
                       case 'cleanup':
                           $cleaned = $protection->cleanup();
                           echo "<div class='status-card'>";
                           echo "<strong>Очистка выполнена:</strong><br>";
                           echo "Удалено элементов: " . ($cleaned !== false ? $cleaned : 'Ошибка');
                           echo "</div>";
                           break;
                       case 'deep_cleanup':
                           $cleaned = $protection->deepCleanup();
                           echo "<div class='status-card'>";
                           echo "<strong>Глубокая очистка выполнена:</strong><br>";
                           echo "Удалено элементов: " . ($cleaned !== false ? $cleaned : 'Ошибка');
                           echo "</div>";
                           break;
                   }
               }
               ?>
               
               <a href="redis_test.php?admin=1&action=unblock_ip" class="btn success">🔓 Разблокировать IP</a>
               <a href="redis_test.php?admin=1&action=unblock_session" class="btn success">🔓 Разблокировать сессию</a>
               <a href="redis_test.php?admin=1&action=unblock_user_hash" class="btn success">🔐 Разблокировать хеш</a>
               <a href="redis_test.php?admin=1&action=cleanup" class="btn secondary">🧹 Очистка Redis</a>
               <a href="redis_test.php?admin=1&action=deep_cleanup" class="btn warning">🗑️ Глубокая очистка</a>
               <a href="redis-admin.php" class="btn danger">⚙️ Админ панель</a>
               <a href="redis_test.php" class="btn">👁️ Обычный режим</a>
           </div>
       </div>
       <?php endif; ?>

       <!-- Обработка тяжелых операций -->
       <?php if (isset($_GET['heavy'])): ?>
       <div class="status-card">
           <h3>⚡ Тяжелая операция</h3>
           <?php
           $start = microtime(true);
           usleep(500000); // 0.5 секунды
           $end = microtime(true);
           $duration = round(($end - $start) * 1000, 2);
           
           echo "<p>✅ Операция выполнена за {$duration} мс</p>";
           echo "<p>Время: " . date('H:i:s') . "</p>";
           ?>
       </div>
       <?php endif; ?>

       <hr style="margin: 40px 0; border: none; height: 1px; background: linear-gradient(90deg, transparent, #dee2e6, transparent);">
       
       <p style="text-align: center; color: #6c757d;">
           <small>
               🛡️ Redis MurKir Security System v2.0 with User Hash Support | 
               Generated: <?php echo date('Y-m-d H:i:s'); ?> | 
               PHP: <?php echo PHP_VERSION; ?> | 
               Session: <?php echo substr(session_id(), 0, 8); ?>... |
               Redis: <?php echo $protectionActive ? 'Active' : 'Inactive'; ?> |
               Device: <?php echo $isMobile ? 'Mobile' : 'Desktop'; ?>
           </small>
       </p>
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

       // Активность пользователя для демонстрации человеческого поведения
       let userActivity = {
           mouseMovements: 0,
           clicks: 0,
           scrolls: 0,
           keyPresses: 0,
           startTime: Date.now(),
           lastActivity: Date.now()
       };

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

       // Обновление прогресс-баров
       function updateProgressBars() {
           document.querySelectorAll('.progress-fill').forEach(bar => {
               const width = parseInt(bar.style.width);
               if (width > 0) {
                   bar.style.width = width + '%';
               }
           });
       }

       // Анимация метрик
       function animateMetrics() {
           document.querySelectorAll('.metric .number').forEach(element => {
               const finalValue = parseInt(element.textContent);
               let currentValue = 0;
               const increment = finalValue / 20;
               
               const timer = setInterval(() => {
                   currentValue += increment;
                   if (currentValue >= finalValue) {
                       currentValue = finalValue;
                       clearInterval(timer);
                   }
                   element.textContent = Math.floor(currentValue);
               }, 50);
           });
       }

       // Кастомные функции для тестирования v2.0
       window.botProtectionTest = {
           // Симуляция bot-подобного поведения
           simulateBot: function() {
               console.log('🤖 Simulating bot behavior...');
               for(let i = 0; i < 20; i++) {
                   setTimeout(() => {
                       fetch(window.location.href + '?bot_test=' + i + '&timestamp=' + Date.now())
                           .then(response => console.log(`Bot request ${i}: ${response.status}`))
                           .catch(err => console.log(`Bot request ${i} failed:`, err));
                   }, i * 100);
               }
           },
           
           // Симуляция человеческого поведения
           simulateHuman: function() {
               console.log('👤 Simulating human behavior...');
               const pages = ['?page=1', '?page=2', '?page=3', '?about=1', '?contact=1'];
               
               pages.forEach((page, index) => {
                   setTimeout(() => {
                       fetch(window.location.origin + window.location.pathname + page + '&human_test=' + index)
                           .then(response => console.log(`Human request ${index}: ${response.status}`))
                           .catch(err => console.log(`Human request ${index} failed:`, err));
                   }, index * 2000 + Math.random() * 1000); // Случайные интервалы
               });
           },
           
           // Тест хеша пользователя
           testUserHash: function() {
               console.log('🔐 Testing user hash...');
               fetch(window.location.href + '?hash_test=1&timestamp=' + Date.now())
                   .then(response => response.text())
                   .then(data => {
                       console.log('User hash test completed');
                       this.showNotification('🔐 Тест хеша пользователя выполнен', 'info');
                   })
                   .catch(err => console.log('Hash test failed:', err));
           },
           
           // Получение статистики Redis v2.0
           getRedisStats: function() {
               return <?php echo json_encode($redisStats); ?>;
           },
           
           // Информация о текущем IP
           getCurrentIPInfo: function() {
               return <?php echo json_encode($ipInfo); ?>;
           },
           
           // Информация о хеше пользователя
           getUserHashInfo: function() {
               return <?php echo json_encode($userHashInfo); ?>;
           },
           
           // Очистка локальных данных
           clearLocalData: function() {
               localStorage.clear();
               sessionStorage.clear();
               console.log('🧹 Local storage cleared');
               this.showNotification('🧹 Локальные данные очищены', 'success');
           },
           
           // Показ уведомлений
           showNotification: function(message, type = 'info') {
               const notification = document.createElement('div');
               notification.style.cssText = `
                   position: fixed;
                   top: 20px;
                   right: 20px;
                   background: ${type === 'error' ? '#dc3545' : type === 'success' ? '#28a745' : '#007bff'};
                   color: white;
                   padding: 15px 25px;
                   border-radius: 8px;
                   font-weight: bold;
                   z-index: 1000;
                   box-shadow: 0 4px 15px rgba(0,0,0,0.2);
                   max-width: 300px;
                   opacity: 0;
                   transform: translateX(100%);
                   transition: all 0.3s ease;
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
               }, 5000);
           }
       };

       // Мониторинг активности пользователя
       setInterval(() => {
           const timeSpent = Math.floor((Date.now() - userActivity.startTime) / 1000);
           const timeSinceLastActivity = Math.floor((Date.now() - userActivity.lastActivity) / 1000);
           
           console.log('👤 User Activity v2.0:', {
               ...userActivity,
               timeSpent: timeSpent + 's',
               timeSinceLastActivity: timeSinceLastActivity + 's',
               activityScore: userActivity.mouseMovements + userActivity.clicks + userActivity.scrolls + userActivity.keyPresses,
               isActive: timeSinceLastActivity < 30
           });
       }, 15000);

       // Автообновление страницы для демонстрации (только в demo режиме)
       if (window.location.search.includes('demo=1')) {
           let countdown = 60;
           const countdownElement = document.createElement('div');
           countdownElement.style.cssText = `
               position: fixed;
               top: 20px;
               left: 20px;
               background: rgba(0, 123, 255, 0.9);
               color: white;
               padding: 10px 15px;
               border-radius: 8px;
               font-weight: bold;
               z-index: 1000;
           `;
           document.body.appendChild(countdownElement);

           const updateCountdown = () => {
               countdownElement.textContent = `🔄 Auto-refresh in ${countdown}s`;
               countdown--;
               
               if (countdown < 0) {
                   window.location.reload();
               }
           };

           updateCountdown();
           setInterval(updateCountdown, 1000);
       }

       // Копирование Redis ключей в буфер обмена
       document.querySelectorAll('.redis-key, .hash-display').forEach(element => {
           element.style.cursor = 'pointer';
           element.title = 'Click to copy';
           element.addEventListener('click', () => {
               navigator.clipboard.writeText(element.textContent).then(() => {
                   const original = element.style.background;
                   element.style.background = '#28a745';
                   element.style.color = 'white';
                   setTimeout(() => {
                       element.style.background = original;
                       element.style.color = '';
                   }, 500);
                   botProtectionTest.showNotification('📋 Скопировано в буфер обмена', 'success');
               }).catch(err => {
                   console.log('Copy failed:', err);
               });
           });
       });

       // Запускаем анимации после загрузки
       document.addEventListener('DOMContentLoaded', () => {
           setTimeout(animateMetrics, 300);
           updateProgressBars();
           
           // Показываем приветственное сообщение
           setTimeout(() => {
               <?php if (!$protectionActive): ?>
               botProtectionTest.showNotification('⚠️ Redis недоступен! Система защиты не активна.', 'error');
               <?php elseif ($userHashInfo && $userHashInfo['blocked']): ?>
               botProtectionTest.showNotification('🚫 Ваш хеш пользователя заблокирован системой защиты!', 'error');
               <?php elseif ($ipInfo && $ipInfo['blocked']): ?>
               botProtectionTest.showNotification('🚫 Ваш IP заблокирован системой защиты!', 'error');
               <?php elseif ($isVerified && $trustScore > 70): ?>
               botProtectionTest.showNotification('🌟 Добро пожаловать, VIP пользователь!', 'success');
               <?php elseif ($isMobile): ?>
               botProtectionTest.showNotification('📱 Мобильное устройство обнаружено. Система v2.0 оптимизирована для мобильных!', 'info');
               <?php else: ?>
               botProtectionTest.showNotification('🛡️ Bot Protection v2.0 с поддержкой хеш-блокировки активна!', 'info');
               <?php endif; ?>
           }, 1000);
       });

       // Обработка ошибок JavaScript
       window.addEventListener('error', (e) => {
           console.error('JavaScript Error:', e.error);
           botProtectionTest.showNotification('❌ Произошла ошибка JavaScript', 'error');
       });

       // Детектор бездействия пользователя
       let idleTimer;
       let idleTime = 0;
       const maxIdleTime = 300; // 5 минут

       function resetIdleTimer() {
           idleTime = 0;
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

       resetIdleTimer(); // Инициализируем таймер

       // Мониторинг производительности страницы
       window.addEventListener('load', () => {
           const loadTime = performance.timing.loadEventEnd - performance.timing.navigationStart;
           console.log(`📊 Page load time: ${loadTime}ms`);
           
           if (loadTime > 3000) {
               botProtectionTest.showNotification('⚠️ Страница загружалась медленно (' + Math.round(loadTime/1000) + 's)', 'warning');
           }

           // Показываем информацию о системе
           console.log(`
█▀▀▄ █▀▀█ ▀▀█▀▀   █▀▀█ █▀▀█ █▀▀█ ▀▀█▀▀ █▀▀ █▀▀ ▀▀█▀▀ ─▀─ █▀▀█ █▀▀▄   ▄█    █
█▀▀▄ █  █   █     █  █ █▄▄▀ █  █   █   █▄▄ █     █    ▀█▀ █  █ █  █    █      █
▀▀▀  ▀▀▀▀   ▀     █▀▀▀ ▀ ▀▀ ▀▀▀▀   ▀   ▀▀▀ ▀▀▀   ▀   ▀▀▀ ▀▀▀▀ ▀  ▀   ▀▀▀    ▀

Version 2.0 - User Hash Protection System
Test Page Loaded Successfully!

New Features:
✅ User Hash Blocking & Tracking
✅ Mobile Device Optimization  
✅ Enhanced TTL Settings
✅ Improved Performance
✅ Advanced Analytics

Device: <?php echo $isMobile ? 'Mobile' : 'Desktop'; ?>
Protection: <?php echo $protectionActive ? 'Active' : 'Inactive'; ?>
User Hash: <?php echo $userHashInfo ? (strlen($userHashInfo['user_hash']) > 0 ? 'Generated' : 'N/A') : 'N/A'; ?>
           `);
       });

       // Клавиатурные сочетания
       document.addEventListener('keydown', (e) => {
           if (e.ctrlKey || e.metaKey) {
               switch(e.key) {
                   case 'r':
                       // Разрешаем обычное обновление
                       break;
                   case '1':
                       e.preventDefault();
                       showTab('request-info');
                       break;
                   case '2':
                       e.preventDefault();
                       showTab('session-info');
                       break;
                   case '3':
                       e.preventDefault();
                       showTab('redis-keys');
                       break;
                   case '4':
                       e.preventDefault();
                       showTab('ttl-settings');
                       break;
                   case '5':
                       e.preventDefault();
                       showTab('testing');
                       break;
                   case '6':
                       e.preventDefault();
                       showTab('debug');
                       break;
                   case 'b':
                       e.preventDefault();
                       botProtectionTest.simulateBot();
                       break;
                   case 'h':
                       e.preventDefault();
                       botProtectionTest.simulateHuman();
                       break;
               }
           }
       });

       // Показываем горячие клавиши
       setTimeout(() => {
           botProtectionTest.showNotification('💡 Горячие клавиши: Ctrl+1-6 (табы), Ctrl+B (бот), Ctrl+H (человек)', 'info');
       }, 3000);

       // Живые обновления счетчиков
       function updateCounters() {
           const stats = document.querySelectorAll('.metric .number');
           stats.forEach(stat => {
               const currentValue = parseInt(stat.textContent);
               if (currentValue > 0) {
                   stat.style.animation = 'pulse 0.5s ease-in-out';
                   setTimeout(() => {
                       stat.style.animation = '';
                   }, 500);
               }
           });
       }

       // Добавляем CSS анимацию для hover эффектов
       const style = document.createElement('style');
       style.textContent = `
           @keyframes pulse {
               0% { transform: scale(1); }
               50% { transform: scale(1.05); }
               100% { transform: scale(1); }
           }
           
           .metric:hover .number {
               color: #0056b3;
               transition: color 0.3s ease;
           }
           
           .table tr:hover {
               background: #f1f3f4 !important;
               transform: scale(1.01);
               transition: all 0.2s ease;
           }
           
           .btn:active {
               transform: scale(0.95) translateY(-2px);
           }
           
           .redis-key:hover, .hash-display:hover {
               background: #007bff !important;
               color: white !important;
               transition: all 0.3s ease;
           }
           
           .tab:hover:not(.active) {
               background: rgba(0, 123, 255, 0.1);
               color: #007bff;
           }
           
           .status-card {
               transition: transform 0.3s ease;
           }
           
           .status-card:hover {
               transform: translateY(-2px);
           }
           
           .progress-fill {
               background: linear-gradient(90deg, #28a745, #20c997) !important;
               box-shadow: 0 2px 4px rgba(40, 167, 69, 0.3);
           }
       `;
       document.head.appendChild(style);

       // Функция для тестирования производительности
       window.botProtectionTest.performanceTest = function() {
           console.log('🚀 Starting performance test...');
           const startTime = performance.now();
           
           // Серия быстрых запросов
           const requests = [];
           for (let i = 0; i < 10; i++) {
               requests.push(
                   fetch(window.location.href + '?perf_test=' + i + '&t=' + Date.now())
                       .then(response => ({
                           request: i,
                           status: response.status,
                           time: performance.now() - startTime
                       }))
               );
           }
           
           Promise.all(requests).then(results => {
               console.log('Performance test results:', results);
               const avgTime = results.reduce((sum, r) => sum + r.time, 0) / results.length;
               this.showNotification(`🚀 Тест производительности: ${avgTime.toFixed(2)}ms`, 'info');
           });
       };

       // Функция для анализа хеша пользователя
       window.botProtectionTest.analyzeUserHash = function() {
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
               timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
               timestamp: Date.now()
           };
           
           console.log('🔍 Browser fingerprint analysis:', fingerprint);
           this.showNotification('🔍 Анализ отпечатка браузера выполнен (см. консоль)', 'info');
           
           return fingerprint;
       };

       // Инициализация завершена
       updateCounters();
       
       console.log('🛡️ Bot Protection Test Page v2.0 loaded successfully');
       console.log('Available functions:', Object.keys(window.botProtectionTest));
       console.log('Redis Status:', <?php echo $protectionActive ? 'true' : 'false'; ?>);
       console.log('User Hash Info:', <?php echo json_encode($userHashInfo ? true : false); ?>);
       console.log('Mobile Device:', <?php echo $isMobile ? 'true' : 'false'; ?>);
       
       // Автоматический тест на готовность системы
       setTimeout(() => {
           console.log('🔬 Running system readiness check...');
           
           const checks = {
               redis: <?php echo $protectionActive ? 'true' : 'false'; ?>,
               session: <?php echo $isVerified ? 'true' : 'false'; ?>,
               userHash: <?php echo $userHashInfo ? 'true' : 'false'; ?>,
               protection: true
           };
           
           const passed = Object.values(checks).filter(Boolean).length;
           const total = Object.keys(checks).length;
           
           console.log(`✅ System readiness: ${passed}/${total} checks passed`);
           console.log('Check details:', checks);
           
           if (passed === total) {
               console.log('🎉 All systems operational!');
           } else {
               console.log('⚠️ Some systems may need attention');
           }
       }, 2000);
   </script>
</body>
</html>