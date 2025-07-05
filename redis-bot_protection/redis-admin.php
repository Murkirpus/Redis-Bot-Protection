<?php
// /home/kinoprostor/kinoprostor15.2/dos/bot_protection/redis-admin.php

session_start();

// Настройки авторизации
define('ADMIN_LOGIN', 'murkir');
define('ADMIN_PASSWORD', 'murkir.pp.ua');

// Настройки rDNS
define('ENABLE_RDNS', true); // включить/выключить rDNS
define('RDNS_TIMEOUT', 1); // 1 секунда таймаут
define('RDNS_CACHE_TTL', 3600); // 1 час кеш

// Проверка авторизации
if (isset($_POST['login'])) {
 if ($_POST['username'] === ADMIN_LOGIN && $_POST['password'] === ADMIN_PASSWORD) {
     $_SESSION['admin_logged_in'] = true;
     $_SESSION['admin_login_time'] = time();
     header('Location: ' . $_SERVER['PHP_SELF']);
     exit;
 } else {
     $login_error = 'Неверный логин или пароль';
 }
}

// Выход
if (isset($_GET['logout'])) {
 session_destroy();
 header('Location: ' . $_SERVER['PHP_SELF']);
 exit;
}

// Проверка сессии (таймаут 1 час)
if (isset($_SESSION['admin_logged_in'])) {
 if (time() - $_SESSION['admin_login_time'] > 3600) {
     session_destroy();
     header('Location: ' . $_SERVER['PHP_SELF']);
     exit;
 }
}

$isLoggedIn = isset($_SESSION['admin_logged_in']) && $_SESSION['admin_logged_in'];

// Подключение к Redis
$redis = null;
$redisError = null;

if ($isLoggedIn) {
 try {
     $redis = new Redis();
     $redis->connect('127.0.0.1', 6379);
     $redis->setOption(Redis::OPT_SERIALIZER, Redis::SERIALIZER_JSON);
     //$redis->setOption(Redis::OPT_PREFIX, 'bot_protection:');
 } catch (Exception $e) {
     $redisError = $e->getMessage();
 }
}

// Функция быстрого rDNS с кешированием
function getRDNSFast($redis, $ip) {
   // Проверяем состояние rDNS из Redis (с fallback на константу)
   $rdnsEnabled = $redis->get('bot_protection:config:rdns_enabled');
   if ($rdnsEnabled === false) {
       $rdnsEnabled = ENABLE_RDNS;
   }
   
   // Если rDNS отключен
   if (!$rdnsEnabled) {
       return 'rDNS disabled';
   }
   
   // Проверяем валидность IP
   if (empty($ip) || $ip === 'unknown') {
       return 'N/A';
   }
   
   // Ключ для кеша
   $cacheKey = 'bot_protection:rdns:cache:' . $ip;
   
   // Проверяем кеш
   $cached = $redis->get($cacheKey);
   if ($cached !== false) {
       return $cached;
   }
   
   // Засекаем время начала запроса
   $start = microtime(true);
   
   // Делаем rDNS запрос с подавлением ошибок
   $hostname = @gethostbyaddr($ip);
   
   // Вычисляем длительность запроса
   $duration = microtime(true) - $start;
   
   // Проверяем результат и таймаут
   if ($duration > RDNS_TIMEOUT || $hostname === $ip || $hostname === false) {
       $hostname = 'Timeout/N/A';
   }
   
   // Кешируем результат (даже если это Timeout/N/A)
   $redis->setex($cacheKey, RDNS_CACHE_TTL, $hostname);
   
   return $hostname;
}

// Функции для работы с Redis
function getBlockedIPs($redis) {
  if (!$redis) return [];
  
  $blockedIPs = [];
  // Используем полное имя ключа с префиксом
  $keys = $redis->keys('bot_protection:blocked:ip:*');
  
  foreach ($keys as $key) {
      $data = $redis->get($key);
      if ($data) {
          $ttl = $redis->ttl($key);
          $data['ttl'] = $ttl;
          $data['key'] = $key;
          
          // Получаем rDNS с кешированием
          if (isset($data['ip'])) {
              $data['hostname'] = getRDNSFast($redis, $data['ip']);
          }
          
          $blockedIPs[] = $data;
      }
  }
  
  usort($blockedIPs, function($a, $b) {
      return ($b['blocked_at'] ?? 0) - ($a['blocked_at'] ?? 0);
  });
  
  return $blockedIPs;
}

function getBlockedSessions($redis) {
  if (!$redis) return [];
  
  $blockedSessions = [];
  $keys = $redis->keys('bot_protection:session:blocked:*');
  
  foreach ($keys as $key) {
      $data = $redis->get($key);
      if ($data) {
          $ttl = $redis->ttl($key);
          $data['ttl'] = $ttl;
          $data['key'] = $key;
          $blockedSessions[] = $data;
      }
  }
  
  usort($blockedSessions, function($a, $b) {
      return ($b['blocked_at'] ?? 0) - ($a['blocked_at'] ?? 0);
  });
  
  return $blockedSessions;
}

function getBlockedCookies($redis) {
  if (!$redis) return [];
  
  $blockedCookies = [];
  $keys = $redis->keys('bot_protection:cookie:blocked:*');
  
  foreach ($keys as $key) {
      $data = $redis->get($key);
      if ($data) {
          $ttl = $redis->ttl($key);
          $data['ttl'] = $ttl;
          $data['key'] = $key;
          $blockedCookies[] = $data;
      }
  }
  
  usort($blockedCookies, function($a, $b) {
      return ($b['blocked_at'] ?? 0) - ($a['blocked_at'] ?? 0);
  });
  
  return $blockedCookies;
}

function getBlockedUserHashes($redis) {
  if (!$redis) return [];
  
  $blockedHashes = [];
  $keys = $redis->keys('bot_protection:user_hash:blocked:*');
  
  foreach ($keys as $key) {
      $data = $redis->get($key);
      if ($data) {
          $ttl = $redis->ttl($key);
          $data['ttl'] = $ttl;
          $data['key'] = $key;
          
          // Извлекаем хеш из ключа
          $hashPart = str_replace('bot_protection:user_hash:blocked:', '', $key);
          $data['hash_short'] = substr($hashPart, 0, 12);
          $data['hash_full'] = $hashPart;
          
          // Получаем rDNS если есть IP
          if (isset($data['ip'])) {
              $data['hostname'] = getRDNSFast($redis, $data['ip']);
          } else {
              $data['hostname'] = 'N/A';
          }
          
          $blockedHashes[] = $data;
      }
  }
  
  usort($blockedHashes, function($a, $b) {
      return ($b['blocked_at'] ?? 0) - ($a['blocked_at'] ?? 0);
  });
  
  return $blockedHashes;
}

function getUserHashTracking($redis) {
  if (!$redis) return [];
  
  $trackingData = [];
  $keys = $redis->keys('bot_protection:user_hash:tracking:*');
  
  foreach ($keys as $key) {
      $data = $redis->get($key);
      if ($data) {
          $ttl = $redis->ttl($key);
          $data['ttl'] = $ttl;
          $data['key'] = $key;
          
          // Извлекаем хеш из ключа
          $hashPart = str_replace('bot_protection:user_hash:tracking:', '', $key);
          $data['hash_short'] = substr($hashPart, 0, 12);
          $data['hash_full'] = $hashPart;
          
          // Обрабатываем массив IP адресов
          if (isset($data['ips']) && is_array($data['ips'])) {
              $data['unique_ips'] = count(array_unique($data['ips']));
              $data['primary_ip'] = $data['ips'][0] ?? 'unknown';
              
              // rDNS для основного IP
              if ($data['primary_ip'] !== 'unknown') {
                  $data['hostname'] = getRDNSFast($redis, $data['primary_ip']);
              } else {
                  $data['hostname'] = 'N/A';
              }
          } else {
              $data['unique_ips'] = 0;
              $data['primary_ip'] = 'unknown';
              $data['hostname'] = 'N/A';
          }
          
          $trackingData[] = $data;
      }
  }
  
  usort($trackingData, function($a, $b) {
      return ($b['last_activity'] ?? 0) - ($a['last_activity'] ?? 0);
  });
  
  return $trackingData;
}

function getUserHashStats($redis) {
  if (!$redis) return [];
  
  $stats = [];
  $keys = $redis->keys('bot_protection:user_hash:stats:*');
  
  foreach ($keys as $key) {
      $data = $redis->hgetall($key);
      if ($data) {
          $hashPart = str_replace('bot_protection:user_hash:stats:', '', $key);
          $data['hash_short'] = substr($hashPart, 0, 12);
          $data['hash_full'] = $hashPart;
          $data['key'] = $key;
          
          $stats[] = $data;
      }
  }
  
  usort($stats, function($a, $b) {
      return ($b['last_blocked'] ?? 0) - ($a['last_blocked'] ?? 0);
  });
  
  return $stats;
}

function getTrackingData($redis) {
  if (!$redis) return [];
  
  $trackingData = [];
  $keys = $redis->keys('bot_protection:tracking:ip:*');
  
  foreach ($keys as $key) {
      $data = $redis->get($key);
      if ($data) {
          $ttl = $redis->ttl($key);
          $data['ttl'] = $ttl;
          $data['key'] = $key;
          
          // Пытаемся найти IP в данных
          if (!empty($data['headers']['HTTP_CF_CONNECTING_IP'])) {
              $ip = $data['headers']['HTTP_CF_CONNECTING_IP'];
          } elseif (!empty($data['headers']['HTTP_X_REAL_IP'])) {
              $ip = $data['headers']['HTTP_X_REAL_IP'];
          } elseif (!empty($data['headers']['REMOTE_ADDR'])) {
              $ip = $data['headers']['REMOTE_ADDR'];
          } else {
              $ip = 'unknown';
          }
          
          $data['detected_ip'] = $ip;
          if ($ip !== 'unknown') {
              $data['hostname'] = getRDNSFast($redis, $ip);
          } else {
              $data['hostname'] = 'N/A';
          }
          
          $trackingData[] = $data;
      }
  }
  
  usort($trackingData, function($a, $b) {
      return ($b['first_seen'] ?? 0) - ($a['first_seen'] ?? 0);
  });
  
  return $trackingData;
}

function getRedisStats($redis) {
  if (!$redis) return null;
  
  $stats = [
      'blocked_ips' => count($redis->keys('bot_protection:blocked:ip:*')),
      'blocked_sessions' => count($redis->keys('bot_protection:session:blocked:*')),
      'blocked_cookies' => count($redis->keys('bot_protection:cookie:blocked:*')),
      'blocked_user_hashes' => count($redis->keys('bot_protection:user_hash:blocked:*')),
      'tracking_records' => count($redis->keys('bot_protection:tracking:ip:*')),
      'user_hash_tracking' => count($redis->keys('bot_protection:user_hash:tracking:*')),
      'user_hash_stats' => count($redis->keys('bot_protection:user_hash:stats:*')),
      'rdns_cache' => count($redis->keys('bot_protection:rdns:cache:*')),
      'logs_today' => count($redis->keys('bot_protection:logs:*:' . date('Y-m-d'))),
      'memory_usage' => $redis->info('memory')['used_memory_human'] ?? 'N/A',
      'total_keys' => $redis->dbSize()
  ];
  
  return $stats;
}

function getLogs($redis, $type = 'all', $limit = 50) {
  if (!$redis) return [];
  
  $logs = [];
  $today = date('Y-m-d');
  
  $logKeys = [
      'bot_protection:logs:legitimate_bots:' . $today,
      'bot_protection:logs:search_engines:' . $today
  ];
  
  foreach ($logKeys as $logKey) {
      $logEntries = $redis->lrange($logKey, 0, $limit);
      foreach ($logEntries as $entry) {
          if ($entry) {
              $entry['log_type'] = strpos($logKey, 'legitimate_bots') !== false ? 'bot' : 'search_engine';
              $logs[] = $entry;
          }
      }
  }
  
  usort($logs, function($a, $b) {
      $timeA = strtotime($a['timestamp'] ?? '1970-01-01');
      $timeB = strtotime($b['timestamp'] ?? '1970-01-01');
      return $timeB - $timeA;
  });
  
  return array_slice($logs, 0, $limit);
}

// Обработка действий
if ($isLoggedIn && $redis && isset($_POST['action'])) {
 $result = '';
 
 switch ($_POST['action']) {
     case 'toggle_rdns':
         $currentState = $redis->get('bot_protection:config:rdns_enabled');
         $newState = ($currentState === null) ? !ENABLE_RDNS : !$currentState;
         $redis->set('bot_protection:config:rdns_enabled', $newState);
         $result = 'rDNS переключен: ' . ($newState ? 'включен' : 'выключен');
         break;
         
     case 'clear_rdns_cache':
         $keys = $redis->keys('bot_protection:rdns:cache:*');
         $deleted = 0;
         foreach ($keys as $key) {
             $redis->del($key);
             $deleted++;
         }
         $result = "Очищено записей rDNS кеша: $deleted";
         break;
         
     case 'unblock_ip':
         if (isset($_POST['key'])) {
             $deleted = $redis->del($_POST['key']);
             $result = $deleted ? 'IP разблокирован' : 'Ошибка разблокировки';
         }
         break;
         
     case 'unblock_session':
         if (isset($_POST['key'])) {
             $deleted = $redis->del($_POST['key']);
             $result = $deleted ? 'Сессия разблокирована' : 'Ошибка разблокировки';
         }
         break;
         
     case 'unblock_cookie':
         if (isset($_POST['key'])) {
             $deleted = $redis->del($_POST['key']);
             $result = $deleted ? 'Cookie разблокирована' : 'Ошибка разблокировки';
         }
         break;
         
     case 'unblock_user_hash':
         if (isset($_POST['key'])) {
             $deleted = $redis->del($_POST['key']);
             $result = $deleted ? 'Хеш пользователя разблокирован' : 'Ошибка разблокировки';
         }
         break;
         
     case 'clear_tracking':
         if (isset($_POST['key'])) {
             $deleted = $redis->del($_POST['key']);
             $result = $deleted ? 'Данные трекинга удалены' : 'Ошибка удаления';
         }
         break;
         
     case 'clear_user_hash_tracking':
         if (isset($_POST['key'])) {
             $deleted = $redis->del($_POST['key']);
             $result = $deleted ? 'Данные трекинга хеша удалены' : 'Ошибка удаления';
         }
         break;
         
     case 'clear_user_hash_stats':
         if (isset($_POST['key'])) {
             $deleted = $redis->del($_POST['key']);
             $result = $deleted ? 'Статистика хеша удалена' : 'Ошибка удаления';
         }
         break;
         
     case 'cleanup_all':
         $cleaned = 0;
         
         // Очищаем просроченные ключи
         $allKeys = $redis->keys('*');
         foreach ($allKeys as $key) {
             $ttl = $redis->ttl($key);
             if ($ttl === -1) continue; // Ключи без TTL оставляем
             if ($ttl <= 0) {
                 $redis->del($key);
                 $cleaned++;
             }
         }
         
         $result = "Очищено ключей: $cleaned";
         break;
         
     case 'flush_logs':
         $flushed = 0;
         $logKeys = $redis->keys('bot_protection:logs:*');
         foreach ($logKeys as $key) {
             $redis->del($key);
             $flushed++;
         }
         $result = "Удалено логов: $flushed";
         break;
         
     case 'block_manual_session':
         if (isset($_POST['session_id']) && !empty($_POST['session_id'])) {
             $sessionId = $_POST['session_id'];
             $reason = $_POST['reason'] ?? 'Manual admin block';
             
             $blockKey = 'bot_protection:session:blocked:' . $sessionId;
             $blockData = [
                 'session_id' => $sessionId,
                 'blocked_at' => time(),
                 'blocked_reason' => $reason,
                 'blocked_by' => ADMIN_LOGIN,
                 'admin_action' => true
             ];
             
             $redis->setex($blockKey, 21600, $blockData); // 6 hours
             $result = "Сессия $sessionId заблокирована вручную";
         }
         break;
         
     case 'block_manual_ip':
         if (isset($_POST['ip_address']) && !empty($_POST['ip_address'])) {
             $ip = $_POST['ip_address'];
             $reason = $_POST['reason'] ?? 'Manual admin block';
             
             $blockKey = 'bot_protection:blocked:ip:' . hash('md5', $ip);
             $blockData = [
                 'ip' => $ip,
                 'blocked_at' => time(),
                 'blocked_reason' => $reason,
                 'blocked_by' => ADMIN_LOGIN,
                 'admin_action' => true,
                 'user_agent' => 'Manual block',
                 'session_id' => 'manual',
                 'repeat_offender' => false
             ];
             
             $redis->setex($blockKey, 7200, $blockData); // 2 hours
             $result = "IP $ip заблокирован вручную";
         }
         break;
 }
}

// Получаем данные для отображения
if ($isLoggedIn && $redis) {
 $blockedIPs = getBlockedIPs($redis);
 $blockedSessions = getBlockedSessions($redis);
 $blockedCookies = getBlockedCookies($redis);
 $blockedUserHashes = getBlockedUserHashes($redis);
 $userHashTracking = getUserHashTracking($redis);
 $userHashStats = getUserHashStats($redis);
 $trackingData = getTrackingData($redis);
 $redisStats = getRedisStats($redis);
 $logs = getLogs($redis);
 
 // Проверяем текущее состояние rDNS
 $rdnsCurrentState = $redis->get('bot_protection:config:rdns_enabled');
 if ($rdnsCurrentState === false) $rdnsCurrentState = ENABLE_RDNS;
}
?>
<!DOCTYPE html>
<html lang="ru">
<head>
 <meta charset="UTF-8">
 <meta name="viewport" content="width=device-width, initial-scale=1.0">
 <title>🛡️ Redis MurKir Security - Admin Panel v2.0</title>
 <style>
     * {
         box-sizing: border-box;
         margin: 0;
         padding: 0;
     }

     body {
         font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
         background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
         min-height: 100vh;
         color: #333;
     }

     .login-container {
         display: flex;
         justify-content: center;
         align-items: center;
         min-height: 100vh;
         padding: 20px;
     }

     .login-form {
         background: white;
         padding: 40px;
         border-radius: 15px;
         box-shadow: 0 10px 30px rgba(0,0,0,0.2);
         max-width: 400px;
         width: 100%;
     }

     .login-form h1 {
         text-align: center;
         margin-bottom: 30px;
         color: #007bff;
     }

     .form-group {
         margin-bottom: 20px;
     }

     .form-group label {
         display: block;
         margin-bottom: 5px;
         font-weight: bold;
     }

     .form-group input {
         width: 100%;
         padding: 12px;
         border: 1px solid #ddd;
         border-radius: 8px;
         font-size: 16px;
     }

     .btn {
         background: linear-gradient(135deg, #007bff, #0056b3);
         color: white;
         padding: 12px 24px;
         border: none;
         border-radius: 8px;
         cursor: pointer;
         font-size: 16px;
         transition: all 0.3s ease;
         text-decoration: none;
         display: inline-block;
         margin: 5px;
     }

     .btn:hover {
         transform: translateY(-2px);
         box-shadow: 0 4px 15px rgba(0, 123, 255, 0.3);
     }

     .btn.btn-danger {
         background: linear-gradient(135deg, #dc3545, #c82333);
     }

     .btn.btn-success {
         background: linear-gradient(135deg, #28a745, #1e7e34);
     }

     .btn.btn-warning {
         background: linear-gradient(135deg, #ffc107, #e0a800);
         color: #212529;
     }

     .btn.btn-secondary {
         background: linear-gradient(135deg, #6c757d, #495057);
     }

     .btn.btn-info {
         background: linear-gradient(135deg, #17a2b8, #138496);
     }

     .btn-small {
         padding: 6px 12px;
         font-size: 12px;
     }

     .admin-container {
         max-width: 1400px;
         margin: 0 auto;
         padding: 20px;
     }

     .header {
         background: white;
         padding: 20px;
         border-radius: 15px;
         box-shadow: 0 4px 15px rgba(0,0,0,0.1);
         margin-bottom: 20px;
         display: flex;
         justify-content: space-between;
         align-items: center;
     }

     .stats-grid {
         display: grid;
         grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
         gap: 20px;
         margin-bottom: 30px;
     }

     .stat-card {
         background: white;
         padding: 20px;
         border-radius: 12px;
         box-shadow: 0 4px 15px rgba(0,0,0,0.1);
         text-align: center;
         transition: transform 0.3s ease;
     }

     .stat-card:hover {
         transform: translateY(-5px);
     }

     .stat-number {
         font-size: 2.5em;
         font-weight: bold;
         color: #007bff;
         margin-bottom: 5px;
     }

     .stat-label {
         color: #6c757d;
         font-weight: 500;
     }

     .section {
         background: white;
         margin-bottom: 30px;
         border-radius: 15px;
         box-shadow: 0 4px 15px rgba(0,0,0,0.1);
         overflow: hidden;
     }

     .section-header {
         background: linear-gradient(135deg, #007bff, #0056b3);
         color: white;
         padding: 20px;
         font-size: 1.2em;
         font-weight: bold;
         display: flex;
         justify-content: space-between;
         align-items: center;
     }

     .section-content {
         padding: 20px;
     }

     .table {
         width: 100%;
         border-collapse: collapse;
         margin-top: 10px;
     }

     .table th,
     .table td {
         padding: 12px;
         text-align: left;
         border-bottom: 1px solid #dee2e6;
     }

     .table th {
         background: #f8f9fa;
         font-weight: bold;
         color: #495057;
     }

     .table tr:hover {
         background: #f8f9fa;
     }

     .status-badge {
         padding: 4px 8px;
         border-radius: 4px;
         font-size: 0.8em;
         font-weight: bold;
     }

     .status-blocked {
         background: #f8d7da;
         color: #721c24;
     }

     .status-tracking {
         background: #fff3cd;
         color: #856404;
     }

     .status-active {
         background: #d4edda;
         color: #155724;
     }

     .status-user-hash {
         background: #e2e3e5;
         color: #383d41;
     }

     .ip-info {
         font-family: monospace;
         background: #f8f9fa;
         padding: 4px 8px;
         border-radius: 4px;
         font-size: 0.9em;
     }

     .error-message {
         background: #f8d7da;
         color: #721c24;
         padding: 15px;
         border-radius: 8px;
         border: 1px solid #f5c6cb;
         margin-bottom: 20px;
     }

     .success-message {
         background: #d4edda;
         color: #155724;
         padding: 15px;
         border-radius: 8px;
         border: 1px solid #c3e6cb;
         margin-bottom: 20px;
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

     .actions {
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

     .manual-block-form {
         background: #f8f9fa;
         padding: 20px;
         border-radius: 8px;
         margin-bottom: 20px;
     }

     .manual-block-form h4 {
         margin-bottom: 15px;
         color: #495057;
     }

     .form-row {
         display: flex;
         gap: 10px;
         margin-bottom: 15px;
     }

     .form-row input {
         flex: 1;
         padding: 8px 12px;
         border: 1px solid #ddd;
         border-radius: 6px;
     }

     .version-info {
         position: fixed;
         top: 10px;
         left: 10px;
         background: rgba(0, 123, 255, 0.9);
         color: white;
         padding: 5px 10px;
         border-radius: 15px;
         font-size: 0.8em;
         z-index: 1000;
     }

     @media (max-width: 768px) {
         .admin-container {
             padding: 10px;
         }
		 .header {
             flex-direction: column;
             gap: 10px;
         }
         
         .stats-grid {
             grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
         }
         
         .table {
             font-size: 0.9em;
         }
         
         .table th,
         .table td {
             padding: 8px;
         }

         .tabs {
             flex-direction: column;
         }

         .tab {
             flex: none;
             margin: 2px 0;
         }

         .form-row {
             flex-direction: column;
         }
     }
 </style>
</head>
<body>
 <div class="version-info">Bot Protection v2.0</div>
 
 <?php if (!$isLoggedIn): ?>
     <div class="login-container">
         <form class="login-form" method="POST">
             <h1>🛡️ Admin Panel v2.0</h1>
             
             <?php if (isset($login_error)): ?>
                 <div class="error-message">
                     <?php echo htmlspecialchars($login_error); ?>
                 </div>
             <?php endif; ?>
             
             <div class="form-group">
                 <label for="username">Логин:</label>
                 <input type="text" id="username" name="username" required>
             </div>
             
             <div class="form-group">
                 <label for="password">Пароль:</label>
                 <input type="password" id="password" name="password" required>
             </div>
             
             <button type="submit" name="login" class="btn" style="width: 100%;">
                 🔐 Войти
             </button>
         </form>
     </div>
 <?php else: ?>
     <div class="admin-container">
         <div class="header">
             <div>
                 <h1>🛡️ Redis MurKir Security - Admin Panel v2.0</h1>
                 <p>Logged in as: <strong><?php echo ADMIN_LOGIN; ?></strong> | 
                    Session expires: <?php echo date('H:i:s', $_SESSION['admin_login_time'] + 3600); ?></p>
             </div>
             <div>
                 <a href="redis_test.php" class="btn btn-secondary">📊 Test Page</a>
                 <a href="?logout=1" class="btn btn-danger">🚪 Выйти</a>
             </div>
         </div>

         <?php if ($redisError): ?>
             <div class="error-message">
                 <strong>Ошибка подключения к Redis:</strong> <?php echo htmlspecialchars($redisError); ?>
             </div>
         <?php endif; ?>
   	  <?php if (isset($result) && $result): ?>
             <div class="success-message">
                 <?php echo htmlspecialchars($result); ?>
             </div>
         <?php endif; ?>

         <?php if ($redis): ?>
             <!-- Статистика -->
             <div class="stats-grid">
                 <div class="stat-card">
                     <div class="stat-number"><?php echo $redisStats['blocked_ips']; ?></div>
                     <div class="stat-label">Заблокированных IP</div>
                 </div>
                 <div class="stat-card">
                     <div class="stat-number"><?php echo $redisStats['blocked_sessions']; ?></div>
                     <div class="stat-label">Заблокированных сессий</div>
                 </div>
                 <div class="stat-card">
                     <div class="stat-number"><?php echo $redisStats['blocked_cookies']; ?></div>
                     <div class="stat-label">Заблокированных cookies</div>
                 </div>
                 <div class="stat-card">
                     <div class="stat-number"><?php echo $redisStats['blocked_user_hashes']; ?></div>
                     <div class="stat-label">Заблокированных хешей</div>
                 </div>
                 <div class="stat-card">
                     <div class="stat-number"><?php echo $redisStats['tracking_records']; ?></div>
                     <div class="stat-label">Записей трекинга IP</div>
                 </div>
                 <div class="stat-card">
                     <div class="stat-number"><?php echo $redisStats['user_hash_tracking']; ?></div>
                     <div class="stat-label">Трекинг хешей</div>
                 </div>
                 <div class="stat-card">
                     <div class="stat-number"><?php echo $redisStats['rdns_cache']; ?></div>
                     <div class="stat-label">rDNS кеш</div>
                 </div>
                 <div class="stat-card">
                     <div class="stat-number"><?php echo $redisStats['total_keys']; ?></div>
                     <div class="stat-label">Всего ключей Redis</div>
                 </div>
                 <div class="stat-card">
                     <div class="stat-number"><?php echo $redisStats['memory_usage']; ?></div>
                     <div class="stat-label">Использование памяти</div>
                 </div>
             </div>

             <!-- Глобальные действия -->
             <div class="section">
                 <div class="section-header">
                     ⚙️ Управление системой
                 </div>
                 <div class="section-content">
                     <div class="actions">
                         <form method="POST" style="display: inline;" onsubmit="return confirm('Вы уверены?');">
                             <input type="hidden" name="action" value="cleanup_all">
                             <button type="submit" class="btn btn-warning">🧹 Очистить просроченные ключи</button>
                         </form>
                         
                         <form method="POST" style="display: inline;" onsubmit="return confirm('Удалить ВСЕ логи?');">
                             <input type="hidden" name="action" value="flush_logs">
                             <button type="submit" class="btn btn-secondary">🗑️ Очистить логи</button>
                         </form>
                         
                         <form method="POST" style="display: inline;">
                             <input type="hidden" name="action" value="toggle_rdns">
                             <button type="submit" class="btn btn-info">
                                 🌐 rDNS: <?php echo $rdnsCurrentState ? 'ON' : 'OFF'; ?>
                             </button>
                         </form>
                         
                         <form method="POST" style="display: inline;" onsubmit="return confirm('Очистить весь rDNS кеш?');">
                             <input type="hidden" name="action" value="clear_rdns_cache">
                             <button type="submit" class="btn btn-secondary">🗑️ Очистить rDNS кеш</button>
                         </form>
                         
                         <button onclick="location.reload()" class="btn">🔄 Обновить</button>
                     </div>

                     <!-- Ручная блокировка -->
                     <div class="manual-block-form">
                         <h4>🔨 Ручная блокировка</h4>
                         
                         <div class="form-row">
                             <form method="POST" style="display: contents;">
                                 <input type="hidden" name="action" value="block_manual_ip">
                                 <input type="text" name="ip_address" placeholder="IP адрес для блокировки" required>
                                 <input type="text" name="reason" placeholder="Причина блокировки" value="Manual admin block">
                                 <button type="submit" class="btn btn-danger btn-small">🚫 Заблокировать IP</button>
                             </form>
                         </div>
                         
                         <div class="form-row">
                             <form method="POST" style="display: contents;">
                                 <input type="hidden" name="action" value="block_manual_session">
                                 <input type="text" name="session_id" placeholder="Session ID для блокировки" required>
                                 <input type="text" name="reason" placeholder="Причина блокировки" value="Manual admin block">
                                 <button type="submit" class="btn btn-danger btn-small">🔒 Заблокировать сессию</button>
                             </form>
                         </div>
                     </div>
                 </div>
             </div>

             <!-- Табы -->
             <div class="tabs">
                 <button class="tab active" onclick="showTab('blocked-ips')">🚫 IP</button>
                 <button class="tab" onclick="showTab('blocked-sessions')">🔒 Сессии</button>
                 <button class="tab" onclick="showTab('blocked-cookies')">🍪 Cookies</button>
                 <button class="tab" onclick="showTab('blocked-user-hashes')">👤 Хеши</button>
                 <button class="tab" onclick="showTab('user-hash-tracking')">📊 Трекинг хешей</button>
                 <button class="tab" onclick="showTab('tracking')">📈 Трекинг IP</button>
                 <button class="tab" onclick="showTab('logs')">📝 Логи</button>
             </div>

             <!-- Заблокированные IP -->
             <div id="blocked-ips" class="tab-content active">
                 <div class="section">
                     <div class="section-header">
                         🚫 Заблокированные IP адреса (<?php echo count($blockedIPs); ?>)
                     </div>
                     <div class="section-content">
                         <input type="text" class="search-box" placeholder="🔍 Поиск по IP или hostname..." onkeyup="filterTable(this, 'blocked-ips-table')">
                         
                         <table class="table" id="blocked-ips-table">
                             <thead>
                                 <tr>
                                     <th>IP адрес</th>
                                     <th>Hostname (rDNS)</th>
                                     <th>Заблокирован</th>
                                     <th>TTL</th>
                                     <th>User-Agent</th>
                                     <th>Повторное нарушение</th>
                                     <th>Действия</th>
                                 </tr>
                             </thead>
                             <tbody>
                                 <?php foreach ($blockedIPs as $ip): ?>
                                     <tr>
                                         <td>
                                             <span class="ip-info"><?php echo htmlspecialchars($ip['ip']); ?></span>
                                         </td>
                                         <td>
                                             <?php if ($ip['hostname'] !== 'N/A' && $ip['hostname'] !== 'Timeout/N/A' && $ip['hostname'] !== 'rDNS disabled'): ?>
                                                 <span title="<?php echo htmlspecialchars($ip['hostname']); ?>">
                                                     <?php echo htmlspecialchars(substr($ip['hostname'], 0, 30)); ?>
                                                     <?php if (strlen($ip['hostname']) > 30) echo '...'; ?>
                                                 </span>
                                             <?php else: ?>
                                                 <span style="color: #6c757d;"><?php echo htmlspecialchars($ip['hostname']); ?></span>
                                             <?php endif; ?>
                                         </td>
                                         <td><?php echo date('Y-m-d H:i:s', $ip['blocked_at']); ?></td>
                                         <td>
                                             <?php if ($ip['ttl'] > 0): ?>
                                                 <span class="status-badge status-blocked">
                                                     <?php echo gmdate('H:i:s', $ip['ttl']); ?>
                                                 </span>
                                             <?php else: ?>
                                                 <span class="status-badge status-active">Постоянно</span>
                                             <?php endif; ?>
                                         </td>
                                         <td>
                                             <span title="<?php echo htmlspecialchars($ip['user_agent']); ?>">
                                                 <?php echo htmlspecialchars(substr($ip['user_agent'], 0, 40)); ?>
                                                 <?php if (strlen($ip['user_agent']) > 40) echo '...'; ?>
                                             </span>
                                         </td>
                                         <td>
                                             <?php if ($ip['repeat_offender']): ?>
                                                 <span class="status-badge status-blocked">Да</span>
                                             <?php else: ?>
                                                 <span class="status-badge status-tracking">Нет</span>
                                             <?php endif; ?>
                                         </td>
                                         <td>
                                             <form method="POST" style="display: inline;">
                                                 <input type="hidden" name="action" value="unblock_ip">
                                                 <input type="hidden" name="key" value="<?php echo htmlspecialchars($ip['key']); ?>">
                                                 <button type="submit" class="btn btn-success btn-small" onclick="return confirm('Разблокировать IP?');">
                                                     🔓 Разблокировать
                                                 </button>
                                             </form>
                                         </td>
                                     </tr>
                                 <?php endforeach; ?>
                             </tbody>
                         </table>
                         
                         <?php if (empty($blockedIPs)): ?>
                             <p style="text-align: center; color: #6c757d; padding: 20px;">
                                 ✅ Нет заблокированных IP адресов
                             </p>
                         <?php endif; ?>
                     </div>
                 </div>
             </div>

             <!-- Заблокированные сессии -->
             <div id="blocked-sessions" class="tab-content">
                 <div class="section">
                     <div class="section-header">
                         🔒 Заблокированные сессии (<?php echo count($blockedSessions); ?>)
                     </div>
                     <div class="section-content">
                         <input type="text" class="search-box" placeholder="🔍 Поиск по Session ID или IP..." onkeyup="filterTable(this, 'blocked-sessions-table')">
                         
                         <table class="table" id="blocked-sessions-table">
                             <thead>
                                 <tr>
                                     <th>Session ID</th>
                                     <th>IP адрес</th>
                                     <th>Заблокирован</th>
                                     <th>TTL</th>
                                     <th>User-Agent</th>
                                     <th>Причина</th>
                                     <th>Действия</th>
                                 </tr>
                             </thead>
                             <tbody>
                                 <?php foreach ($blockedSessions as $session): ?>
                                     <tr>
                                         <td>
                                             <span class="ip-info" title="<?php echo htmlspecialchars($session['session_id']); ?>">
                                                 <?php echo htmlspecialchars(substr($session['session_id'], 0, 16)); ?>...
                                             </span>
                                         </td>
                                         <td>
                                             <span class="ip-info"><?php echo htmlspecialchars($session['ip']); ?></span>
                                         </td>
                                         <td><?php echo date('Y-m-d H:i:s', $session['blocked_at']); ?></td>
                                         <td>
                                             <?php if ($session['ttl'] > 0): ?>
                                                 <span class="status-badge status-blocked">
                                                     <?php echo gmdate('H:i:s', $session['ttl']); ?>
                                                 </span>
                                             <?php else: ?>
                                                 <span class="status-badge status-active">Постоянно</span>
                                             <?php endif; ?>
                                         </td>
                                         <td>
                                             <span title="<?php echo htmlspecialchars($session['user_agent']); ?>">
                                                 <?php echo htmlspecialchars(substr($session['user_agent'], 0, 40)); ?>
                                                 <?php if (strlen($session['user_agent']) > 40) echo '...'; ?>
                                             </span>
                                         </td>
                                         <td><?php echo htmlspecialchars($session['blocked_reason']); ?></td>
                                         <td>
                                             <form method="POST" style="display: inline;">
                                                 <input type="hidden" name="action" value="unblock_session">
                                                 <input type="hidden" name="key" value="<?php echo htmlspecialchars($session['key']); ?>">
                                                 <button type="submit" class="btn btn-success btn-small" onclick="return confirm('Разблокировать сессию?');">
                                                     🔓 Разблокировать
                                                 </button>
                                             </form>
                                         </td>
                                     </tr>
                                 <?php endforeach; ?>
                             </tbody>
                         </table>
                         
                         <?php if (empty($blockedSessions)): ?>
                             <p style="text-align: center; color: #6c757d; padding: 20px;">
                                 ✅ Нет заблокированных сессий
                             </p>
                         <?php endif; ?>
                     </div>
                 </div>
             </div>

             <!-- Заблокированные cookies -->
             <div id="blocked-cookies" class="tab-content">
                 <div class="section">
                     <div class="section-header">
                         🍪 Заблокированные cookies (<?php echo count($blockedCookies); ?>)
                     </div>
                     <div class="section-content">
                         <input type="text" class="search-box" placeholder="🔍 Поиск по IP или hash..." onkeyup="filterTable(this, 'blocked-cookies-table')">
                         
                         <table class="table" id="blocked-cookies-table">
                             <thead>
                                 <tr>
                                     <th>Cookie Hash</th>
                                     <th>IP адрес</th>
                                     <th>Session ID</th>
                                     <th>Заблокирован</th>
                                     <th>TTL</th>
                                     <th>URI</th>
                                     <th>Действия</th>
                                 </tr>
                             </thead>
                             <tbody>
                                 <?php foreach ($blockedCookies as $cookie): ?>
                                     <tr>
                                         <td>
                                             <span class="ip-info" title="<?php echo htmlspecialchars($cookie['cookie_hash']); ?>">
                                                 <?php echo htmlspecialchars(substr($cookie['cookie_hash'], 0, 16)); ?>...
                                             </span>
                                         </td>
                                         <td>
                                             <span class="ip-info"><?php echo htmlspecialchars($cookie['ip']); ?></span>
                                         </td>
                                         <td>
                                             <span class="ip-info" title="<?php echo htmlspecialchars($cookie['session_id']); ?>">
                                                 <?php echo htmlspecialchars(substr($cookie['session_id'], 0, 12)); ?>...
                                             </span>
                                         </td>
                                         <td><?php echo date('Y-m-d H:i:s', $cookie['blocked_at']); ?></td>
                                         <td>
                                             <?php if ($cookie['ttl'] > 0): ?>
                                                 <span class="status-badge status-blocked">
                                                     <?php echo gmdate('H:i:s', $cookie['ttl']); ?>
                                                 </span>
                                             <?php else: ?>
                                                 <span class="status-badge status-active">Постоянно</span>
                                             <?php endif; ?>
                                         </td>
                                         <td>
                                             <span title="<?php echo htmlspecialchars($cookie['uri']); ?>">
                                                 <?php echo htmlspecialchars(substr($cookie['uri'], 0, 30)); ?>
                                                 <?php if (strlen($cookie['uri']) > 30) echo '...'; ?>
                                             </span>
                                         </td>
                                         <td>
                                             <form method="POST" style="display: inline;">
                                                 <input type="hidden" name="action" value="unblock_cookie">
                                                 <input type="hidden" name="key" value="<?php echo htmlspecialchars($cookie['key']); ?>">
                                                 <button type="submit" class="btn btn-success btn-small" onclick="return confirm('Разблокировать cookie?');">
                                                     🔓 Разблокировать
                                                 </button>
                                             </form>
                                         </td>
                                     </tr>
                                 <?php endforeach; ?>
                             </tbody>
                         </table>
                         
                         <?php if (empty($blockedCookies)): ?>
                             <p style="text-align: center; color: #6c757d; padding: 20px;">
                                 ✅ Нет заблокированных cookies
                             </p>
                         <?php endif; ?>
                     </div>
                 </div>
             </div>

             <!-- Заблокированные хеши пользователей -->
             <div id="blocked-user-hashes" class="tab-content">
                 <div class="section">
                     <div class="section-header">
                         👤 Заблокированные хеши пользователей (<?php echo count($blockedUserHashes); ?>)
                     </div>
                     <div class="section-content">
                         <input type="text" class="search-box" placeholder="🔍 Поиск по хешу или IP..." onkeyup="filterTable(this, 'blocked-user-hashes-table')">
                         
                         <table class="table" id="blocked-user-hashes-table">
                             <thead>
                                 <tr>
                                     <th>Хеш пользователя</th>
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
                                 <?php foreach ($blockedUserHashes as $hash): ?>
                                     <tr>
                                         <td>
                                             <span class="ip-info" title="<?php echo htmlspecialchars($hash['hash_full']); ?>">
                                                 <?php echo htmlspecialchars($hash['hash_short']); ?>...
                                             </span>
                                         </td>
                                         <td>
                                             <span class="ip-info"><?php echo htmlspecialchars($hash['ip'] ?? 'N/A'); ?></span>
                                         </td>
                                         <td>
                                             <?php if ($hash['hostname'] !== 'N/A' && $hash['hostname'] !== 'Timeout/N/A' && $hash['hostname'] !== 'rDNS disabled'): ?>
                                                 <span title="<?php echo htmlspecialchars($hash['hostname']); ?>">
                                                     <?php echo htmlspecialchars(substr($hash['hostname'], 0, 30)); ?>
                                                     <?php if (strlen($hash['hostname']) > 30) echo '...'; ?>
                                                 </span>
                                             <?php else: ?>
                                                 <span style="color: #6c757d;"><?php echo htmlspecialchars($hash['hostname']); ?></span>
                                             <?php endif; ?>
                                         </td>
                                         <td><?php echo date('Y-m-d H:i:s', $hash['blocked_at']); ?></td>
                                         <td>
                                             <?php if ($hash['ttl'] > 0): ?>
                                                 <span class="status-badge status-blocked">
                                                     <?php echo gmdate('H:i:s', $hash['ttl']); ?>
                                                 </span>
                                             <?php else: ?>
                                                 <span class="status-badge status-active">Постоянно</span>
                                             <?php endif; ?>
                                         </td>
                                         <td>
                                             <span title="<?php echo htmlspecialchars($hash['user_agent'] ?? ''); ?>">
                                                 <?php echo htmlspecialchars(substr($hash['user_agent'] ?? '', 0, 40)); ?>
                                                 <?php if (strlen($hash['user_agent'] ?? '') > 40) echo '...'; ?>
                                             </span>
                                         </td>
                                         <td><?php echo htmlspecialchars($hash['blocked_reason'] ?? 'N/A'); ?></td>
                                         <td>
                                             <form method="POST" style="display: inline;">
                                                 <input type="hidden" name="action" value="unblock_user_hash">
                                                 <input type="hidden" name="key" value="<?php echo htmlspecialchars($hash['key']); ?>">
                                                 <button type="submit" class="btn btn-success btn-small" onclick="return confirm('Разблокировать хеш пользователя?');">
                                                     🔓 Разблокировать
                                                 </button>
                                             </form>
                                         </td>
                                     </tr>
                                 <?php endforeach; ?>
                             </tbody>
                         </table>
                         
                         <?php if (empty($blockedUserHashes)): ?>
                             <p style="text-align: center; color: #6c757d; padding: 20px;">
                                 ✅ Нет заблокированных хешей пользователей
                             </p>
                         <?php endif; ?>
                     </div>
                 </div>
             </div>

             <!-- Трекинг хешей пользователей -->
             <div id="user-hash-tracking" class="tab-content">
                 <div class="section">
                     <div class="section-header">
                         📊 Активный трекинг хешей пользователей (<?php echo count($userHashTracking); ?>)
                     </div>
                     <div class="section-content">
                         <input type="text" class="search-box" placeholder="🔍 Поиск по хешу или IP..." onkeyup="filterTable(this, 'user-hash-tracking-table')">
                         
                         <table class="table" id="user-hash-tracking-table">
                             <thead>
                                 <tr>
                                     <th>Хеш пользователя</th>
                                     <th>Основной IP</th>
                                     <th>Hostname</th>
                                     <th>Уникальных IP</th>
                                     <th>Последняя активность</th>
                                     <th>Запросов</th>
                                     <th>Страниц</th>
                                     <th>TTL</th>
                                     <th>Действия</th>
                                 </tr>
                             </thead>
                             <tbody>
                                 <?php foreach ($userHashTracking as $track): ?>
                                     <tr>
                                         <td>
                                             <span class="ip-info" title="<?php echo htmlspecialchars($track['hash_full']); ?>">
                                                 <?php echo htmlspecialchars($track['hash_short']); ?>...
                                             </span>
                                         </td>
                                         <td>
                                             <span class="ip-info"><?php echo htmlspecialchars($track['primary_ip']); ?></span>
                                         </td>
                                         <td>
                                             <?php if ($track['hostname'] !== 'N/A' && $track['hostname'] !== 'Timeout/N/A' && $track['hostname'] !== 'rDNS disabled'): ?>
                                                 <span title="<?php echo htmlspecialchars($track['hostname']); ?>">
                                                     <?php echo htmlspecialchars(substr($track['hostname'], 0, 30)); ?>
                                                     <?php if (strlen($track['hostname']) > 30) echo '...'; ?>
                                                 </span>
                                             <?php else: ?>
                                                 <span style="color: #6c757d;"><?php echo htmlspecialchars($track['hostname']); ?></span>
                                             <?php endif; ?>
                                         </td>
                                         <td>
                                             <span class="status-badge <?php echo $track['unique_ips'] > 3 ? 'status-blocked' : 'status-tracking'; ?>">
                                                 <?php echo $track['unique_ips']; ?>
                                             </span>
                                         </td>
                                         <td><?php echo date('Y-m-d H:i:s', $track['last_activity']); ?></td>
                                         <td>
                                             <span class="status-badge <?php echo $track['requests'] > 50 ? 'status-blocked' : 'status-tracking'; ?>">
                                                 <?php echo $track['requests']; ?>
                                             </span>
                                         </td>
                                         <td><?php echo count($track['pages'] ?? []); ?></td>
                                         <td>
                                             <?php if ($track['ttl'] > 0): ?>
                                                 <span class="status-badge status-tracking">
                                                     <?php echo gmdate('H:i:s', $track['ttl']); ?>
                                                 </span>
                                             <?php else: ?>
                                                 <span class="status-badge status-active">Постоянно</span>
                                             <?php endif; ?>
                                         </td>
                                         <td>
                                             <form method="POST" style="display: inline;">
                                                 <input type="hidden" name="action" value="clear_user_hash_tracking">
                                                 <input type="hidden" name="key" value="<?php echo htmlspecialchars($track['key']); ?>">
                                                 <button type="submit" class="btn btn-secondary btn-small" onclick="return confirm('Удалить данные трекинга хеша?');">
                                                     🗑️ Удалить
                                                 </button>
                                             </form>
                                         </td>
                                     </tr>
                                 <?php endforeach; ?>
                             </tbody>
                         </table>
                         
                         <?php if (empty($userHashTracking)): ?>
                             <p style="text-align: center; color: #6c757d; padding: 20px;">
                                 📊 Нет активных записей трекинга хешей
                             </p>
                         <?php endif; ?>
                     </div>
                 </div>
             </div>

             <!-- Данные трекинга IP -->
             <div id="tracking" class="tab-content">
                 <div class="section">
                     <div class="section-header">
                         📈 Активный трекинг IP адресов (<?php echo count($trackingData); ?>)
                     </div>
                     <div class="section-content">
                         <input type="text" class="search-box" placeholder="🔍 Поиск по IP или hostname..." onkeyup="filterTable(this, 'tracking-table')">
                         
                         <table class="table" id="tracking-table">
                             <thead>
                                 <tr>
                                     <th>IP адрес</th>
                                     <th>Hostname (rDNS)</th>
                                     <th>Первый визит</th>
                                     <th>Запросов</th>
                                     <th>Страниц</th>
                                     <th>User-Agents</th>
                                     <th>TTL</th>
                                     <th>Действия</th>
                                 </tr>
                             </thead>
                             <tbody>
                                 <?php foreach ($trackingData as $track): ?>
                                     <tr>
                                         <td>
                                             <span class="ip-info"><?php echo htmlspecialchars($track['detected_ip']); ?></span>
                                         </td>
                                         <td>
                                             <?php if ($track['hostname'] !== 'N/A' && $track['hostname'] !== 'Timeout/N/A' && $track['hostname'] !== 'rDNS disabled'): ?>
                                                 <span title="<?php echo htmlspecialchars($track['hostname']); ?>">
                                                     <?php echo htmlspecialchars(substr($track['hostname'], 0, 30)); ?>
                                                     <?php if (strlen($track['hostname']) > 30) echo '...'; ?>
                                                 </span>
                                             <?php else: ?>
                                                 <span style="color: #6c757d;"><?php echo htmlspecialchars($track['hostname']); ?></span>
                                             <?php endif; ?>
                                         </td>
                                         <td><?php echo date('Y-m-d H:i:s', $track['first_seen']); ?></td>
                                         <td>
                                             <span class="status-badge <?php echo $track['requests'] > 10 ? 'status-blocked' : 'status-tracking'; ?>">
                                                 <?php echo $track['requests']; ?>
                                             </span>
                                         </td>
                                         <td><?php echo count($track['pages']); ?></td>
                                         <td>
                                             <span class="status-badge <?php echo count($track['user_agents']) > 1 ? 'status-blocked' : 'status-active'; ?>">
                                                 <?php echo count($track['user_agents']); ?>
                                             </span>
                                         </td>
                                         <td>
                                             <?php if ($track['ttl'] > 0): ?>
                                                 <span class="status-badge status-tracking">
                                                     <?php echo gmdate('H:i:s', $track['ttl']); ?>
                                                 </span>
                                             <?php else: ?>
                                                 <span class="status-badge status-active">Постоянно</span>
                                             <?php endif; ?>
                                         </td>
                                         <td>
                                             <form method="POST" style="display: inline;">
                                                 <input type="hidden" name="action" value="clear_tracking">
                                                 <input type="hidden" name="key" value="<?php echo htmlspecialchars($track['key']); ?>">
                                                 <button type="submit" class="btn btn-secondary btn-small" onclick="return confirm('Удалить данные трекинга?');">
                                                     🗑️ Удалить
                                                 </button>
                                             </form>
                                         </td>
                                     </tr>
                                 <?php endforeach; ?>
                             </tbody>
                         </table>
                         
                         <?php if (empty($trackingData)): ?>
                             <p style="text-align: center; color: #6c757d; padding: 20px;">
                                 📊 Нет активных записей трекинга
                             </p>
                         <?php endif; ?>
                     </div>
                 </div>
             </div>

             <!-- Логи -->
             <div id="logs" class="tab-content">
                 <div class="section">
                     <div class="section-header">
                         📝 Логи системы защиты (последние 50)
                     </div>
                     <div class="section-content">
                         <input type="text" class="search-box" placeholder="🔍 Поиск в логах..." onkeyup="filterTable(this, 'logs-table')">
                         
                         <table class="table" id="logs-table">
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
                                         <td><?php echo htmlspecialchars($log['timestamp']); ?></td>
                                         <td>
                                             <span class="status-badge <?php echo $log['log_type'] === 'bot' ? 'status-tracking' : 'status-active'; ?>">
                                                 <?php echo $log['log_type'] === 'bot' ? '🤖 Bot' : '🔍 Search Engine'; ?>
                                             </span>
                                         </td>
                                         <td>
                                             <span class="ip-info"><?php echo htmlspecialchars($log['ip']); ?></span>
                                         </td>
                                         <td>
                                             <span title="<?php echo htmlspecialchars($log['user_agent']); ?>">
                                                 <?php echo htmlspecialchars(substr($log['user_agent'], 0, 50)); ?>
                                                 <?php if (strlen($log['user_agent']) > 50) echo '...'; ?>
                                             </span>
                                         </td>
                                         <td>
                                             <span title="<?php echo htmlspecialchars($log['uri']); ?>">
                                                 <?php echo htmlspecialchars(substr($log['uri'], 0, 30)); ?>
                                                 <?php if (strlen($log['uri']) > 30) echo '...'; ?>
                                             </span>
                                         </td>
                                         <td>
                                             <?php if (isset($log['hostname']) && $log['hostname']): ?>
                                                 <span title="<?php echo htmlspecialchars($log['hostname']); ?>">
                                                     <?php echo htmlspecialchars(substr($log['hostname'], 0, 25)); ?>
                                                     <?php if (strlen($log['hostname']) > 25) echo '...'; ?>
                                                 </span>
                                             <?php else: ?>
                                                 <span style="color: #6c757d;">N/A</span>
                                             <?php endif; ?>
                                         </td>
                                     </tr>
                                 <?php endforeach; ?>
                             </tbody>
                         </table>
                         
                         <?php if (empty($logs)): ?>
                             <p style="text-align: center; color: #6c757d; padding: 20px;">
                                 📝 Нет записей в логах за сегодня
                             </p>
                         <?php endif; ?>
                     </div>
                 </div>
             </div>
         <?php endif; ?>
     </div>

     <script>
         // Функция переключения табов
         function showTab(tabId) {
             // Скрываем все табы
             document.querySelectorAll('.tab-content').forEach(tab => {
                 tab.classList.remove('active');
             });
             
             // Убираем активный класс с кнопок
             document.querySelectorAll('.tab').forEach(btn => {
                 btn.classList.remove('active');
             });
             
             // Показываем выбранный таб
             document.getElementById(tabId).classList.add('active');
             
             // Добавляем активный класс к кнопке
             event.target.classList.add('active');
         }
         
         // Функция поиска в таблицах
         function filterTable(input, tableId) {
             const filter = input.value.toLowerCase();
             const table = document.getElementById(tableId);
             const rows = table.getElementsByTagName('tr');
             
             for (let i = 1; i < rows.length; i++) { // Начинаем с 1, чтобы пропустить заголовок
                 const row = rows[i];
                 const cells = row.getElementsByTagName('td');
                 let found = false;
                 
                 for (let j = 0; j < cells.length; j++) {
                     const cellText = cells[j].textContent || cells[j].innerText;
                     if (cellText.toLowerCase().indexOf(filter) > -1) {
                         found = true;
                         break;
                     }
                 }
                 
                 row.style.display = found ? '' : 'none';
             }
         }
         
         // Автообновление страницы каждые 30 секунд
         let autoRefreshInterval;
         let isUserActive = false;
         
         function startAutoRefresh() {
             autoRefreshInterval = setInterval(() => {
                 if (!isUserActive) {
                     location.reload();
                 }
             }, 30000);
             
             // Показываем индикатор автообновления
             const indicator = document.createElement('div');
             indicator.id = 'refresh-indicator';
             indicator.style.cssText = `
                 position: fixed;
                 bottom: 20px;
                 right: 20px;
                 background: rgba(0, 123, 255, 0.9);
                 color: white;
                 padding: 10px 15px;
                 border-radius: 8px;
                 font-size: 0.9em;
                 z-index: 1000;
                 transition: opacity 0.3s ease;
             `;
             indicator.innerHTML = '🔄 Auto-refresh: ON <span style="cursor: pointer; margin-left: 10px;" onclick="toggleAutoRefresh()">❌</span>';
             document.body.appendChild(indicator);
             
             // Скрываем индикатор через 3 секунды
             setTimeout(() => {
                 if (indicator) {
                     indicator.style.opacity = '0.7';
                 }
             }, 3000);
         }
         
         function stopAutoRefresh() {
             if (autoRefreshInterval) {
                 clearInterval(autoRefreshInterval);
                 autoRefreshInterval = null;
             }
             
             const indicator = document.getElementById('refresh-indicator');
             if (indicator) {
                 indicator.innerHTML = '🔄 Auto-refresh: OFF <span style="cursor: pointer; margin-left: 10px;" onclick="toggleAutoRefresh()">✅</span>';
                 indicator.style.background = 'rgba(108, 117, 125, 0.9)';
             }
         }
         
         function toggleAutoRefresh() {
             if (autoRefreshInterval) {
                 stopAutoRefresh();
             } else {
                 startAutoRefresh();
             }
         }
         
         // Запускаем автообновление
         startAutoRefresh();
         
         // Отслеживаем активность пользователя
         let userActivityTimer;
         
         function resetActivityTimer() {
             isUserActive = true;
             clearTimeout(userActivityTimer);
             
             userActivityTimer = setTimeout(() => {
                 isUserActive = false;
             }, 10000); // 10 секунд активности
         }
         
         // Отслеживаем активность пользователя
         ['click', 'keypress', 'scroll', 'mousemove', 'input'].forEach(event => {
             document.addEventListener(event, resetActivityTimer);
         });
         
         // Уведомления
         function showNotification(message, type = 'info') {
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
                 z-index: 1001;
                 box-shadow: 0 4px 15px rgba(0,0,0,0.2);
                 max-width: 300px;
                 opacity: 0;
                 transform: translateX(100%);
                 transition: all 0.3s ease;
             `;
             notification.textContent = message;
             document.body.appendChild(notification);

             // Анимация появления
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
         
         // Подтверждение массовых действий
         document.querySelectorAll('form').forEach(form => {
             const action = form.querySelector('input[name="action"]');
             if (action && ['cleanup_all', 'flush_logs', 'clear_rdns_cache'].includes(action.value)) {
                 form.addEventListener('submit', (e) => {
                     const actionText = action.value === 'cleanup_all' ? 
                         'очистить все просроченные ключи' : 
                         action.value === 'flush_logs' ?
                         'удалить все логи' :
                         'очистить весь rDNS кеш';
                     
                     if (!confirm(`Вы действительно хотите ${actionText}? Это действие необратимо!`)) {
                         e.preventDefault();
                     }
                 });
             }
         });
         
         // Валидация форм ручной блокировки
         document.querySelectorAll('form[method="POST"]').forEach(form => {
             form.addEventListener('submit', (e) => {
                 const action = form.querySelector('input[name="action"]');
                 if (action && action.value === 'block_manual_ip') {
                     const ipInput = form.querySelector('input[name="ip_address"]');
                     const ip = ipInput.value.trim();
                     
                     // Простая валидация IP
                     const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
                     if (!ipRegex.test(ip)) {
                         e.preventDefault();
                         showNotification('Неверный формат IP адреса!', 'error');
                         ipInput.focus();
                     }
                 }
             });
         });
         
         // Статистика по состоянию страницы
         console.log('🛡️ Redis Bot Protection Admin Panel v2.0 loaded');
         console.log('📊 Current stats:', {
             blockedIPs: <?php echo count($blockedIPs ?? []); ?>,
             blockedSessions: <?php echo count($blockedSessions ?? []); ?>,
             blockedCookies: <?php echo count($blockedCookies ?? []); ?>,
             blockedUserHashes: <?php echo count($blockedUserHashes ?? []); ?>,
             userHashTracking: <?php echo count($userHashTracking ?? []); ?>,
             trackingRecords: <?php echo count($trackingData ?? []); ?>,
             logs: <?php echo count($logs ?? []); ?>,
             rdnsCache: <?php echo $redisStats['rdns_cache'] ?? 0; ?>
         });
         
         // Клавиатурные сочетания
         document.addEventListener('keydown', (e) => {
             if (e.ctrlKey || e.metaKey) {
                 switch(e.key) {
                     case 'r':
                         e.preventDefault();
                         location.reload();
                         break;
                     case '1':
                         e.preventDefault();
                         showTab('blocked-ips');
                         break;
                     case '2':
                         e.preventDefault();
                         showTab('blocked-sessions');
                         break;
                     case '3':
                         e.preventDefault();
                         showTab('blocked-cookies');
                         break;
                     case '4':
                         e.preventDefault();
                         showTab('blocked-user-hashes');
                         break;
                     case '5':
                         e.preventDefault();
                         showTab('user-hash-tracking');
                         break;
                     case '6':
                         e.preventDefault();
                         showTab('tracking');
                         break;
                     case '7':
                         e.preventDefault();
                         showTab('logs');
                         break;
                 }
             }
         });
         
         // Показываем горячие клавиши
         setTimeout(() => {
             showNotification('💡 Горячие клавиши: Ctrl+R (обновить), Ctrl+1-7 (переключение табов)', 'info');
         }, 1000);

         // Живые обновления счетчиков
         function updateCounters() {
             const stats = document.querySelectorAll('.stat-number');
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

         // Добавляем CSS анимацию
         const style = document.createElement('style');
         style.textContent = `
             @keyframes pulse {
                 0% { transform: scale(1); }
                 50% { transform: scale(1.1); }
                 100% { transform: scale(1); }
             }
             
             .stat-card:hover .stat-number {
                 color: #0056b3;
                 transition: color 0.3s ease;
             }
             
             .table tr:hover {
                 background: #f1f3f4 !important;
                 transform: scale(1.01);
                 transition: all 0.2s ease;
             }
             
             .btn:active {
                 transform: scale(0.95);
             }
             
             .search-box:focus {
                 border-color: #007bff;
                 box-shadow: 0 0 0 0.2rem rgba(0, 123, 255, 0.25);
                 outline: none;
             }
         `;
         document.head.appendChild(style);
         
         // Инициализация завершена
         updateCounters();
         
         // Показываем информацию о версии при загрузке
         console.log(`
█▀▀▄ █▀▀█ ▀▀█▀▀   █▀▀█ █▀▀█ █▀▀█ ▀▀█▀▀ █▀▀ █▀▀ ▀▀█▀▀ ─▀─ █▀▀█ █▀▀▄
█▀▀▄ █  █   █     █  █ █▄▄▀ █  █   █   █▄▄ █     █    ▀█▀ █  █ █  █
▀▀▀  ▀▀▀▀   ▀     █▀▀▀ ▀ ▀▀ ▀▀▀▀   ▀   ▀▀▀ ▀▀▀   ▀   ▀▀▀ ▀▀▀▀ ▀  ▀

Version 2.0 - Full User Hash Support + Fast rDNS
Admin Panel Loaded Successfully!
         `);
     </script>
 <?php endif; ?>
</body>
</html>