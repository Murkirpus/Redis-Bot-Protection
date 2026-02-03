<?php
/**
 * iptables.php - Управление блокировкой IP-адресов через iptables
 * Версия: 2.1
 * 
 * Скрипт для блокировки IPv4 и IPv6 адресов через iptables
 * Работает через sudo (требуется настройка sudoers)
 * 
 * Совместимость: PHP 5.6 - 8.3
 * 
 * Настройка sudoers (добавьте в /etc/sudoers):
 * www-data ALL=(ALL) NOPASSWD: /sbin/iptables, /sbin/ip6tables, /sbin/iptables-save, /sbin/ip6tables-save
 * 
 * =====================================================================
 * ПОДДЕРЖИВАЕМЫЕ API КОМАНДЫ
 * =====================================================================
 * 
 * 1. Блокировка IP
 *    GET:  ?action=block&ip=IP_ADDRESS&api=1&api_key=YOUR_KEY
 *    POST: action=block&ip=IP_ADDRESS&api=1&api_key=YOUR_KEY
 *    Блокирует IP для портов 80 и 443
 * 
 * 2. Разблокировка IP
 *    GET:  ?action=unblock&ip=IP_ADDRESS&api=1&api_key=YOUR_KEY
 *    POST: action=unblock&ip=IP_ADDRESS&api=1&api_key=YOUR_KEY
 *    Разблокирует IP
 * 
 * 3. Список заблокированных IPv4
 *    URL: ?action=list&api=1&api_key=YOUR_KEY
 *    Возвращает список заблокированных IPv4 адресов
 * 
 * 4. Список заблокированных IPv6
 *    URL: ?action=list6&api=1&api_key=YOUR_KEY
 *    Возвращает список заблокированных IPv6 адресов
 * 
 * 5. Очистка всех правил
 *    URL: ?action=clear&api=1&api_key=YOUR_KEY
 *    Удаляет все правила блокировки
 * 
 * 6. Отладочная информация
 *    URL: ?action=debug&api=1&api_key=YOUR_KEY
 *    Возвращает полную информацию о правилах iptables
 * 
 * Все API вызовы возвращают JSON (с поддержкой кириллицы)
 */

// Отключаем уведомления для совместимости
error_reporting(E_ALL & ~E_NOTICE & ~E_DEPRECATED);

// Отключаем кеширование для получения актуальных данных
header("Cache-Control: no-cache, no-store, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: 0");

// Подключаем настройки
require_once 'settings.php';

// =====================================================================
// НАСТРОЙКИ БЕЗОПАСНОСТИ
// =====================================================================

// API ключ из settings.php
$valid_api_key = defined('API_BLOCK_KEY') ? API_BLOCK_KEY : 'default-key';

// Разрешенные IP (опционально, при наличии API ключа не обязательно)
$allowed_ips = array(
    '127.0.0.1'  // localhost
);

// Включить проверку по IP
$enable_ip_restriction = false; // Если false, работает только по API ключу

// =====================================================================
// НАСТРОЙКИ БАЛАНСИРОВКИ НАГРУЗКИ
// =====================================================================

$load_balancing_enabled = defined('LOAD_BALANCING_ENABLED') ? LOAD_BALANCING_ENABLED : true;
$max_concurrent_requests = defined('MAX_CONCURRENT_REQUESTS') ? MAX_CONCURRENT_REQUESTS : 20;
$request_processing_delay = defined('REQUEST_PROCESSING_DELAY') ? REQUEST_PROCESSING_DELAY : 0;
$dynamic_delay_enabled = defined('DYNAMIC_DELAY_ENABLED') ? DYNAMIC_DELAY_ENABLED : true;
$load_threshold = defined('LOAD_THRESHOLD') ? LOAD_THRESHOLD : 4.0;
$max_dynamic_delay = defined('MAX_DYNAMIC_DELAY') ? MAX_DYNAMIC_DELAY : 100000;
$sem_key_path = defined('SEM_KEY_PATH') ? SEM_KEY_PATH : __FILE__;
$load_tracking_file = defined('LOAD_TRACKING_FILE') ? LOAD_TRACKING_FILE : '/tmp/iptables_load_tracking';

// =====================================================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
// =====================================================================

/**
 * Безопасное получение значения из массива
 */
function safe_get($array, $key, $default = '') {
    return isset($array[$key]) ? $array[$key] : $default;
}

/**
 * Получение IP пользователя
 */
function getUserIP() {
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
        if (strpos($ip, ',') !== false) {
            $ip = trim(explode(',', $ip)[0]);
        }
    } elseif (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        $ip = $_SERVER['HTTP_CLIENT_IP'];
    } else {
        $ip = $_SERVER['REMOTE_ADDR'];
    }
    return $ip;
}

/**
 * Получение нагрузки сервера
 */
function getServerLoad() {
    if (function_exists('sys_getloadavg')) {
        $load = sys_getloadavg();
        return $load[0];
    }
    return 0;
}

/**
 * Расчет динамической задержки
 */
function calculateDynamicDelay($threshold, $max_delay) {
    $load = getServerLoad();
    
    if ($load <= $threshold) {
        return 0;
    }
    
    $factor = ($load - $threshold) / $threshold;
    $delay = (int)($factor * $max_delay);
    
    return min($delay, $max_delay);
}

/**
 * Управление семафорами для контроля параллельных запросов
 */
function manageConcurrentRequests($acquire, $max_requests, $sem_key_path) {
    static $semaphore = null;
    
    if (!extension_loaded('sysvsem')) {
        return true;
    }
    
    if ($semaphore === null) {
        $sem_key = ftok($sem_key_path, 'i');
        $semaphore = sem_get($sem_key, $max_requests);
        
        if (!$semaphore) {
            error_log("Не удалось создать семафор");
            return true;
        }
    }
    
    if ($acquire) {
        return sem_acquire($semaphore, true);
    } else {
        return sem_release($semaphore);
    }
}

/**
 * Отслеживание частоты запросов
 */
function trackRequestRate() {
    global $load_tracking_file;
    
    $now = microtime(true);
    $tracking_data = array(
        'timestamp' => $now,
        'request_count' => 1,
        'load' => getServerLoad()
    );
    
    if (file_exists($load_tracking_file)) {
        $content = @file_get_contents($load_tracking_file);
        if ($content) {
            $previous_data = json_decode($content, true);
            if (is_array($previous_data)) {
                if (($now - $previous_data['timestamp']) < 1.0) {
                    $tracking_data['request_count'] = $previous_data['request_count'] + 1;
                }
            }
        }
    }
    
    @file_put_contents($load_tracking_file, json_encode($tracking_data));
    
    if ($tracking_data['request_count'] % 100 === 0) {
        error_log("API статистика: {$tracking_data['request_count']} запросов/сек, нагрузка: {$tracking_data['load']}");
    }
}

/**
 * Применение балансировки нагрузки
 */
function applyLoadBalancing() {
    global $load_balancing_enabled, $max_concurrent_requests, $request_processing_delay,
           $dynamic_delay_enabled, $load_threshold, $max_dynamic_delay, $sem_key_path;
    
    if (!$load_balancing_enabled) {
        return true;
    }
    
    trackRequestRate();
    
    if (!manageConcurrentRequests(true, $max_concurrent_requests, $sem_key_path)) {
        usleep(10000); // 10ms задержка при превышении лимита
    }
    
    if ($request_processing_delay > 0) {
        usleep($request_processing_delay);
    }
    
    if ($dynamic_delay_enabled) {
        $dynamic_delay = calculateDynamicDelay($load_threshold, $max_dynamic_delay);
        if ($dynamic_delay > 0) {
            usleep($dynamic_delay);
        }
    }
    
    return true;
}

/**
 * Проверка доступа по API ключу
 */
function checkAccess($valid_api_key, $allowed_ips, $enable_ip_restriction) {
    $api_key = safe_get($_REQUEST, 'api_key', '');
    
    if ($api_key === $valid_api_key) {
        return true;
    }
    
    if ($enable_ip_restriction) {
        $user_ip = getUserIP();
        if (in_array($user_ip, $allowed_ips)) {
            return true;
        }
    }
    
    return false;
}

// Проверка доступа
if (!checkAccess($valid_api_key, $allowed_ips, $enable_ip_restriction)) {
    header("HTTP/1.1 403 Forbidden");
    echo "Доступ запрещен. Требуется авторизация.";
    exit;
}

// Режим API (поддержка GET и POST)
$api_mode = isset($_REQUEST['api']) && $_REQUEST['api'] == 1;

if ($api_mode) {
    header('Content-Type: application/json');
    // Дополнительная защита от кеширования для API запросов
    header("Cache-Control: no-cache, no-store, must-revalidate, max-age=0");
    header("Pragma: no-cache");
    header("Expires: 0");
    
    applyLoadBalancing();
    
    register_shutdown_function(function() use ($max_concurrent_requests, $sem_key_path) {
        manageConcurrentRequests(false, $max_concurrent_requests, $sem_key_path);
    });
}

// =====================================================================
// ФУНКЦИИ РАБОТЫ С БЛОКИРОВКАМИ
// =====================================================================

/**
 * Очистка старых lock файлов
 */
function cleanupOldLocks() {
    $lockPattern = '/tmp/iptables_*.lock';
    $files = glob($lockPattern);
    
    if ($files) {
        $now = time();
        foreach ($files as $file) {
            if (file_exists($file) && ($now - filemtime($file)) > 60) {
                @unlink($file);
            }
        }
    }
}

/**
 * Проверка блокировки операции (защита от race condition)
 */
function checkOperationLock($ip, $action = 'block') {
    cleanupOldLocks();
    
    $lockFile = '/tmp/iptables_' . md5($ip . '_' . $action) . '.lock';
    
    if (file_exists($lockFile)) {
        $fileAge = time() - filemtime($lockFile);
        if ($fileAge > 30) {
            @unlink($lockFile);
        } else {
            return array(
                'locked' => false,
                'message' => 'Операция для IP ' . $ip . ' уже выполняется'
            );
        }
    }
    
    $lockHandle = @fopen($lockFile, 'x');
    
    if (!$lockHandle) {
        return array(
            'locked' => false,
            'message' => 'Операция для IP ' . $ip . ' уже выполняется'
        );
    }
    
    fwrite($lockHandle, time());
    
    return array(
        'locked' => true,
        'handle' => $lockHandle,
        'file' => $lockFile
    );
}

/**
 * Освобождение блокировки
 */
function releaseOperationLock($lockData) {
    if (isset($lockData['handle']) && $lockData['handle']) {
        fclose($lockData['handle']);
    }
    if (isset($lockData['file']) && file_exists($lockData['file'])) {
        @unlink($lockData['file']);
    }
}

/**
 * Сохранение правил iptables
 */
function saveRules($isIPv6 = false) {
    if ($isIPv6) {
        exec("sudo ip6tables-save > /tmp/rules.v6 2>/dev/null");
    } else {
        exec("sudo iptables-save > /tmp/rules.v4 2>/dev/null");
    }
}

/**
 * Блокировка IP-адреса
 */
function blockIP($ip) {
    $lockCheck = checkOperationLock($ip, 'block');
    if (!$lockCheck['locked']) {
        return array(
            'status' => 'info',
            'message' => $lockCheck['message']
        );
    }
    
    try {
        // Валидация IP
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return array('status' => 'error', 'message' => "Неверный формат IP: $ip");
        }
        
        // Защита от инъекций
        if (!preg_match('/^[0-9a-fA-F:\.]+$/', $ip)) {
            return array('status' => 'error', 'message' => "Недопустимые символы в IP");
        }
        
        $isIPv6 = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
        $results = array();
        $success = true;
        $ports = array(80, 443);
        
        error_log("Блокировка IP: $ip, IPv6: " . ($isIPv6 ? "да" : "нет"));
        
        foreach ($ports as $port) {
            if ($isIPv6) {
                $commandCheck = "sudo ip6tables -C INPUT -s " . escapeshellarg($ip) . " -p tcp --dport $port -j DROP 2>/dev/null";
                $command = "sudo ip6tables -I INPUT -s " . escapeshellarg($ip) . " -p tcp --dport $port -j DROP";
            } else {
                $commandCheck = "sudo iptables -C INPUT -s " . escapeshellarg($ip) . " -p tcp --dport $port -j DROP 2>/dev/null";
                $command = "sudo iptables -I INPUT -s " . escapeshellarg($ip) . " -p tcp --dport $port -j DROP";
            }
            
            // Проверка существования правила
            $returnVar = 0;
            $output = array();
            exec($commandCheck, $output, $returnVar);
            
            if ($returnVar === 0) {
                $results[] = "Порт $port: уже заблокирован";
                continue;
            }
            
            // Выполнение блокировки
            $output = array();
            $returnVar = 0;
            exec($command, $output, $returnVar);
            
            if ($returnVar !== 0) {
                $results[] = "Порт $port: ошибка блокировки";
                $success = false;
            } else {
                $results[] = "Порт $port: заблокирован";
            }
        }
        
        if ($success) {
            saveRules($isIPv6);
        }
        
        if ($success) {
            return array(
                'status' => 'success',
                'message' => "IP $ip успешно заблокирован для портов 80 и 443",
                'details' => implode(", ", $results)
            );
        } else {
            return array(
                'status' => 'error',
                'message' => "Ошибка при блокировке IP: $ip",
                'details' => implode(", ", $results)
            );
        }
        
    } finally {
        releaseOperationLock($lockCheck);
    }
}

/**
 * Разблокировка IP-адреса
 */
function unblockIP($ip) {
    $lockCheck = checkOperationLock($ip, 'unblock');
    if (!$lockCheck['locked']) {
        return array(
            'status' => 'info',
            'message' => $lockCheck['message']
        );
    }
    
    try {
        // Поддержка CIDR нотации
        $is_cidr = strpos($ip, '/') !== false;
        $ip_for_validation = $is_cidr ? substr($ip, 0, strpos($ip, '/')) : $ip;
        
        if (!$is_cidr && !filter_var($ip_for_validation, FILTER_VALIDATE_IP)) {
            return array('status' => 'error', 'message' => "Неверный формат IP: $ip");
        }
        
        // Защита от инъекций
        if (!preg_match('/^[0-9a-fA-F:\.\/]+$/', $ip)) {
            return array('status' => 'error', 'message' => "Недопустимые символы в IP");
        }
        
        $isIPv6 = strpos($ip, ':') !== false || 
                  (!$is_cidr && filter_var($ip_for_validation, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6));
        
        $results = array();
        $success = true;
        $ports = array(80, 443);
        
        error_log("Разблокировка IP: $ip, IPv6: " . ($isIPv6 ? "да" : "нет"));
        
        foreach ($ports as $port) {
            if ($isIPv6) {
                $command = "sudo ip6tables -D INPUT -s " . escapeshellarg($ip) . " -p tcp --dport $port -j DROP 2>/dev/null";
            } else {
                $command = "sudo iptables -D INPUT -s " . escapeshellarg($ip) . " -p tcp --dport $port -j DROP 2>/dev/null";
            }
            
            $output = array();
            $returnVar = 0;
            exec($command, $output, $returnVar);
            
            if ($returnVar !== 0) {
                $results[] = "Порт $port: ошибка разблокировки";
                $success = false;
            } else {
                $results[] = "Порт $port: разблокирован";
            }
        }
        
        // Удаление общего правила (для совместимости)
        if ($isIPv6) {
            $command = "sudo ip6tables -D INPUT -s " . escapeshellarg($ip) . " -j DROP 2>/dev/null";
        } else {
            $command = "sudo iptables -D INPUT -s " . escapeshellarg($ip) . " -j DROP 2>/dev/null";
        }
        exec($command);
        
        saveRules($isIPv6);
        
        if ($success) {
            return array(
                'status' => 'success',
                'message' => "IP $ip успешно разблокирован",
                'details' => implode(", ", $results)
            );
        } else {
            return array(
                'status' => 'warning',
                'message' => "Частичная разблокировка IP: $ip",
                'details' => implode(", ", $results)
            );
        }
        
    } finally {
        releaseOperationLock($lockCheck);
    }
}

/**
 * Получение списка заблокированных IP
 */
function listBlockedIPs($version) {
    $blockedIPs = array();
    $blockedIPsDetails = array();
    
    // Получение правил
    if ($version === 6) {
        $command = "sudo ip6tables -S INPUT | grep DROP | grep -v ufw | grep -v '::/0'";
    } else {
        $command = "sudo iptables -S INPUT | grep DROP | grep -v ufw | grep -v '0.0.0.0/0'";
    }
    
    $output = array();
    exec($command, $output);
    
    foreach ($output as $line) {
        if (strpos($line, " -s 0.0.0.0/0 ") !== false || strpos($line, " -s ::/0 ") !== false) {
            continue;
        }
        
        if (preg_match('/\-s\s+([0-9a-fA-F:\.\/]+)\s+.*\-p\s+tcp\s+.*\-\-dport\s+(\d+)/', $line, $matches)) {
            $ip = $matches[1];
            $port = $matches[2];
            
            if ($ip === "0.0.0.0/0" || $ip === "::/0") {
                continue;
            }
            
            if (!isset($blockedIPsDetails[$ip])) {
                $blockedIPsDetails[$ip] = array(
                    'ip' => $ip,
                    'ports' => array()
                );
                $blockedIPs[] = $ip;
            }
            
            if (!in_array($port, $blockedIPsDetails[$ip]['ports'])) {
                $blockedIPsDetails[$ip]['ports'][] = $port;
            }
        }
    }
    
    $detailsList = array_values($blockedIPsDetails);
    
    return array(
        'status' => 'success',
        'version' => $version === 6 ? 'IPv6' : 'IPv4',
        'count' => count($blockedIPs),
        'blocked_ips' => $blockedIPs,
        'blocked_details' => $detailsList
    );
}

/**
 * Очистка всех правил блокировки
 */
function clearAllRules() {
    $results = array();
    $success = true;
    
    // Получаем списки заблокированных IP
    $ipv4List = listBlockedIPs(4);
    $ipv6List = listBlockedIPs(6);
    
    $ipv4Addresses = isset($ipv4List['blocked_ips']) ? $ipv4List['blocked_ips'] : array();
    $ipv6Addresses = isset($ipv6List['blocked_ips']) ? $ipv6List['blocked_ips'] : array();
    
    // Разблокируем каждый IPv4
    foreach ($ipv4Addresses as $ip) {
        $result = unblockIP($ip);
        if ($result['status'] !== 'success') {
            $success = false;
            $results[] = "Ошибка разблокировки IPv4: $ip";
        } else {
            $results[] = "IPv4 $ip разблокирован";
        }
    }
    
    // Разблокируем каждый IPv6
    foreach ($ipv6Addresses as $ip) {
        $result = unblockIP($ip);
        if ($result['status'] !== 'success') {
            $success = false;
            $results[] = "Ошибка разблокировки IPv6: $ip";
        } else {
            $results[] = "IPv6 $ip разблокирован";
        }
    }
    
    // Дополнительная очистка правил для портов 80 и 443
    $ports = array(80, 443);
    
    foreach ($ports as $port) {
        // IPv4
        $continueDeleting = true;
        $iterations = 0;
        $maxIterations = 50;
        
        while ($continueDeleting && $iterations < $maxIterations) {
            $iterations++;
            $output = array();
            exec("sudo iptables -L INPUT -n --line-numbers | grep 'tcp dpt:$port' | head -n 1", $output);
            
            if (!empty($output) && preg_match('/^(\d+).*DROP.*tcp dpt:' . $port . '/', $output[0], $matches)) {
                $ruleNum = $matches[1];
                $returnVar = 0;
                exec("sudo iptables -D INPUT $ruleNum", $outputCmd, $returnVar);
                if ($returnVar !== 0) {
                    $success = false;
                    $continueDeleting = false;
                }
            } else {
                $continueDeleting = false;
            }
        }
        
        // IPv6
        $continueDeleting = true;
        $iterations = 0;
        
        while ($continueDeleting && $iterations < $maxIterations) {
            $iterations++;
            $output = array();
            exec("sudo ip6tables -L INPUT -n --line-numbers | grep 'tcp dpt:$port' | head -n 1", $output);
            
            if (!empty($output) && preg_match('/^(\d+).*DROP.*tcp dpt:' . $port . '/', $output[0], $matches)) {
                $ruleNum = $matches[1];
                $returnVar = 0;
                exec("sudo ip6tables -D INPUT $ruleNum", $outputCmd, $returnVar);
                if ($returnVar !== 0) {
                    $success = false;
                    $continueDeleting = false;
                }
            } else {
                $continueDeleting = false;
            }
        }
    }
    
    saveRules(false);
    saveRules(true);
    
    if (empty($ipv4Addresses) && empty($ipv6Addresses) && $success) {
        $results[] = "Заблокированных IP не найдено";
    }
    
    if ($success) {
        return array(
            'status' => 'success',
            'message' => 'Все правила блокировки удалены',
            'details' => implode(", ", $results)
        );
    } else {
        return array(
            'status' => 'warning',
            'message' => 'Некоторые правила не удалось удалить',
            'details' => implode(", ", $results)
        );
    }
}

/**
 * Отладочная информация
 */
function getDebugInfo() {
    $debug = array();
    
    // IPv4 правила
    $output = array();
    exec("sudo iptables -L INPUT -n -v", $output);
    $debug['iptables_ipv4'] = implode("\n", $output);
    
    // IPv6 правила
    $output = array();
    exec("sudo ip6tables -L INPUT -n -v", $output);
    $debug['iptables_ipv6'] = implode("\n", $output);
    
    // Нагрузка сервера
    $debug['server_load'] = getServerLoad();
    
    // Заблокированные IP
    $debug['blocked_ipv4'] = listBlockedIPs(4);
    $debug['blocked_ipv6'] = listBlockedIPs(6);
    
    return array(
        'status' => 'success',
        'debug_info' => $debug
    );
}

// =====================================================================
// ОБРАБОТКА ЗАПРОСОВ
// =====================================================================

$action = safe_get($_REQUEST, 'action', '');
$ip = safe_get($_REQUEST, 'ip', '');
$result = array();

// Обработка действий
if ($action === 'block' && $ip) {
    $result = blockIP($ip);
} elseif ($action === 'unblock' && $ip) {
    $result = unblockIP($ip);
} elseif ($action === 'list') {
    $result = listBlockedIPs(4);
} elseif ($action === 'list6') {
    $result = listBlockedIPs(6);
} elseif ($action === 'clear') {
    $result = clearAllRules();
} elseif ($action === 'debug') {
    $result = getDebugInfo();
}

// Возврат результата в режиме API
if ($api_mode) {
    echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    exit;
}

// =====================================================================
// ВЕБ ИНТЕРФЕЙС
// =====================================================================
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
    <meta http-equiv="Pragma" content="no-cache">
    <meta http-equiv="Expires" content="0">
    <title>Управление блокировкой IP</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        .header {
            background: white;
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            color: #333;
            font-size: 32px;
            margin-bottom: 10px;
        }
        
        .header p {
            color: #666;
            font-size: 16px;
        }
        
        .info-box {
            background: #e3f2fd;
            border-left: 4px solid #2196f3;
            padding: 15px;
            margin: 20px 0;
            border-radius: 4px;
        }
        
        .info-box strong {
            color: #1976d2;
        }
        
        .tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }
        
        .tab {
            background: rgba(255,255,255,0.9);
            border: none;
            padding: 15px 30px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 500;
            color: #666;
            transition: all 0.3s ease;
        }
        
        .tab:hover {
            background: white;
            transform: translateY(-2px);
        }
        
        .tab.active {
            background: white;
            color: #667eea;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }
        
        .tab-content {
            display: none;
            background: white;
            border-radius: 12px;
            padding: 30px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
        }
        
        .tab-content.active {
            display: block;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 500;
        }
        
        .form-group input {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.3s ease;
        }
        
        .form-group input:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .btn {
            padding: 12px 30px;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .btn-primary {
            background: #667eea;
            color: white;
        }
        
        .btn-primary:hover {
            background: #5568d3;
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
        }
        
        .btn-danger {
            background: #f44336;
            color: white;
        }
        
        .btn-danger:hover {
            background: #da190b;
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(244, 67, 54, 0.4);
        }
        
        .btn-warning {
            background: #ff9800;
            color: white;
        }
        
        .btn-warning:hover {
            background: #e68900;
        }
        
        .alert {
            padding: 15px 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        
        .alert-success {
            background: #d4edda;
            border-left: 4px solid #28a745;
            color: #155724;
        }
        
        .alert-error {
            background: #f8d7da;
            border-left: 4px solid #dc3545;
            color: #721c24;
        }
        
        .alert-info {
            background: #d1ecf1;
            border-left: 4px solid #17a2b8;
            color: #0c5460;
        }
        
        .ip-list-container {
            margin-top: 20px;
        }
        
        .ip-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            margin-bottom: 10px;
            transition: all 0.3s ease;
        }
        
        .ip-item:hover {
            border-color: #667eea;
            box-shadow: 0 2px 8px rgba(102, 126, 234, 0.1);
        }
        
        .ip-details {
            flex-grow: 1;
        }
        
        .ip-address {
            font-family: 'Courier New', monospace;
            font-weight: bold;
            color: #333;
            font-size: 16px;
        }
        
        .ip-ports {
            color: #666;
            font-size: 14px;
            margin-left: 15px;
        }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 12px;
            text-align: center;
        }
        
        .stat-card h3 {
            font-size: 36px;
            margin-bottom: 10px;
        }
        
        .stat-card p {
            font-size: 14px;
            opacity: 0.9;
        }
        
        .button-group {
            display: flex;
            gap: 10px;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Управление блокировкой IP</h1>
            <p>Система управления правилами iptables для IPv4 и IPv6</p>
            <div class="info-box">
                <strong>Ваш IP:</strong> <span id="userIP"><?php echo getUserIP(); ?></span>
            </div>
        </div>
        
        <?php if (!empty($result) && !$api_mode): ?>
            <?php
            $alertClass = 'alert-info';
            if ($result['status'] === 'success') $alertClass = 'alert-success';
            elseif ($result['status'] === 'error') $alertClass = 'alert-error';
            ?>
            <div class="alert <?php echo $alertClass; ?>">
                <strong><?php echo htmlspecialchars($result['message']); ?></strong>
                <?php if (isset($result['details'])): ?>
                    <br><small><?php echo htmlspecialchars($result['details']); ?></small>
                <?php endif; ?>
            </div>
        <?php endif; ?>
        
        <div class="tabs">
            <button class="tab active" onclick="switchTab('block')">Блокировка</button>
            <button class="tab" onclick="switchTab('list')">Список IP</button>
            <button class="tab" onclick="switchTab('stats')">Статистика</button>
        </div>
        
        <!-- Вкладка блокировки -->
        <div id="block-tab" class="tab-content active">
            <h2>Блокировка / Разблокировка IP</h2>
            
            <form method="post" action="">
                <div class="form-group">
                    <label for="ip">IP-адрес (IPv4 или IPv6)</label>
                    <input type="text" id="ip" name="ip" placeholder="192.168.1.10 или 2001:db8::1" required>
                </div>
                
                <input type="hidden" name="api_key" value="<?php echo htmlspecialchars($valid_api_key); ?>">
                
                <div class="button-group">
                    <button type="submit" name="action" value="block" class="btn btn-primary">🔒 Заблокировать</button>
                    <button type="submit" name="action" value="unblock" class="btn btn-danger">🔓 Разблокировать</button>
                </div>
            </form>
            
            <div style="margin-top: 30px; padding-top: 30px; border-top: 2px solid #e0e0e0;">
                <h3>Быстрые действия</h3>
                <div class="button-group">
                    <button onclick="blockCurrentIP()" class="btn btn-warning">Заблокировать мой IP</button>
                    <form method="post" action="" style="display: inline;">
                        <input type="hidden" name="api_key" value="<?php echo htmlspecialchars($valid_api_key); ?>">
                        <button type="submit" name="action" value="clear" class="btn btn-danger" 
                                onclick="return confirm('Вы уверены? Это удалит ВСЕ правила блокировки!')">
                            🗑️ Очистить все правила
                        </button>
                    </form>
                </div>
            </div>
        </div>
        
        <!-- Вкладка списка -->
        <div id="list-tab" class="tab-content">
            <h2>Заблокированные IP-адреса</h2>
            
            <h3>IPv4 адреса (<span id="ipv4-count">...</span>)</h3>
            <div id="ipv4-list">Загрузка...</div>
            
            <h3 style="margin-top: 30px;">IPv6 адреса (<span id="ipv6-count">...</span>)</h3>
            <div id="ipv6-list">Загрузка...</div>
            
            <div class="button-group" style="margin-top: 20px;">
                <button onclick="refreshLists()" class="btn btn-primary">🔄 Обновить списки</button>
            </div>
        </div>
        
        <!-- Вкладка статистики -->
        <div id="stats-tab" class="tab-content">
            <h2>Статистика блокировок</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3 id="total-ipv4">0</h3>
                    <p>Заблокировано IPv4</p>
                </div>
                <div class="stat-card">
                    <h3 id="total-ipv6">0</h3>
                    <p>Заблокировано IPv6</p>
                </div>
                <div class="stat-card">
                    <h3 id="total-all">0</h3>
                    <p>Всего заблокировано</p>
                </div>
            </div>
            
            <div style="margin-top: 30px;">
                <button onclick="updateStats()" class="btn btn-primary">🔄 Обновить статистику</button>
            </div>
        </div>
    </div>
    
    <script>
        var apiKey = <?php echo json_encode($valid_api_key); ?>;
        
        function switchTab(tabName) {
            // Скрыть все вкладки
            var tabs = document.querySelectorAll('.tab');
            var tabContents = document.querySelectorAll('.tab-content');
            
            for (var i = 0; i < tabs.length; i++) {
                tabs[i].classList.remove('active');
            }
            
            for (var i = 0; i < tabContents.length; i++) {
                tabContents[i].classList.remove('active');
            }
            
            // Показать выбранную вкладку
            document.querySelector('[onclick="switchTab(\'' + tabName + '\')"]').classList.add('active');
            document.getElementById(tabName + '-tab').classList.add('active');
            
            // Загрузить данные для вкладки списка
            if (tabName === 'list') {
                refreshLists();
            }
            
            // Загрузить статистику
            if (tabName === 'stats') {
                updateStats();
            }
        }
        
        function loadIPs(version, callback) {
            var action = version === 6 ? 'list6' : 'list';
            var timestamp = new Date().getTime(); // Добавляем timestamp для предотвращения кеширования
            var xhr = new XMLHttpRequest();
            xhr.open('GET', '?action=' + action + '&api=1&api_key=' + encodeURIComponent(apiKey) + '&_t=' + timestamp, true);
            
            xhr.onload = function() {
                if (xhr.status === 200) {
                    try {
                        var response = JSON.parse(xhr.responseText);
                        if (callback && typeof callback === 'function') {
                            callback(response);
                        }
                    } catch (e) {
                        console.error('Ошибка парсинга JSON:', e);
                    }
                }
            };
            
            xhr.send();
        }
        
        function refreshLists() {
            loadIPs(4, function(data) {
                updateIPList('ipv4', data);
            });
            
            loadIPs(6, function(data) {
                updateIPList('ipv6', data);
            });
        }
        
        function updateIPList(type, data) {
            var ipListElement = document.getElementById(type + '-list');
            var countElement = document.getElementById(type + '-count');
            
            if (countElement) {
                countElement.textContent = data.count;
            }
            
            if (data.status === 'success') {
                if (data.count === 0) {
                    ipListElement.innerHTML = '<p style="color: #666;">Заблокированных адресов не найдено</p>';
                    return;
                }
                
                var html = '<div class="ip-list-container">';
                
                if (data.blocked_details && data.blocked_details.length > 0) {
                    for (var i = 0; i < data.blocked_details.length; i++) {
                        var ipInfo = data.blocked_details[i];
                        var portsText = ipInfo.ports.includes('all') ? 'Все порты' : 'Порты: ' + ipInfo.ports.join(', ');
                        
                        html += '<div class="ip-item">' +
                            '<div class="ip-details">' +
                            '<span class="ip-address">' + ipInfo.ip + '</span>' +
                            '<span class="ip-ports">' + portsText + '</span>' +
                            '</div>' +
                            '<div class="ip-actions">' +
                            '<form method="post" action="" style="display: inline;">' +
                            '<input type="hidden" name="ip" value="' + ipInfo.ip + '">' +
                            '<input type="hidden" name="api_key" value="' + apiKey + '">' +
                            '<button type="submit" name="action" value="unblock" class="btn btn-danger" style="padding: 8px 16px;">Разблокировать</button>' +
                            '</form>' +
                            '</div>' +
                            '</div>';
                    }
                }
                
                html += '</div>';
                ipListElement.innerHTML = html;
            } else {
                ipListElement.innerHTML = '<p style="color: #f44336;">Ошибка: ' + data.message + '</p>';
            }
        }
        
        function blockCurrentIP() {
            var userIP = document.getElementById('userIP').textContent;
            if (confirm('Вы уверены, что хотите заблокировать свой IP (' + userIP + ')?\nЭто приведет к потере доступа!')) {
                var form = document.createElement('form');
                form.method = 'post';
                form.action = '';
                
                var ipInput = document.createElement('input');
                ipInput.type = 'hidden';
                ipInput.name = 'ip';
                ipInput.value = userIP;
                
                var apiInput = document.createElement('input');
                apiInput.type = 'hidden';
                apiInput.name = 'api_key';
                apiInput.value = apiKey;
                
                var actionInput = document.createElement('input');
                actionInput.type = 'hidden';
                actionInput.name = 'action';
                actionInput.value = 'block';
                
                form.appendChild(ipInput);
                form.appendChild(apiInput);
                form.appendChild(actionInput);
                document.body.appendChild(form);
                form.submit();
            }
        }
        
        function updateStats() {
            loadIPs(4, function(data) {
                document.getElementById('total-ipv4').textContent = data.count;
                updateTotalCount();
            });
            
            loadIPs(6, function(data) {
                document.getElementById('total-ipv6').textContent = data.count;
                updateTotalCount();
            });
        }
        
        function updateTotalCount() {
            var ipv4 = parseInt(document.getElementById('total-ipv4').textContent) || 0;
            var ipv6 = parseInt(document.getElementById('total-ipv6').textContent) || 0;
            document.getElementById('total-all').textContent = ipv4 + ipv6;
        }
        
        // Автозагрузка при переходе на вкладку
        document.addEventListener('DOMContentLoaded', function() {
            <?php if ($action === 'unblock' || $action === 'clear'): ?>
                switchTab('list');
            <?php endif; ?>
        });
    </script>
</body>
</html>
