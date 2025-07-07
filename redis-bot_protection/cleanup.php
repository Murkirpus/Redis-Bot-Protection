<?php
// cleanup.php - Полный скрипт для очистки Redis данных Bot Protection
// Версия: 2.0

class RedisBotProtectionCleanup {
   private $redis;
   private $redisPrefix = 'bot_protection:';
   
   // Префиксы для Redis ключей
   private $trackingPrefix = 'tracking:';
   private $blockPrefix = 'blocked:';
   private $sessionPrefix = 'session:';
   private $cookiePrefix = 'cookie:';
   private $rdnsPrefix = 'rdns:';
   private $userHashPrefix = 'user_hash:';
   
   // TTL настройки (в секундах)
   private $ttlSettings = [
       'tracking_ip' => 3600,          // 1 час
       'session_data' => 7200,         // 2 часа
       'session_blocked' => 21600,     // 6 часов
       'cookie_blocked' => 14400,      // 4 часа
       'ip_blocked' => 1800,           // 30 минут
       'ip_blocked_repeat' => 7200,    // 2 часа
       'rdns_cache' => 1800,           // 30 минут
       'logs' => 172800,               // 2 дня
       'user_hash_blocked' => 7200,    // 2 часа
       'user_hash_tracking' => 3600,   // 1 час
   ];
   
   public function __construct($redisHost = '127.0.0.1', $redisPort = 6379, $redisPassword = null, $redisDatabase = 0) {
       $this->initRedis($redisHost, $redisPort, $redisPassword, $redisDatabase);
   }
   
   private function initRedis($host, $port, $password, $database) {
       try {
           $this->redis = new Redis();
           $this->redis->connect($host, $port);
           
           if ($password) {
               $this->redis->auth($password);
           }
           
           $this->redis->select($database);
           $this->redis->setOption(Redis::OPT_SERIALIZER, Redis::SERIALIZER_JSON);
           $this->redis->setOption(Redis::OPT_PREFIX, $this->redisPrefix);
           
       } catch (Exception $e) {
           throw new Exception("Redis connection failed: " . $e->getMessage());
       }
   }
   
   /**
    * Получение детальной статистики
    */
   public function getStats() {
       $stats = [
           'blocked_ips' => 0,
           'blocked_sessions' => 0,
           'blocked_cookies' => 0,
           'blocked_user_hashes' => 0,
           'tracking_ip_records' => 0,
           'tracked_user_hashes' => 0,
           'session_data_records' => 0,
           'rdns_cache_records' => 0,
           'log_records' => 0,
           'stats_records' => 0,
           'total_keys' => 0,
           'memory_usage' => 0,
           'expired_keys' => 0,
           'keys_without_ttl' => 0
       ];
       
       try {
           // Заблокированные элементы
           $blockedIPs = $this->redis->keys($this->blockPrefix . 'ip:*');
           $stats['blocked_ips'] = count($blockedIPs);
           
           $blockedSessions = $this->redis->keys($this->sessionPrefix . 'blocked:*');
           $stats['blocked_sessions'] = count($blockedSessions);
           
           $blockedCookies = $this->redis->keys($this->cookiePrefix . 'blocked:*');
           $stats['blocked_cookies'] = count($blockedCookies);
           
           $blockedHashes = $this->redis->keys($this->userHashPrefix . 'blocked:*');
           $stats['blocked_user_hashes'] = count($blockedHashes);
           
           // Трекинг записи
           $trackingRecords = $this->redis->keys($this->trackingPrefix . 'ip:*');
           $stats['tracking_ip_records'] = count($trackingRecords);
           
           $trackedHashes = $this->redis->keys($this->userHashPrefix . 'tracking:*');
           $stats['tracked_user_hashes'] = count($trackedHashes);
           
           // Сессии и кеш
           $sessionData = $this->redis->keys($this->sessionPrefix . 'data:*');
           $stats['session_data_records'] = count($sessionData);
           
           $rdnsCache = $this->redis->keys($this->rdnsPrefix . 'cache:*');
           $stats['rdns_cache_records'] = count($rdnsCache);
           
           // Логи и статистика
           $logRecords = $this->redis->keys('logs:*');
           $stats['log_records'] = count($logRecords);
           
           $statsRecords = $this->redis->keys($this->userHashPrefix . 'stats:*');
           $stats['stats_records'] = count($statsRecords);
           
           // Общая статистика
           $allKeys = $this->redis->keys('*');
           $stats['total_keys'] = count($allKeys);
           
           // Проверяем TTL ключей
           $expiredCount = 0;
           $noTtlCount = 0;
           foreach (array_slice($allKeys, 0, 100) as $key) { // Проверяем первые 100 ключей
               $ttl = $this->redis->ttl($key);
               if ($ttl === -2) $expiredCount++;
               if ($ttl === -1) $noTtlCount++;
           }
           $stats['expired_keys'] = $expiredCount;
           $stats['keys_without_ttl'] = $noTtlCount;
           
           // Информация о памяти Redis
           $info = $this->redis->info('memory');
           $stats['memory_usage'] = $info['used_memory_human'] ?? 'unknown';
           
       } catch (Exception $e) {
           echo "Error getting stats: " . $e->getMessage() . "\n";
       }
       
       return $stats;
   }
   
   /**
    * Легкая очистка истекших ключей
    */
   public function lightCleanup() {
       try {
           $cleaned = 0;
           $startTime = microtime(true);
           $maxExecutionTime = 5.0; // Максимум 5 секунд
           
           $patterns = [
               $this->trackingPrefix . 'ip:*',
               $this->sessionPrefix . 'data:*',
               $this->rdnsPrefix . 'cache:*',
               $this->userHashPrefix . 'tracking:*'
           ];
           
           foreach ($patterns as $pattern) {
               if ((microtime(true) - $startTime) > $maxExecutionTime) break;
               
               $keys = $this->redis->keys($pattern);
               foreach ($keys as $key) {
                   if ((microtime(true) - $startTime) > $maxExecutionTime) break;
                   
                   $ttl = $this->redis->ttl($key);
                   if ($ttl === -2) { // Ключ истек
                       $this->redis->del($key);
                       $cleaned++;
                   }
               }
               
               if ($cleaned > 500) break; // Ограничиваем количество
           }
           
           $executionTime = round((microtime(true) - $startTime) * 1000);
           echo "Light cleanup: $cleaned expired keys removed in {$executionTime}ms\n";
           
           return $cleaned;
           
       } catch (Exception $e) {
           echo "Light cleanup error: " . $e->getMessage() . "\n";
           return 0;
       }
   }
   
   /**
    * Глубокая очистка всех данных
    */
   public function deepCleanup() {
    try {
        $totalCleaned = 0;
        $totalProcessed = 0;
        $startTime = microtime(true);
        
        echo "Starting deep cleanup...\n";
        
        // 1. Очистка старых логов по дням
        echo "Cleaning old logs...\n";
        $logsCleaned = 0;
        for ($i = 3; $i <= 30; $i++) {
            $oldDate = date('Y-m-d', time() - ($i * 86400));
            $patterns = [
                'logs:legitimate_bots:' . $oldDate,
                'logs:search_engines:' . $oldDate,
                'logs:blocked:' . $oldDate
            ];
            
            foreach ($patterns as $pattern) {
                if ($this->redis->exists($pattern)) {
                    $this->redis->del($pattern);
                    $totalCleaned++;
                    $logsCleaned++;
                }
            }
        }
        echo "  - Old logs removed: $logsCleaned\n";
        
        // 2. Очистка истекших и ключей без TTL
        echo "Cleaning expired and orphaned keys...\n";
        $patterns = [
            $this->trackingPrefix . 'ip:*',
            $this->sessionPrefix . 'data:*',
            $this->sessionPrefix . 'blocked:*',
            $this->rdnsPrefix . 'cache:*',
            $this->userHashPrefix . 'tracking:*',
            $this->userHashPrefix . 'blocked:*',
            $this->userHashPrefix . 'stats:*',
            $this->blockPrefix . 'ip:*',
            $this->cookiePrefix . 'blocked:*'
        ];
        
        foreach ($patterns as $pattern) {
            $keys = $this->redis->keys($pattern);
            $patternCleaned = 0;
            $patternProcessed = count($keys);
            $totalProcessed += $patternProcessed;
            
            foreach ($keys as $key) {
                $ttl = $this->redis->ttl($key);
                
                // Удаляем истекшие ключи
                if ($ttl === -2) {
                    $this->redis->del($key);
                    $totalCleaned++;
                    $patternCleaned++;
                } 
                // Для ключей без TTL - устанавливаем TTL
                elseif ($ttl === -1) {
                    $this->setMissingTTL($key, $pattern);
                    $patternCleaned++;
                }
            }
            
            $patternName = str_replace('*', '', $pattern);
            echo "  - $patternName: $patternProcessed checked, $patternCleaned updated\n";
        }
        
        // 3. Ограничиваем размеры списков
        echo "Trimming large lists...\n";
        $trimmedLists = 0;
        $logKeys = $this->redis->keys('logs:*');
        foreach ($logKeys as $key) {
            if ($this->redis->type($key) === Redis::REDIS_LIST) {
                $listSize = $this->redis->llen($key);
                if ($listSize > 1000) {
                    $this->redis->ltrim($key, 0, 999);
                    $totalCleaned++;
                    $trimmedLists++;
                    echo "  - Trimmed list $key from $listSize to 1000 items\n";
                }
            }
        }
        if ($trimmedLists === 0) {
            echo "  - No lists need trimming\n";
        }
        
        // 4. Очистка очень старых записей трекинга
        echo "Cleaning very old tracking records...\n";
        $oldTrackingCleaned = 0;
        $oldTrackingKeys = $this->redis->keys($this->trackingPrefix . 'ip:*');
        foreach ($oldTrackingKeys as $key) {
            $data = $this->redis->get($key);
            if ($data && isset($data['first_seen'])) {
                $age = time() - $data['first_seen'];
                if ($age > 86400) { // Старше 24 часов
                    $this->redis->del($key);
                    $totalCleaned++;
                    $oldTrackingCleaned++;
                }
            }
        }
        echo "  - Old tracking records removed: $oldTrackingCleaned\n";
        
        // 5. Принудительная очистка памяти Redis
        try {
            $this->redis->bgrewriteaof();
            echo "Redis AOF rewrite initiated\n";
        } catch (Exception $e) {
            echo "AOF rewrite not available\n";
        }
        
        $executionTime = round((microtime(true) - $startTime) * 1000);
        echo "\nDEEP CLEANUP RESULTS:\n";
        echo "  - Total items processed: $totalProcessed\n";
        echo "  - Total items cleaned: $totalCleaned\n";
        echo "  - Execution time: {$executionTime}ms\n";
        
        return $totalCleaned;
        
    } catch (Exception $e) {
        echo "Deep cleanup error: " . $e->getMessage() . "\n";
        return 0;
    }
}
   
   /**
    * Устанавливает TTL для ключей без времени жизни
    */
   private function setMissingTTL($key, $pattern) {
       if (strpos($pattern, $this->trackingPrefix . 'ip:') === 0) {
           $this->redis->expire($key, $this->ttlSettings['tracking_ip']);
       } elseif (strpos($pattern, $this->sessionPrefix . 'data:') === 0) {
           $this->redis->expire($key, $this->ttlSettings['session_data']);
       } elseif (strpos($pattern, $this->sessionPrefix . 'blocked:') === 0) {
           $this->redis->expire($key, $this->ttlSettings['session_blocked']);
       } elseif (strpos($pattern, $this->rdnsPrefix . 'cache:') === 0) {
           $this->redis->expire($key, $this->ttlSettings['rdns_cache']);
       } elseif (strpos($pattern, $this->userHashPrefix . 'tracking:') === 0) {
           $this->redis->expire($key, $this->ttlSettings['user_hash_tracking']);
       } elseif (strpos($pattern, $this->userHashPrefix . 'blocked:') === 0) {
           $this->redis->expire($key, $this->ttlSettings['user_hash_blocked']);
       } elseif (strpos($pattern, $this->blockPrefix . 'ip:') === 0) {
           $this->redis->expire($key, $this->ttlSettings['ip_blocked']);
       } elseif (strpos($pattern, $this->cookiePrefix . 'blocked:') === 0) {
           $this->redis->expire($key, $this->ttlSettings['cookie_blocked']);
       } else {
           // Для неизвестных ключей - удаляем
           $this->redis->del($key);
       }
   }
   
   /**
    * Показывает детальную статистику
    */
   public function showDetailedStats() {
       $stats = $this->getStats();
       
       echo "\n" . str_repeat("=", 60) . "\n";
       echo "         BOT PROTECTION STATISTICS\n";
       echo str_repeat("=", 60) . "\n";
       
       echo "🔒 BLOCKED ITEMS:\n";
       echo "  - IPs:               " . $stats['blocked_ips'] . "\n";
       echo "  - User Hashes:       " . $stats['blocked_user_hashes'] . "\n";
       echo "  - Sessions:          " . $stats['blocked_sessions'] . "\n";
       echo "  - Cookies:           " . $stats['blocked_cookies'] . "\n";
       
       echo "\n📊 TRACKING DATA:\n";
       echo "  - IP Records:        " . $stats['tracking_ip_records'] . "\n";
       echo "  - User Hash Records: " . $stats['tracked_user_hashes'] . "\n";
       echo "  - Session Data:      " . $stats['session_data_records'] . "\n";
       echo "  - rDNS Cache:        " . $stats['rdns_cache_records'] . "\n";
       
       echo "\n📝 LOGS & STATS:\n";
       echo "  - Log Records:       " . $stats['log_records'] . "\n";
       echo "  - Stats Records:     " . $stats['stats_records'] . "\n";
       
       echo "\n💾 REDIS INFO:\n";
       echo "  - Total Keys:        " . $stats['total_keys'] . "\n";
       echo "  - Memory Usage:      " . $stats['memory_usage'] . "\n";
       echo "  - Expired Keys:      " . $stats['expired_keys'] . "\n";
       echo "  - Keys w/o TTL:      " . $stats['keys_without_ttl'] . "\n";
       
       echo str_repeat("=", 60) . "\n\n";
       
       return $stats;
   }
   
   public function __destruct() {
       if ($this->redis) {
           try {
               $this->redis->close();
           } catch (Exception $e) {
               // Игнорируем ошибки при закрытии
           }
       }
   }
}

// ============================================================================
// ОСНОВНОЙ СКРИПТ
// ============================================================================

function showUsage() {
   echo "\nUsage: php cleanup.php [OPTIONS]\n\n";
   echo "Options:\n";
   echo "  --help, -h          Show this help message\n";
   echo "  --stats, -s         Show detailed statistics only\n";
   echo "  --light, -l         Light cleanup (expired keys only)\n";
   echo "  --deep, -d          Deep cleanup (default)\n";
   echo "  --force, -f         Force cleanup without confirmation\n";
   echo "\nExamples:\n";
   echo "  php cleanup.php                 # Deep cleanup with confirmation\n";
   echo "  php cleanup.php --stats         # Show statistics only\n";
   echo "  php cleanup.php --light         # Light cleanup\n";
   echo "  php cleanup.php --force         # Force deep cleanup\n\n";
}

function askConfirmation($message) {
   echo $message . " (y/N): ";
   $handle = fopen("php://stdin", "r");
   $line = fgets($handle);
   fclose($handle);
   return strtolower(trim($line)) === 'y';
}

// Парсинг аргументов командной строки
$options = getopt("hsldf", ["help", "stats", "light", "deep", "force"]);

if (isset($options['h']) || isset($options['help'])) {
   showUsage();
   exit(0);
}

try {
   echo "Bot Protection Cleanup Tool v2.0\n";
   echo "Connecting to Redis...\n";
   
   $cleanup = new RedisBotProtectionCleanup();
   
   // Показать статистику
   if (isset($options['s']) || isset($options['stats'])) {
       $cleanup->showDetailedStats();
       exit(0);
   }
   
   // Показать статистику до очистки
   echo "\nBefore cleanup:\n";
   $statsBefore = $cleanup->showDetailedStats();
   
   $force = isset($options['f']) || isset($options['force']);
   $light = isset($options['l']) || isset($options['light']);
   
   if ($light) {
       // Легкая очистка
       if (!$force && !askConfirmation("Proceed with light cleanup?")) {
           echo "Cleanup cancelled.\n";
           exit(0);
       }
       
       echo "\nStarting light cleanup...\n";
       $cleaned = $cleanup->lightCleanup();
       
   } else {
       // Глубокая очистка (по умолчанию)
       if (!$force && !askConfirmation("Proceed with deep cleanup?")) {
           echo "Cleanup cancelled.\n";
           exit(0);
       }
       
       echo "\nStarting deep cleanup...\n";
       $cleaned = $cleanup->deepCleanup();
   }
   
   // Показать статистику после очистки
   echo "\nAfter cleanup:\n";
   $statsAfter = $cleanup->showDetailedStats();
   
   $keysDiff = $statsBefore['total_keys'] - $statsAfter['total_keys'];
   
   echo "🎉 CLEANUP SUMMARY:\n";
   echo "  - Items processed:   $cleaned\n";
   echo "  - Keys removed:      $keysDiff\n";
   echo "  - Memory before:     " . $statsBefore['memory_usage'] . "\n";
   echo "  - Memory after:      " . $statsAfter['memory_usage'] . "\n";
   echo "\nCleanup completed successfully!\n";
   
} catch (Exception $e) {
   echo "❌ Cleanup error: " . $e->getMessage() . "\n";
   exit(1);
}
?>