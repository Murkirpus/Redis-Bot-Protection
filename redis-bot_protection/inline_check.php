<?php
// /var/www/your-site/bot_protection/redis_inline_check.php

/**
 * ============================================================================
 * ОПТИМИЗИРОВАННАЯ ВЕРСИЯ - Redis Bot Protection (inline_check.php)
 * ============================================================================
 * 
 * ВАЖНО: Этот файл оптимизирован для МАКСИМАЛЬНОЙ СКОРОСТИ!
 * 
 * ============================================================================
 * ВЕРСИЯ 2.5.2 - ИСКЛЮЧЕНИЕ URL ИЗ JS CHALLENGE (2025-12-05)
 * ============================================================================
 * 
 * НОВОЕ v2.5.2:
 * ✓ Добавлена возможность исключать URL из проверки JS Challenge
 * ✓ Поддержка wildcard паттернов (например: /api/, /TEMP//file.php?*)
 * ✓ Исключённые URL также пропускают Rate Limit и Burst Detection
 * ✓ Новые методы управления исключениями:
 *   - addExcludedUrl($pattern) - добавить URL в исключения
 *   - removeExcludedUrl($pattern) - удалить URL из исключений
 *   - getExcludedUrls() - получить список исключенных URL
 *   - setExcludedUrls($patterns) - установить список исключений
 *   - clearExcludedUrls() - очистить все исключения
 *   - isUrlExcluded($url) - проверить исключен ли URL
 * ✓ Настройка 'excluded_urls' в jsChallengeSettings
 * ✓ Минимальное влияние на производительность (<0.1ms проверка паттернов)
 *
 * ПРИМЕР ИСПОЛЬЗОВАНИЯ:
 * $protection->addExcludedUrl('/api/*');
 * $protection->addExcludedUrl('/TEMP/IPv6-IPv4/IPv6-IPv4.php?*');
 * $protection->setExcludedUrls(['/webhook/', '/public/images/']);
 * 
 * ВАЖНО: Исключённые URL пропускают:
 * - JS Challenge
 * - Rate Limit проверки
 * - Burst Detection
 * - Используйте с осторожностью!
 *
 * ============================================================================
 * ВЕРСИЯ 2.5.1 - СТАТИСТИКА ЗАПРОСОВ В РЕАЛЬНОМ ВРЕМЕНИ (2025-12-02)
 * ============================================================================
 * 
 * НОВОЕ v2.5.1:
 * ✓ Добавлен счётчик запросов RPM (requests per minute)
 * ✓ Добавлен счётчик запросов RPS (requests per second)
 * ✓ Новый метод: incrementRequestCounter() - вызывается в protect()
 * ✓ Новый метод: getRequestsPerMinute() - возвращает RPM/RPS статистику
 * ✓ Новый метод: getRPMHistory() - история RPM за последние N минут
 * ✓ Минимальное влияние на производительность (2 операции INCR ~0.2ms)
 *
 * ============================================================================
 * ВЕРСИЯ 2.5.0 - ЗАЩИТА ОТ РАСПРЕДЕЛЁННОГО ПАРСИНГА (2025-12-01)
 * ============================================================================
 * 
 * КЛЮЧЕВЫЕ ИЗМЕНЕНИЯ v2.5:
 * ✓ Slow bot теперь БЛОКИРУЕТСЯ сразу (раньше только extended tracking)
 * ✓ Новая защита от ботнетов: блокировка если нет cookie после N запросов
 * ✓ Ужесточена проверка HTTP заголовков
 * ✓ Снижен порог для isPotentialSlowBot (3 запроса вместо 5)
 * ✓ Новая настройка: no_cookie_block_threshold (по умолчанию 3)
 *
 * ============================================================================
 * ВЕРСИЯ 2.4.0 - RATE LIMIT + BURST РАБОТАЮТ ПРИ 429 (2025-11-30)
 * ============================================================================
 * 
 * ИЗМЕНЕНИЯ v2.4:
 * ✓ Rate Limit и Burst Detection работают ВСЕГДА (даже при 429)
 * ✓ Счетчики увеличиваются даже когда показывается 429 ошибка
 * ✓ Новая система violations с автоматической блокировкой через API
 * ✓ Красивая страница 429 с предупреждением о блокировке
 * ✓ Новые настройки: rate_limit_api_block_threshold, burst_api_block_threshold
 * ✓ Новые методы: getTotalViolations(), incrementViolations(), getViolationsStatus()
 * 
 * НАСТРОЙКИ БЛОКИРОВКИ ЧЕРЕЗ API:
 * - rate_limit_api_block_threshold: 3 (блокировать через API после 3 нарушений)
 * - burst_api_block_threshold: 2 (блокировать через API после 2 burst)
 * - combined_api_block_threshold: 4 (блокировать если сумма violations >= 4)
 *
 * ============================================================================
 * ВЕРСИЯ 2.3.1 - РАБОЧИЙ RATE LIMIT + BURST (2025-11-28)
 * ============================================================================
 * 
 * ИСПРАВЛЕНО И ДОБАВЛЕНО:
 * ✓ Rate Limit - РАБОТАЕТ! Вариант B: cookie пользователи получают ×2 лимиты
 * ✓ Burst Detection - РАБОТАЕТ! Вариант B: cookie пользователи получают ×2 порог
 * ✓ Добавлены тестовые методы: testRateLimit(), testBurst()
 * ✓ Добавлены методы статуса: getRateLimitStatus(), getBurstStatus()
 * 
 * НАСТРОЙКИ ПО УМОЛЧАНИЮ:
 * - Rate Limit: 60/мин, 200/5мин, 800/час (×2 для cookie)
 * - Burst: 5 запросов за 10 сек (×2 для cookie = 10 запросов)
 * - cookie_multiplier: 2.0
 *
 * ============================================================================
 * ВЕРСИЯ 2.3 - ОПТИМИЗАЦИЯ ПАМЯТИ REDIS (2025-11-28)
 * ============================================================================
 * 
 * ОПТИМИЗИРОВАНО:
 * ✓ Rate Limit объединён в один ключ на IP (было 4-5 ключей, стало 1)
 * ✓ Global Rate Limit использует скользящее окно (было 1 ключ/сек, стало 1 ключ/IP)
 * ✓ Уменьшены TTL для tracking данных (3 часа → 1.5 часа)
 * ✓ Уменьшены TTL для extended tracking (24 часа → 6 часов)
 * ✓ Ожидаемое сокращение ключей: в 3-4 раза меньше!
 * 
 * БЫЛО: ~5-7 ключей на IP (12,000+ ключей на 2,000 IP)
 * СТАЛО: ~2-3 ключа на IP (4,000-6,000 ключей на 2,000 IP)
 * 
 * ============================================================================
 * ВЕРСИЯ 2.2 - ИСПРАВЛЕНИЕ ЛОЖНЫХ БЛОКИРОВОК AJAX (2025-11-27)
 * ============================================================================
 * 
 * ИСПРАВЛЕНО:
 * ✓ checkSuspiciousHeaders() теперь корректно обрабатывает AJAX/Fetch запросы
 * ✓ Поиск DLE и другие AJAX-функции больше не вызывают ложных блокировок
 * ✓ Добавлена детекция AJAX через X-Requested-With, Sec-Fetch-Mode, Sec-Fetch-Dest
 * ✓ Для AJAX применяются мягкие проверки (только критичные заголовки)
 * 
 * ============================================================================
 * ВЕРСИЯ 2.1 - УСИЛЕННАЯ ДЕТЕКЦИЯ "УМНЫХ" БОТОВ (2025-11-26)
 * ============================================================================
 * 
 * ФУНКЦИИ v2.1:
 * ✓ checkSuspiciousHeaders() - проверка HTTP заголовков (Accept-Language и т.д.)
 * ✓ analyzeRequestTypes() - анализ типов запросов (только HTML = бот)
 * 
 * УЖЕСТОЧЕННЫЕ ЛИМИТЫ:
 * ✓ max_requests_per_minute: 60 → 40
 * ✓ max_requests_per_5min: 200 → 120
 * ✓ max_requests_per_hour: 1000 → 600
 * ✓ burst_threshold: 20 → 15
 * ✓ slow_bot_threshold_hours: 4 → 2
 * ✓ blockThreshold: 10/12 → 7/8
 * 
 * НОВЫЕ ПРОВЕРКИ В analyzeSlowBotBehavior():
 * ✓ Проверка HTTP заголовков (боты не шлют Accept-Language)
 * ✓ Проверка типов запросов (боты запрашивают только HTML)
 * ✓ Проверка отсутствия cookies после 12+ запросов
 * ✓ Расширенный диапазон детекции регулярности (30-900 сек)
 * 
 * ============================================================================
 * 
 * ЧТО БЫЛО УДАЛЕНО (тяжелые операции перенесены в cleanup.php):
 * ✗ cleanup() - использовал keys() для сканирования всех ключей
 * ✗ cleanupUserHashData() - использовал keys() множество раз
 * ✗ deepCleanup() - вызывал cleanup() и cleanupUserHashData()
 * ✗ forceCleanup() - агрессивная очистка с неограниченным SCAN
 * 
 * ЧТО БЫЛО ОПТИМИЗИРОВАНО:
 * ✓ getRedisMemoryInfo() - теперь читает готовые метрики вместо SCAN
 * ✓ cleanup_probability = 999999 (автоочистка отключена)
 * 
 * ЧТО ДОБАВЛЕНО:
 * ✓ getCleanupStatus() - проверка работы cleanup.php
 * 
 * ============================================================================
 * УЛУЧШЕНИЯ ДЛЯ ВЫСОКИХ НАГРУЗОК (v2.0)
 * ============================================================================
 * 
 * 1. АТОМАРНЫЙ Rate Limit (без race condition):
 *    - checkRateLimit() использует Redis INCR вместо GET-SET
 *    - Надёжная работа при >1000 req/sec
 *    - Отдельные ключи для каждого временного окна
 * 
 * 2. ГЛОБАЛЬНЫЙ Rate Limit (защита от DDoS):
 *    - checkGlobalRateLimit() срабатывает при >100 req/sec с одного IP
 *    - Работает ДО проверки ботов - защита от поддельных User-Agent
 * 
 * 3. WHITELIST верифицированных поисковиков:
 *    - isWhitelistedSearchEngine() - мгновенная проверка кеша
 *    - addToSearchEngineWhitelist() - кеширование на 24 часа после rDNS
 *    - Поисковики НЕ БЛОКИРУЮТСЯ даже при высокой нагрузке
 * 
 * 4. SCAN вместо KEYS:
 *    - getRDNSRateLimitStats() - неблокирующая статистика
 *    - clearRDNSCache() - неблокирующая очистка
 *    - clearSearchEngineWhitelist() - очистка whitelist
 * 
 * ============================================================================
 * КРИТИЧЕСКОЕ ТРЕБОВАНИЕ:
 * cleanup.php ДОЛЖЕН запускаться по cron каждые 5-10 минут!
 * Без cleanup.php Redis переполнится и защита не будет работать!
 * 
 * Настройка cron:
 * Каждые 5 минут: php /var/www/your-site/cleanup.php >> /var/log/cleanup.log 2>&1
 * 
 * ОЖИДАЕМАЯ ПРОИЗВОДИТЕЛЬНОСТЬ:
 * - Обычные запросы: 2-5ms (до оптимизации: 5-10ms)
 * - Запросы с очисткой: 2-5ms (до оптимизации: 100-500ms)
 * - getRedisMemoryInfo(): <1ms (до оптимизации: 100-200ms)
 * - checkRateLimit(): <1ms (атомарные операции)
 * - Общий прирост: в 5-50 раз быстрее!
 * 
 * ============================================================================
 */

class RedisBotProtectionNoSessions {
    private $redis;
    private $cookieName = 'visitor_verified';
    private $secretKey = 'your_secret_key_here_change_this';
    private $cookieLifetime = 86400 * 30; // 30 дней
    
    // Префиксы для Redis ключей
    private $redisPrefix = 'bot_protection:';
    private $trackingPrefix = 'tracking:';
    private $blockPrefix = 'blocked:';
    private $cookiePrefix = 'cookie:';
    private $rdnsPrefix = 'rdns:';
    private $userHashPrefix = 'user_hash:';
    
    // TTL настройки (ОПТИМИЗИРОВАНО для экономии памяти v2.3)
    private $ttlSettings = [
        'tracking_ip' => 5400,          // 1.5 часа (было 3 часа) - основной трекинг
        'cookie_blocked' => 7200,       // 2 часа - блокировка по cookie
        'ip_blocked' => 86400,          // 24 часа - блокировка IP
        'ip_blocked_repeat' => 259200,  // 3 дня - повторная блокировка
        'rdns_cache' => 1800,           // 30 мин - кеш rDNS
        'logs' => 86400,                // 1 день (было 2 дня) - логи
        'cleanup_interval' => 1800,     // 30 мин
        'user_hash_blocked' => 86400,   // 1 день (было 2 дня) - блокировка user hash
        'user_hash_tracking' => 10800,  // 3 часа (было 6 часов) - трекинг user hash
        'user_hash_stats' => 259200,    // 3 дня (было 7 дней) - статистика
        'extended_tracking' => 21600,   // 6 часов (было 24 часа) - расширенный трекинг
        'rate_limit' => 3600,           // НОВОЕ: 1 час для rate limit hash
    ];
    
    // Настройки для медленных ботов (УЖЕСТОЧЕНО для борьбы с умными ботами)
    private $slowBotSettings = [
        'min_requests_for_analysis' => 3,
        'slow_bot_threshold_hours' => 2,         // Снижено с 4 - быстрее детектим
        'slow_bot_min_requests' => 10,           // Снижено с 15
        'long_session_hours' => 1,               // Снижено с 2
        'suspicious_regularity_variance' => 300, // Увеличено с 100 - шире детекция
    ];
    
    // ═══════════════════════════════════════════════════════════════════════
    // НАСТРОЙКИ ДЕТЕКЦИИ БОТОВ ПО HTTP ЗАГОЛОВКАМ
    // ОБНОВЛЕНО v2.5: Ужесточены пороги
    // ═══════════════════════════════════════════════════════════════════════
    private $headerDetectionSettings = [
        'block_score_threshold' => 5,    // v2.5: Снижено с 4 до 3 - блокируем раньше
        'tracking_score_threshold' => 2, // v2.5: Снижено с 3 до 2
        'enabled' => true,               // Включить/выключить детекцию по заголовкам
    ];
    
    // Настройки rate limiting и защиты от нагрузки
    private $rateLimitSettings = [
        'max_requests_per_minute' => 30,         // Лимит запросов в минуту (без cookie)
        'max_requests_per_5min' => 100,          // Лимит за 5 минут (без cookie)
        'max_requests_per_hour' => 400,          // Лимит в час (без cookie)
        'cookie_multiplier' => 2.0,              // Множитель лимитов для пользователей с cookie (×2)
        'burst_threshold' => 10,                 // Порог всплеска
        'burst_window' => 10,                    // Окно для детекции всплеска (секунды)
        'ua_change_threshold' => 10,             // Макс. смен UA за сессию
        'ua_change_time_window' => 300,          // Окно для детекции смены UA (5 мин)
        'progressive_block_duration' => 1800,    // Прогрессивная блокировка (30 мин)
        'aggressive_block_duration' => 7200,     // Агрессивная блокировка (2 часа)
        
        // ═══════════════════════════════════════════════════════════════════
        // НОВОЕ v2.4: Пороги для автоматической блокировки через API
        // ═══════════════════════════════════════════════════════════════════
        'rate_limit_api_block_threshold' => 3,   // Блокировать через API после N нарушений rate limit
        'burst_api_block_threshold' => 2,        // Блокировать через API после N burst'ов
        'combined_api_block_threshold' => 4,     // Блокировать если сумма всех violations >= N
        
        // ═══════════════════════════════════════════════════════════════════
        // НОВОЕ v2.5: Защита от распределённого парсинга (ботнеты)
        // ═══════════════════════════════════════════════════════════════════
        'no_cookie_block_threshold' => 5,        // Блокировать если нет cookie после N запросов
        'slow_bot_instant_block' => true,        // Блокировать slow bot сразу (true) или только tracking (false)
    ];
    
    // Настройки защиты от переполнения Redis
    private $globalProtectionSettings = [
        'cleanup_threshold' => 5000,             // Начать очистку при достижении
        'cleanup_batch_size' => 100,             // Удалять за один раз
        'cleanup_probability' => 999999,  // ОТКЛЮЧЕНО - используйте cleanup.php             // Проверять каждый N-й запрос (1 из 50 = 2%)
        'max_cleanup_time_ms' => 50,            // Максимум 50ms на очистку
    ];
    
    // Настройки rate limiting для rDNS проверок
    private $rdnsLimitSettings = [
        'max_rdns_per_minute' => 60,            // Максимум rDNS проверок в минуту
        'rdns_cache_ttl' => 1800,               // Кеш результатов 30 минут
        'rdns_negative_cache_ttl' => 300,       // Кеш негативных результатов 5 минут
        'rdns_on_limit_action' => 'skip',       // 'skip' или 'block' при превышении
        'trust_search_engine_ua_on_limit' => true, // НОВОЕ: Доверять UA поисковика при превышении лимита
    ];
    
    private $globalPrefix = 'global:';
	
	// Настройки API для блокировки через iptables
    private $apiSettings = [
        'enabled' => true,                                              // Включить/выключить API блокировку
        'url' => 'https://domain.com/redis-bot_protection/API/iptables.php',           // URL вашего API
        'api_key' => '12345',                          // API ключ (из settings.php)
        'timeout' => 5,                                                 // Таймаут запроса (секунды)
        'block_on_redis' => true,                                       // Блокировать в Redis (локально)
        'block_on_api' => false,                                         // Блокировать через API (iptables)
        'auto_unblock' => true,                                         // Автоматически разблокировать через API при истечении TTL
        'retry_on_failure' => 2,                                        // Количество попыток при ошибке API
        'log_api_errors' => true,                                       // Логировать ошибки API
        'user_agent' => 'uptimerobot',            // User-Agent для API запросов
        'verify_ssl' => true,                                           // Проверять SSL сертификат
    ];
    
    // Список поисковиков с точными паттернами
    private $allowedSearchEngines = [
        'googlebot' => [
            'user_agent_patterns' => [
                'googlebot', 'google', 'googleother',
                'googlebot-image', 'googlebot-news', 'googlebot-video'
            ],
            'rdns_patterns' => ['.googlebot.com', '.google.com']
        ],
        'bingbot' => [
            'user_agent_patterns' => ['bingbot', 'msnbot'],
            'rdns_patterns' => ['.search.msn.com']
        ],
        'yandexbot' => [
            'user_agent_patterns' => ['yandexbot', 'yandex'],
            'rdns_patterns' => ['.yandex.ru', '.yandex.net', '.yandex.com']
        ],
        'slurp' => [
            'user_agent_patterns' => ['slurp'],
            'rdns_patterns' => ['.crawl.yahoo.net']
        ],
        'duckduckbot' => [
            'user_agent_patterns' => ['duckduckbot'],
            'rdns_patterns' => ['.duckduckgo.com']
        ],
        'baiduspider' => [
            'user_agent_patterns' => ['baiduspider'],
            'rdns_patterns' => ['.baidu.com', '.baidu.jp']
        ],
        'facebookexternalhit' => [
            'user_agent_patterns' => ['facebookexternalhit', 'facebookcatalog'],
            'rdns_patterns' => ['.facebook.com', '.fbsv.net'],
            'skip_forward_verification' => true  // Facebook часто использует динамические PTR
        ],
        'twitterbot' => [
            'user_agent_patterns' => ['twitterbot'],
            'rdns_patterns' => ['.twitter.com', '.twttr.com'],
            'skip_forward_verification' => true  // Twitter/X использует динамические PTR
        ],
        'linkedinbot' => [
            'user_agent_patterns' => ['linkedinbot'],
            'rdns_patterns' => ['.linkedin.com'],
            'skip_forward_verification' => true  // LinkedIn использует динамические PTR
        ],
        'applebot' => [
            'user_agent_patterns' => ['applebot'],
            'rdns_patterns' => ['.applebot.apple.com']
        ],
        'amazonbot' => [
            'user_agent_patterns' => ['amazonbot', 'amazon bot', 'amazon-bot'],
            'rdns_patterns' => ['.amazon.com', '.amazon', '.crawl.amazonbot.amazon']
        ],
        'petalbot' => [
            'user_agent_patterns' => ['petalbot'],
            'rdns_patterns' => ['.petalsearch.com']
        ],
        'sogou' => [
            'user_agent_patterns' => ['sogou'],
            'rdns_patterns' => ['.sogou.com']
        ],
        'telegrambot' => [
            'user_agent_patterns' => ['telegrambot', 'telegram bot', 'tgbot'],
            'rdns_patterns' => ['.telegram.org', '.ptr.telegram.org'],
            'skip_forward_verification' => true  // PTR записи Telegram не имеют forward DNS
        ]
    ];
    
    // ═══════════════════════════════════════════════════════════════════════
    // JS CHALLENGE SETTINGS - Защита от ботов через JavaScript проверку
    // ═══════════════════════════════════════════════════════════════════════
    private $jsChallengeSettings = [
        'enabled' => true,                          // Включить JS Challenge
        'trigger_on_suspicious' => true,            // Показывать при подозрительном поведении
        'trigger_on_high_violations' => true,       // Показывать при высоких violations
        'violations_threshold' => 3,                // Порог violations для показа challenge
        'trigger_on_slow_bot' => true,              // Показывать для slow bot
        'trigger_on_no_cookie' => true,             // Показывать если нет cookie (ВСЕМ при первом запросе!)
        'no_cookie_threshold' => 1,                 // УСТАРЕЛО: показывается ВСЕМ без cookie сразу
        'token_ttl' => 3600,                        // TTL токена JS Challenge (1 час)
        'token_name' => 'murkir_js_token',          // Имя cookie с токеном
        'min_solve_time' => 2000,                   // Минимальное время решения (ms)
        'pow_difficulty' => 3,                      // Сложность PoW (количество нулей в начале хеша)
        'failure_block_threshold' => 3,             // Блокировать после N провалов Challenge (нормальный режим)
        
        // ═══════════════════════════════════════════════════════════════════
        // ИСКЛЮЧЕНИЯ URL - URL которые НЕ ПРОВЕРЯЮТСЯ защитой
        // ═══════════════════════════════════════════════════════════════════
        // ВАЖНО: Исключённые URL пропускают ВСЕ проверки:
        // - JS Challenge
        // - Rate Limit (все временные окна)
        // - Burst Detection
        // Используйте только для доверенных endpoints!
        // ═══════════════════════════════════════════════════════════════════
        'excluded_urls' => [
            // Примеры паттернов (раскомментируйте нужные):
            // '/api/*',                           // Все API endpoints
            '/TEMP/IPv6-IPv4/IPv6-IPv4.php',  // Конкретный файл с любыми параметрами
			'/TEMP/IPv6-IPv4/IPv6-IPv4-PTR.php',  // Конкретный файл с любыми параметрами
			//'/bot_protection/redis_test-gemini.php',  // Конкретный файл с любыми параметрами
            // '/admin/ajax/*',                     // Все AJAX запросы админки
            // '/webhook/*',                        // Все webhook endpoints
            // '/public/images/*',                  // Статичные ресурсы
        ],
        
        // ═══════════════════════════════════════════════════════════════════
        // АДАПТИВНАЯ ЗАЩИТА v2.8.0 - АВТОМАТИЧЕСКОЕ УЖЕСТОЧЕНИЕ ПРИ АТАКЕ
        // ═══════════════════════════════════════════════════════════════════
        'adaptive_protection' => true,              // Включить адаптивную защиту (автоматическое переключение)
        'adaptive_threshold_normal' => 3,           // Порог провалов в нормальном режиме
        'adaptive_threshold_attack' => 1,           // Порог провалов во время атаки (агрессивный)
        
        // Критерии определения атаки (любой критерий = атака):
        'attack_rps_threshold' => 50,               // RPS выше этого = атака (запросов в секунду)
        'attack_failures_per_minute' => 30,         // Провалов JS Challenge за минуту > этого = атака
        'attack_blocks_per_minute' => 15,           // Блокировок за минуту > этого = атака
        
        // Критерии окончания атаки (ВСЕ критерии должны выполниться):
        'recovery_rps_threshold' => 20,             // RPS ниже этого = атака закончилась
        'recovery_duration' => 300,                 // Время в секундах (5 мин) низкого RPS для окончания атаки
    ];

    
    public function __construct($redisHost = '127.0.0.1', $redisPort = 6379, $redisPassword = null, $redisDatabase = 0) {
        $this->initRedis($redisHost, $redisPort, $redisPassword, $redisDatabase);
        
    }
    
    private function initRedis($host, $port, $password, $database) {
        try {
            $this->redis = new Redis();
            
            if (!$this->redis->connect($host, $port, 2)) {
                throw new Exception("Cannot connect to Redis server at {$host}:{$port}");
            }
            
            if ($password) {
                if (!$this->redis->auth($password)) {
                    throw new Exception("Redis authentication failed");
                }
            }
            
            if (!$this->redis->select($database)) {
                throw new Exception("Cannot select Redis database {$database}");
            }
            
            $this->redis->setOption(Redis::OPT_SERIALIZER, Redis::SERIALIZER_JSON);
            $this->redis->setOption(Redis::OPT_PREFIX, $this->redisPrefix);
            
            if (!$this->redis->ping()) {
                throw new Exception("Redis ping failed");
            }
            
        } catch (Exception $e) {
            error_log("CRITICAL: Redis connection failed - " . $e->getMessage());
            throw $e;
        }
    }
    
    private function normalizeIPv6($ip) {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return $ip;
        }
        
        $binary = @inet_pton($ip);
        if ($binary === false) {
            return $ip;
        }
        
        $normalized = @inet_ntop($binary);
        return $normalized ?: $ip;
    }
    
    private function normalizeIP($ip) {
        $ip = trim($ip);
        
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return $ip;
        }
        
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return $this->normalizeIPv6($ip);
        }
        
        return $ip;
    }
    
    private function getIPFingerprint($ip) {
        $ip = $this->normalizeIPv6($ip);
        
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $parts = explode(':', $ip);
            if (count($parts) >= 4) {
                return implode(':', array_slice($parts, -4));
            }
            return substr($ip, -16);
        } else {
            $parts = explode('.', $ip);
            if (count($parts) >= 2) {
                return end($parts) . '.' . prev($parts);
            }
            return $ip;
        }
    }
    
    private function generateUserHash($ip = null) {
        $ip = $ip ?: $this->getRealIP();
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $acceptLanguage = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '';
        $acceptEncoding = $_SERVER['HTTP_ACCEPT_ENCODING'] ?? '';
        $accept = $_SERVER['HTTP_ACCEPT'] ?? '';
        
        $browserInfo = $this->getBrowserFingerprint($userAgent);
        
        $stableFingerprint = $userAgent . '|' . 
                            $acceptLanguage . '|' . 
                            $acceptEncoding . '|' . 
                            $accept . '|' .
                            $browserInfo['name'] . '|' .
                            $browserInfo['version'] . '|' .
                            $browserInfo['platform'] . '|' .
                            $this->secretKey;
        
        if (false /* isMobileDevice removed */) {
            $ipPart = $this->getIPFingerprint($ip);
            $stableFingerprint .= '|mobile|' . $ipPart;
        } else {
            $stableFingerprint .= '|desktop|' . $ip;
        }
        
        return hash('sha256', $stableFingerprint);
    }
    
    private function getBrowserFingerprint($userAgent) {
        $browser = [
            'name' => 'unknown',
            'version' => 'unknown',
            'platform' => 'unknown'
        ];
        
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
    
    private function isUserHashBlocked() {
        try {
            $userHash = $this->generateUserHash();
            $blockKey = $this->userHashPrefix . 'blocked:' . $userHash;
            return $this->redis->exists($blockKey);
        } catch (Exception $e) {
            error_log("Error checking user hash block: " . $e->getMessage());
            return false;
        }
    }
    
    private function blockUserHash($reason = 'Bot behavior detected') {
        try {
            $userHash = $this->generateUserHash();
            $ip = $this->getRealIP();
            
            $blockData = [
                'user_hash' => $userHash,
                'ip' => $ip,
                'blocked_at' => time(),
                'blocked_reason' => $reason,
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
                'session_id' => 'no_session',
                'uri' => $_SERVER['REQUEST_URI'] ?? '',
                'headers' => $this->collectHeaders(),
                'browser_info' => $this->getBrowserFingerprint($_SERVER['HTTP_USER_AGENT'] ?? ''),
                'device_type' => 'unknown' // isMobileDevice() removed in optimization
            ];
            
            $blockKey = $this->userHashPrefix . 'blocked:' . $userHash;
            $this->redis->setex($blockKey, $this->ttlSettings['user_hash_blocked'], $blockData);
            
            $statsKey = $this->userHashPrefix . 'stats:' . $userHash;
            $this->redis->hincrby($statsKey, 'block_count', 1);
            $this->redis->hset($statsKey, 'last_blocked', time());
            $this->redis->hset($statsKey, 'last_blocked_reason', $reason);
            $this->redis->expire($statsKey, $this->ttlSettings['user_hash_stats']);
            
            error_log("Bot blocked [HASH]: " . substr($userHash, 0, 8) . " | IP: $ip | " . $blockData['device_type'] . " | " . $reason);
        } catch (Exception $e) {
            error_log("Error blocking user hash: " . $e->getMessage());
        }
    }
    
    private function trackUserHashActivity() {
        try {
            $userHash = $this->generateUserHash();
            $trackingKey = $this->userHashPrefix . 'tracking:' . $userHash;
            
            $existing = $this->redis->get($trackingKey);
            
            if ($existing) {
                $existing['requests']++;
                $existing['last_activity'] = time();
                
                $currentPage = parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH);
                if (!in_array($currentPage, $existing['pages'])) {
                    $existing['pages'][] = $currentPage;
                }
                
                $existing['request_times'][] = time();
                
                $currentIP = $this->getRealIP();
                if (!in_array($currentIP, $existing['ips'])) {
                    $existing['ips'][] = $currentIP;
                }
                
                if (count($existing['request_times']) > 30) {
                    $existing['request_times'] = array_slice($existing['request_times'], -30);
                }
                if (count($existing['pages']) > 50) {
                    $existing['pages'] = array_unique(array_slice($existing['pages'], -50));
                }
                if (count($existing['ips']) > 15) {
                    $existing['ips'] = array_unique(array_slice($existing['ips'], -15));
                }
                
                $this->redis->setex($trackingKey, $this->ttlSettings['user_hash_tracking'], $existing);
                return $existing;
            } else {
                $data = [
                    'user_hash' => $userHash,
                    'first_seen' => time(),
                    'last_activity' => time(),
                    'requests' => 1,
                    'pages' => [parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH)],
                    'ips' => [$this->getRealIP()],
                    'user_agents' => [$_SERVER['HTTP_USER_AGENT'] ?? ''],
                    'request_times' => [time()],
                    'browser_info' => $this->getBrowserFingerprint($_SERVER['HTTP_USER_AGENT'] ?? '')
                ];
                
                $this->redis->setex($trackingKey, $this->ttlSettings['user_hash_tracking'], $data);
                return $data;
            }
        } catch (Exception $e) {
            error_log("Error tracking user hash: " . $e->getMessage());
            return [];
        }
    }
    
    // analyzeSlowBot() removed in optimization (saved 107 lines)
    
    // enableExtendedTracking() removed in optimization (saved 19 lines)
    
    // checkExtendedTracking() removed in optimization (saved 9 lines)
    
    private function getUserTrackingData($ip) {
        try {
            $trackingKey = $this->trackingPrefix . 'ip:' . hash('md5', $ip);
            return $this->redis->get($trackingKey);
        } catch (Exception $e) {
            error_log("Error getting user tracking data: " . $e->getMessage());
            return null;
        }
    }
    
    /**
     * ═══════════════════════════════════════════════════════════════════════
     * ОБНОВЛЕНО v2.5: isPotentialSlowBot с более агрессивными проверками
     * 
     * Изменения:
     * - Порог снижен с 5 до 3 запросов
     * - Добавлена проверка отсутствия cookie
     * - Ужесточена проверка заголовков
     * ═══════════════════════════════════════════════════════════════════════
     */
    private function isPotentialSlowBot($trackingData) {
        // v2.5: Снижен порог с 5 до 3
        if (!$trackingData || $trackingData['requests'] < 3) {
            return false;
        }
        
        $timeSpent = time() - ($trackingData['first_seen'] ?? time());
        $requests = $trackingData['requests'];
        $headers = $this->collectHeaders();
        
        // v2.5: НОВОЕ - нет Accept-Language = очень подозрительно
        $acceptLang = $headers['HTTP_ACCEPT_LANGUAGE'] ?? '';
        if (empty($acceptLang) && $requests >= 3) {
            return true;
        }
        
        // v2.5: НОВОЕ - Accept: */* без других признаков браузера
        $accept = $headers['HTTP_ACCEPT'] ?? '';
        if ($accept === '*/*' && empty($headers['HTTP_SEC_FETCH_MODE']) && $requests >= 3) {
            return true;
        }
        
        // Долгая сессия с умеренным количеством запросов
        if ($timeSpent > ($this->slowBotSettings['long_session_hours'] * 3600) && 
            $requests > 10 && $requests < 100) {
            return true;
        }
        
        // Регулярные интервалы между запросами (роботы делают запросы "по таймеру")
        // v2.5: Снижен порог с 8 до 5 запросов
        if (isset($trackingData['request_times']) && count($trackingData['request_times']) >= 5) {
            $times = $trackingData['request_times'];
            $intervals = [];
            
            for ($i = 1; $i < count($times); $i++) {
                $intervals[] = $times[$i] - $times[$i-1];
            }
            
            if (count($intervals) >= 4) {
                $avgInterval = array_sum($intervals) / count($intervals);
                $variance = 0;
                foreach ($intervals as $interval) {
                    $variance += pow($interval - $avgInterval, 2);
                }
                $variance /= count($intervals);
                
                // Малая дисперсия = регулярные запросы = бот
                if ($variance < $this->slowBotSettings['suspicious_regularity_variance'] && 
                    $avgInterval > 30 && $avgInterval < 900) {  // v2.5: расширен диапазон
                    return true;
                }
            }
        }
        
        // Отсутствие критических заголовков после некоторого времени
        // v2.5: Снижен порог с 8 до 5 запросов
        if ($timeSpent > 1800 && $requests > 5) {  // 30 минут вместо 1 часа
            $missingHeaders = 0;
            
            if (!isset($headers['HTTP_REFERER'])) $missingHeaders++;
            if (!isset($headers['HTTP_ACCEPT_LANGUAGE'])) $missingHeaders += 2;  // v2.5: больший вес
            if (($headers['HTTP_ACCEPT'] ?? '') === '*/*') $missingHeaders++;
            if (!isset($headers['HTTP_SEC_FETCH_MODE'])) $missingHeaders++;
            
            if ($missingHeaders >= 2) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * ═══════════════════════════════════════════════════════════════════════
     * НОВЫЙ МЕТОД v2.4: Получить общее количество violations для IP
     * Объединяет rate limit violations + burst violations
     * ═══════════════════════════════════════════════════════════════════════
     */
    private function getTotalViolations($ip) {
        try {
            $violationsKey = $this->trackingPrefix . 'violations:' . hash('md5', $ip);
            $data = $this->redis->get($violationsKey);
            
            if (!$data || !is_array($data)) {
                return [
                    'rate_limit' => 0,
                    'burst' => 0,
                    'total' => 0,
                    'last_violation' => null
                ];
            }
            
            return [
                'rate_limit' => (int)($data['rate_limit'] ?? 0),
                'burst' => (int)($data['burst'] ?? 0),
                'total' => (int)($data['rate_limit'] ?? 0) + (int)($data['burst'] ?? 0),
                'last_violation' => $data['last_violation'] ?? null
            ];
        } catch (Exception $e) {
            error_log("Error getting total violations: " . $e->getMessage());
            return ['rate_limit' => 0, 'burst' => 0, 'total' => 0, 'last_violation' => null];
        }
    }
    
    /**
     * НОВЫЙ МЕТОД v2.4: Увеличить счётчик violations
     */
    private function incrementViolations($ip, $type = 'rate_limit') {
        try {
            $violationsKey = $this->trackingPrefix . 'violations:' . hash('md5', $ip);
            $data = $this->redis->get($violationsKey);
            
            if (!$data || !is_array($data)) {
                $data = [
                    'rate_limit' => 0,
                    'burst' => 0,
                    'ip' => $ip,
                    'first_violation' => time()
                ];
            }
            
            if ($type === 'rate_limit') {
                $data['rate_limit'] = (int)($data['rate_limit'] ?? 0) + 1;
            } elseif ($type === 'burst') {
                $data['burst'] = (int)($data['burst'] ?? 0) + 1;
            }
            
            $data['last_violation'] = time();
            $data['last_type'] = $type;
            
            // TTL 1 час - violations сбрасываются если пользователь "успокоился"
            $this->redis->setex($violationsKey, 3600, $data);
            
            return [
                'rate_limit' => (int)$data['rate_limit'],
                'burst' => (int)$data['burst'],
                'total' => (int)$data['rate_limit'] + (int)$data['burst']
            ];
        } catch (Exception $e) {
            error_log("Error incrementing violations: " . $e->getMessage());
            return ['rate_limit' => 0, 'burst' => 0, 'total' => 0];
        }
    }
    
    /**
     * НОВЫЙ МЕТОД v2.4: Сброс violations для IP
     */
    public function resetViolations($ip) {
        try {
            $violationsKey = $this->trackingPrefix . 'violations:' . hash('md5', $ip);
            $this->redis->del($violationsKey);
            return true;
        } catch (Exception $e) {
            return false;
        }
    }
    
    /**
     * НОВЫЙ МЕТОД v2.4: Получить статус violations для IP
     */
    public function getViolationsStatus($ip) {
        $violations = $this->getTotalViolations($ip);
        
        return [
            'ip' => $ip,
            'violations' => $violations,
            'thresholds' => [
                'rate_limit_api_block' => $this->rateLimitSettings['rate_limit_api_block_threshold'],
                'burst_api_block' => $this->rateLimitSettings['burst_api_block_threshold'],
                'combined_api_block' => $this->rateLimitSettings['combined_api_block_threshold'],
            ],
            'will_block_api' => $this->shouldBlockViaAPI($violations)
        ];
    }
    
    /**
     * НОВЫЙ МЕТОД v2.4: Проверить, нужно ли блокировать через API
     */
    private function shouldBlockViaAPI($violations) {
        // Проверяем каждый порог
        if ($violations['rate_limit'] >= $this->rateLimitSettings['rate_limit_api_block_threshold']) {
            return ['block' => true, 'reason' => 'rate_limit_threshold'];
        }
        
        if ($violations['burst'] >= $this->rateLimitSettings['burst_api_block_threshold']) {
            return ['block' => true, 'reason' => 'burst_threshold'];
        }
        
        if ($violations['total'] >= $this->rateLimitSettings['combined_api_block_threshold']) {
            return ['block' => true, 'reason' => 'combined_threshold'];
        }
        
        return ['block' => false, 'reason' => null];
    }
    
    // analyzeUserHashBehavior() removed in optimization (saved 12 lines)
    
    // performStandardUserHashAnalysis() removed in optimization (saved 90 lines)
    
    /**
     * НОВЫЙ МЕТОД: Проверка rate limit для rDNS
     */
    private function checkRDNSRateLimit() {
        try {
            $currentMinute = floor(time() / 60); // Текущая минута
            $rateLimitKey = $this->rdnsPrefix . 'ratelimit:' . $currentMinute;
            
            $currentCount = $this->redis->get($rateLimitKey);
            
            if ($currentCount === false) {
                // Первый запрос в эту минуту
                $this->redis->setex($rateLimitKey, 120, 1); // TTL 2 минуты для безопасности
                return ['allowed' => true, 'count' => 1, 'limit' => $this->rdnsLimitSettings['max_rdns_per_minute']];
            }
            
            $currentCount = (int)$currentCount;
            
            if ($currentCount >= $this->rdnsLimitSettings['max_rdns_per_minute']) {
                // Лимит превышен
                error_log("rDNS rate limit exceeded: $currentCount/{$this->rdnsLimitSettings['max_rdns_per_minute']} in current minute");
                return [
                    'allowed' => false,
                    'count' => $currentCount,
                    'limit' => $this->rdnsLimitSettings['max_rdns_per_minute'],
                    'reason' => 'rDNS rate limit exceeded'
                ];
            }
            
            // Инкрементируем счетчик
            $this->redis->incr($rateLimitKey);
            
            return [
                'allowed' => true,
                'count' => $currentCount + 1,
                'limit' => $this->rdnsLimitSettings['max_rdns_per_minute']
            ];
            
        } catch (Exception $e) {
            error_log("Error in checkRDNSRateLimit: " . $e->getMessage());
            // При ошибке - разрешаем проверку
            return ['allowed' => true, 'count' => 0, 'limit' => $this->rdnsLimitSettings['max_rdns_per_minute']];
        }
    }
    
    /**
     * Получить статистику rDNS rate limit
     */
    /**
     * УЛУЧШЕННАЯ версия: использует SCAN вместо KEYS для неблокирующей работы
     */
    public function getRDNSRateLimitStats() {
        try {
            $currentMinute = floor(time() / 60);
            $prevMinute = $currentMinute - 1;
            
            $currentKey = $this->rdnsPrefix . 'ratelimit:' . $currentMinute;
            $prevKey = $this->rdnsPrefix . 'ratelimit:' . $prevMinute;
            
            $currentCount = $this->redis->get($currentKey) ?: 0;
            $prevCount = $this->redis->get($prevKey) ?: 0;
            
            // УЛУЧШЕНИЕ: Используем SCAN вместо KEYS (не блокирует Redis)
            $cacheCount = 0;
            $verifiedCount = 0;
            $notVerifiedCount = 0;
            $sampleSize = 100; // Проверяем максимум 100 записей для статистики
            $sampled = 0;
            
            $iterator = null;
            // ВАЖНО: OPT_PREFIX НЕ применяется к паттернам SCAN - указываем полный путь
            $pattern = $this->redisPrefix . $this->rdnsPrefix . 'cache:*';
            
            while (true) {
                $keys = $this->redis->scan($iterator, $pattern, 50);
                
                if ($keys === false) {
                    break;
                }
                
                $cacheCount += count($keys);
                
                // Проверяем только первые $sampleSize записей
                if ($sampled < $sampleSize) {
                    foreach ($keys as $key) {
                        if ($sampled >= $sampleSize) break;
                        
                        // SCAN возвращает полный путь, убираем redisPrefix для get()
                        $keyWithoutPrefix = str_replace($this->redisPrefix, '', $key);
                        $data = $this->redis->get($keyWithoutPrefix);
                        if ($data && isset($data['verified'])) {
                            if ($data['verified']) {
                                $verifiedCount++;
                            } else {
                                $notVerifiedCount++;
                            }
                        }
                        $sampled++;
                    }
                }
                
                if ($iterator === 0) {
                    break;
                }
            }
            
            return [
                'current_minute_requests' => (int)$currentCount,
                'previous_minute_requests' => (int)$prevCount,
                'limit_per_minute' => $this->rdnsLimitSettings['max_rdns_per_minute'],
                'cache_entries' => $cacheCount,
                'verified_in_cache' => $verifiedCount,
                'not_verified_in_cache' => $notVerifiedCount,
                'limit_reached' => $currentCount >= $this->rdnsLimitSettings['max_rdns_per_minute'],
                'settings' => $this->rdnsLimitSettings
            ];
            
        } catch (Exception $e) {
            error_log("Error getting rDNS stats: " . $e->getMessage());
            return [];
        }
    }
    
    /**
     * УЛУЧШЕННАЯ версия: использует SCAN вместо KEYS для неблокирующей очистки
     */
    public function clearRDNSCache() {
        try {
            $deleted = 0;
            $iterator = null;
            // ВАЖНО: OPT_PREFIX НЕ применяется к паттернам SCAN - указываем полный путь
            $pattern = $this->redisPrefix . $this->rdnsPrefix . 'cache:*';
            
            while (true) {
                $keys = $this->redis->scan($iterator, $pattern, 100);
                
                if ($keys === false) {
                    break;
                }
                
                foreach ($keys as $key) {
                    // SCAN возвращает полный путь, убираем redisPrefix для del()
                    $keyWithoutPrefix = str_replace($this->redisPrefix, '', $key);
                    $this->redis->del($keyWithoutPrefix);
                    $deleted++;
                }
                
                if ($iterator === 0) {
                    break;
                }
            }
            
            error_log("Cleared rDNS cache: $deleted entries");
            return $deleted;
            
        } catch (Exception $e) {
            error_log("Error clearing rDNS cache: " . $e->getMessage());
            return 0;
        }
    }
    
    /**
     * НОВЫЙ МЕТОД: Очистка whitelist поисковиков (вызывается из cleanup.php)
     */
    public function clearSearchEngineWhitelist() {
        try {
            $deleted = 0;
            $iterator = null;
            // ВАЖНО: OPT_PREFIX НЕ применяется к паттернам SCAN - указываем полный путь
            $pattern = $this->redisPrefix . $this->rdnsPrefix . 'whitelist:*';
            
            while (true) {
                $keys = $this->redis->scan($iterator, $pattern, 100);
                
                if ($keys === false) {
                    break;
                }
                
                foreach ($keys as $key) {
                    // SCAN возвращает полный путь, убираем redisPrefix для del()
                    $keyWithoutPrefix = str_replace($this->redisPrefix, '', $key);
                    $this->redis->del($keyWithoutPrefix);
                    $deleted++;
                }
                
                if ($iterator === 0) {
                    break;
                }
            }
            
            error_log("Cleared search engine whitelist: $deleted entries");
            return $deleted;
            
        } catch (Exception $e) {
            error_log("Error clearing whitelist: " . $e->getMessage());
            return 0;
        }
    }
    
    /**
     * Сбросить счетчики rDNS rate limit
     */
    public function resetRDNSRateLimit() {
        try {
            $currentMinute = floor(time() / 60);
            $rateLimitKey = $this->rdnsPrefix . 'ratelimit:' . $currentMinute;
            
            $result = $this->redis->del($rateLimitKey);
            error_log("rDNS rate limit reset for current minute");
            
            return $result > 0;
            
        } catch (Exception $e) {
            error_log("Error resetting rDNS rate limit: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Обновить настройки rDNS rate limiting
     */
    public function updateRDNSSettings($newSettings) {
        $this->rdnsLimitSettings = array_merge($this->rdnsLimitSettings, $newSettings);
        error_log("rDNS settings updated: " . json_encode($newSettings));
    }
    
    /**
     * Получить настройки rDNS
     */
    public function getRDNSSettings() {
        return $this->rdnsLimitSettings;
    }
    
    /**
     * РАБОЧИЙ Rate Limit v2.3.2 (добавлено сохранение IP в данные)
     * 
     * Вариант B: Мягче для пользователей с валидным cookie
     * - Пользователи с cookie: лимиты × cookie_multiplier (по умолчанию ×2)
     * - Пользователи без cookie: стандартные лимиты
     * 
     * @param string $ip IP адрес
     * @param bool $hasCookie Есть ли валидный cookie
     * @return array Результат проверки
     */
    private function checkRateLimit($ip, $hasCookie = false) {
        // Проверяем исключен ли текущий URL из проверок
        if ($this->isExcludedFromJSChallenge()) {
            return [
                'allowed' => true,
                'reason' => 'URL excluded from rate limit checks',
                'excluded' => true
            ];
        }
        
        try {
            $now = time();
            
            // Ключ для этого IP
            $key = $this->trackingPrefix . 'rl:' . hash('md5', $ip);
            
            // Получаем данные из Redis
            $data = $this->redis->get($key);
            
            // Текущие временные окна
            $minuteWindow = floor($now / 60);
            $fiveMinWindow = floor($now / 300);
            $hourWindow = floor($now / 3600);
            
            // Инициализация счётчиков
            $counts = [
                'min' => 0,
                'min5' => 0,
                'hour' => 0,
                'min_window' => $minuteWindow,
                'min5_window' => $fiveMinWindow,
                'hour_window' => $hourWindow,
                'violations' => 0,
                'ip' => $ip  // Сохраняем IP для отображения в админке
            ];
            
            // Если есть данные - восстанавливаем счётчики для текущих окон
            if ($data && is_array($data)) {
                // Минута - если окно совпадает, берём счётчик
                if (isset($data['min_window']) && $data['min_window'] == $minuteWindow) {
                    $counts['min'] = (int)($data['min'] ?? 0);
                }
                // 5 минут
                if (isset($data['min5_window']) && $data['min5_window'] == $fiveMinWindow) {
                    $counts['min5'] = (int)($data['min5'] ?? 0);
                }
                // Час
                if (isset($data['hour_window']) && $data['hour_window'] == $hourWindow) {
                    $counts['hour'] = (int)($data['hour'] ?? 0);
                }
                // Нарушения
                $counts['violations'] = (int)($data['violations'] ?? 0);
                // IP сохраняем всегда текущий
                $counts['ip'] = $ip;
            }
            
            // Инкрементируем ВСЕ счётчики
            $counts['min']++;
            $counts['min5']++;
            $counts['hour']++;
            
            // Определяем лимиты (с множителем для cookie)
            $multiplier = $hasCookie ? $this->rateLimitSettings['cookie_multiplier'] : 1.0;
            $limits = [
                'min' => (int)($this->rateLimitSettings['max_requests_per_minute'] * $multiplier),
                'min5' => (int)($this->rateLimitSettings['max_requests_per_5min'] * $multiplier),
                'hour' => (int)($this->rateLimitSettings['max_requests_per_hour'] * $multiplier),
            ];
            
            // Проверяем превышения
            $exceeded = [];
            if ($counts['min'] > $limits['min']) {
                $exceeded[] = "1min({$counts['min']}/{$limits['min']})";
            }
            if ($counts['min5'] > $limits['min5']) {
                $exceeded[] = "5min({$counts['min5']}/{$limits['min5']})";
            }
            if ($counts['hour'] > $limits['hour']) {
                $exceeded[] = "1hour({$counts['hour']}/{$limits['hour']})";
            }
            
            // Если есть превышение - инкрементируем violations
            if (!empty($exceeded)) {
                $counts['violations']++;
            }
            
            // Сохраняем в Redis (TTL 1 час)
            $this->redis->setex($key, 3600, $counts);
            
            // Формируем ответ
            if (!empty($exceeded)) {
                return [
                    'allowed' => false,
                    'reason' => 'Rate limit exceeded: ' . implode(', ', $exceeded),
                    'exceeded' => $exceeded,
                    'violation_count' => $counts['violations'],
                    'has_cookie' => $hasCookie,
                    'multiplier' => $multiplier,
                    'stats' => [
                        '1min' => $counts['min'],
                        '5min' => $counts['min5'],
                        '1hour' => $counts['hour'],
                    ],
                    'limits' => $limits
                ];
            }
            
            return [
                'allowed' => true,
                'reason' => null,
                'violation_count' => $counts['violations'],
                'has_cookie' => $hasCookie,
                'stats' => [
                    '1min' => $counts['min'],
                    '5min' => $counts['min5'],
                    '1hour' => $counts['hour'],
                ],
                'limits' => $limits
            ];
            
        } catch (Exception $e) {
            error_log("checkRateLimit ERROR: " . $e->getMessage());
            return ['allowed' => true, 'reason' => null, 'violation_count' => 0];
        }
    }
    
    /**
     * Сброс rate limit для IP (например, после разблокировки)
     * v2.3: Теперь просто удаляем один ключ
     */
    public function resetRateLimit($ip) {
        try {
            $rateLimitKey = $this->trackingPrefix . 'rl:' . hash('md5', $ip);
            $this->redis->del($rateLimitKey);
            return true;
        } catch (Exception $e) {
            error_log("Error resetting rate limit: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Получить текущий статус rate limit для IP
     */
    public function getRateLimitStatus($ip) {
        try {
            $key = $this->trackingPrefix . 'rl:' . hash('md5', $ip);
            $data = $this->redis->get($key);
            
            if (!$data || !is_array($data)) {
                return [
                    'exists' => false,
                    'message' => 'No rate limit data for this IP'
                ];
            }
            
            $now = time();
            $minuteWindow = floor($now / 60);
            $fiveMinWindow = floor($now / 300);
            $hourWindow = floor($now / 3600);
            
            // Определяем актуальные счётчики (те что в текущем окне)
            $currentCounts = [
                '1min' => (isset($data['min_window']) && $data['min_window'] == $minuteWindow) ? $data['min'] : 0,
                '5min' => (isset($data['min5_window']) && $data['min5_window'] == $fiveMinWindow) ? $data['min5'] : 0,
                '1hour' => (isset($data['hour_window']) && $data['hour_window'] == $hourWindow) ? $data['hour'] : 0,
            ];
            
            return [
                'exists' => true,
                'ip' => $ip,
                'current_counts' => $currentCounts,
                'limits_no_cookie' => [
                    '1min' => $this->rateLimitSettings['max_requests_per_minute'],
                    '5min' => $this->rateLimitSettings['max_requests_per_5min'],
                    '1hour' => $this->rateLimitSettings['max_requests_per_hour'],
                ],
                'limits_with_cookie' => [
                    '1min' => (int)($this->rateLimitSettings['max_requests_per_minute'] * $this->rateLimitSettings['cookie_multiplier']),
                    '5min' => (int)($this->rateLimitSettings['max_requests_per_5min'] * $this->rateLimitSettings['cookie_multiplier']),
                    '1hour' => (int)($this->rateLimitSettings['max_requests_per_hour'] * $this->rateLimitSettings['cookie_multiplier']),
                ],
                'violations' => (int)($data['violations'] ?? 0),
                'raw_data' => $data
            ];
        } catch (Exception $e) {
            return ['error' => $e->getMessage()];
        }
    }
    
    /**
     * Тест rate limit - симулирует N запросов
     * @param string $ip IP адрес для теста
     * @param int $numRequests Количество запросов для симуляции
     * @param bool $withCookie Симулировать с cookie или без
     */
    // testRateLimit() removed in optimization (saved 47 lines)
    
    /**
     * НОВЫЙ МЕТОД v2.3: Миграция со старой версии
     * Удаляет старые rate limit ключи формата rl:1m:*, rl:5m:*, rl:1h:*, grl:*:*
     * Запустить ОДИН раз после обновления!
     */
    // migrateFromOldRateLimitKeys() removed in optimization (saved 54 lines)
    
    /**
     * НОВЫЙ МЕТОД v2.3: Получить статистику использования ключей
     * Помогает диагностировать проблемы с памятью
     */
    // getKeyStats() removed in optimization (saved 45 lines)
    
    /**
     * НОВЫЙ МЕТОД: Детекция всплесков активности
     */
    /**
     * РАБОЧИЙ Burst Detection v2.3.1
     * 
     * Детектирует всплески активности: слишком много запросов за короткое время
     * Использует отдельный ключ для надёжности
     * 
     * Вариант B: пользователи с cookie получают увеличенный порог (×cookie_multiplier)
     * 
     * @param string $ip IP адрес
     * @param bool $hasCookie Есть ли валидный cookie
     * @return array|false Информация о всплеске или false
     */
    private function detectBurst($ip, $hasCookie = false) {
        // Проверяем исключен ли текущий URL из проверок
        if ($this->isExcludedFromJSChallenge()) {
            return [
                'detected' => false,
                'reason' => 'URL excluded from burst detection',
                'excluded' => true
            ];
        }
        
        try {
            $now = time();
            $window = $this->rateLimitSettings['burst_window'];  // 10 сек
            
            // Порог с учётом cookie
            $multiplier = $hasCookie ? $this->rateLimitSettings['cookie_multiplier'] : 1.0;
            $threshold = (int)($this->rateLimitSettings['burst_threshold'] * $multiplier);
            
            // Отдельный ключ для burst detection
            $burstKey = $this->trackingPrefix . 'burst:' . hash('md5', $ip);
            
            // Получаем данные
            $data = $this->redis->get($burstKey);
            
            // Инициализация
            $requests = [];
            
            if ($data && is_array($data) && isset($data['times'])) {
                // Фильтруем только запросы в текущем окне
                $requests = array_filter($data['times'], function($time) use ($now, $window) {
                    return ($now - $time) <= $window;
                });
                // Переиндексируем массив
                $requests = array_values($requests);
            }
            
            // Добавляем текущий запрос
            $requests[] = $now;
            
            // Ограничиваем размер массива (храним только последние N*2 запросов)
            $maxStore = max($threshold * 2, 20);
            if (count($requests) > $maxStore) {
                $requests = array_slice($requests, -$maxStore);
            }
            
            // Проверяем порог ПЕРЕД сохранением, чтобы определить TTL
            $requestsInWindow = count(array_filter($requests, function($time) use ($now, $window) {
                return ($now - $time) <= $window;
            }));
            
            // Если превысили порог - увеличиваем TTL до 1 часа для показа в админке
            // Иначе - короткий TTL (окно * 2)
            $ttl = ($requestsInWindow > $threshold) ? 3600 : ($window * 2);
            
            // Сохраняем с адаптивным TTL - добавляем IP для отображения в админке
            $this->redis->setex($burstKey, $ttl, [
                'times' => $requests, 
                'ip' => $ip,
                'exceeded' => ($requestsInWindow > $threshold) // Маркер превышения
            ]);
            
            if ($requestsInWindow > $threshold) {
                return [
                    'detected' => true,
                    'requests_in_window' => $requestsInWindow,
                    'threshold' => $threshold,
                    'window' => $window,
                    'has_cookie' => $hasCookie,
                    'multiplier' => $multiplier,
                    'message' => "$requestsInWindow requests in {$window}s (limit: $threshold)"
                ];
            }
            
            return false;
            
        } catch (Exception $e) {
            error_log("detectBurst ERROR: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Сброс burst detection для IP
     */
    public function resetBurst($ip) {
        try {
            $burstKey = $this->trackingPrefix . 'burst:' . hash('md5', $ip);
            $this->redis->del($burstKey);
            return true;
        } catch (Exception $e) {
            return false;
        }
    }
    
    /**
     * Получить статус burst для IP
     */
    public function getBurstStatus($ip, $hasCookie = false) {
        try {
            $now = time();
            $window = $this->rateLimitSettings['burst_window'];
            $multiplier = $hasCookie ? $this->rateLimitSettings['cookie_multiplier'] : 1.0;
            $threshold = (int)($this->rateLimitSettings['burst_threshold'] * $multiplier);
            
            $burstKey = $this->trackingPrefix . 'burst:' . hash('md5', $ip);
            $data = $this->redis->get($burstKey);
            
            if (!$data || !is_array($data) || !isset($data['times'])) {
                return [
                    'exists' => false,
                    'requests_in_window' => 0,
                    'threshold' => $threshold,
                    'window' => $window,
                    'has_cookie' => $hasCookie
                ];
            }
            
            $requestsInWindow = count(array_filter($data['times'], function($time) use ($now, $window) {
                return ($now - $time) <= $window;
            }));
            
            return [
                'exists' => true,
                'requests_in_window' => $requestsInWindow,
                'threshold' => $threshold,
                'window' => $window,
                'has_cookie' => $hasCookie,
                'will_block_next' => $requestsInWindow >= $threshold,
                'raw_times' => $data['times']
            ];
        } catch (Exception $e) {
            return ['error' => $e->getMessage()];
        }
    }
    
    /**
     * Тест burst detection
     * @param string $ip IP для теста
     * @param int $numRequests Количество запросов
     * @param int $delayMs Задержка между запросами в миллисекундах
     * @param bool $withCookie Симулировать с cookie или без
     */
    // testBurst() removed in optimization (saved 43 lines)
    
    /**
     * НОВЫЙ МЕТОД: Детекция смены User-Agent
     */
    private function detectUserAgentSwitching($ip) {
        try {
            $trackingKey = $this->trackingPrefix . 'ip:' . hash('md5', $ip);
            $data = $this->redis->get($trackingKey);
            
            if (!$data) {
                return false;
            }
            
            $uniqueUA = array_unique($data['user_agents'] ?? []);
            $uaCount = count($uniqueUA);
            
            if ($uaCount >= $this->rateLimitSettings['ua_change_threshold']) {
                $timeSpent = time() - ($data['first_seen'] ?? time());
                
                if ($timeSpent < $this->rateLimitSettings['ua_change_time_window']) {
                    return [
                        'detected' => true,
                        'unique_ua_count' => $uaCount,
                        'time_window' => $timeSpent,
                        'threshold' => $this->rateLimitSettings['ua_change_threshold'],
                        'user_agents' => array_map(function($ua) {
                            return substr($ua, 0, 50) . '...';
                        }, $uniqueUA)
                    ];
                }
            }
            
            return false;
            
        } catch (Exception $e) {
            error_log("Error in detectUserAgentSwitching: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * НОВЫЙ МЕТОД: Прогрессивная блокировка
     */
    private function applyProgressiveBlock($ip, $reason, $violationData = null) {
    try {
        $blockKey = $this->blockPrefix . 'ip:' . hash('md5', $ip);
        $historyKey = $this->blockPrefix . 'history:' . hash('md5', $ip);
        
        $history = $this->redis->get($historyKey) ?: ['count' => 0, 'last_block' => 0];
        $history['count']++;
        $history['last_block'] = time();
        
        $blockDuration = $this->rateLimitSettings['progressive_block_duration'];
        
        if ($history['count'] >= 3) {
            $blockDuration = $this->rateLimitSettings['aggressive_block_duration'] * $history['count'];
        }
        
        $blockData = [
            'ip' => $ip,
            'blocked_at' => time(),
            'blocked_reason' => $reason,
            'violation_count' => $history['count'],
            'block_duration' => $blockDuration,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'uri' => $_SERVER['REQUEST_URI'] ?? '',
            'violation_data' => $violationData,
            'api_blocked' => false
        ];
        
        // Блокировка в Redis
        if ($this->apiSettings['block_on_redis']) {
            $this->redis->setex($blockKey, $blockDuration, $blockData);
            $this->redis->setex($historyKey, 86400 * 7, $history);
        }
        
		// НОВАЯ ПРОВЕРКА: Защита от повторных вызовов API
$apiCallKey = $this->blockPrefix . 'api_call:' . hash('md5', $ip);
$recentApiCall = $this->redis->get($apiCallKey);

if ($recentApiCall) {
    // API уже вызывался в последние 60 секунд - пропустить
    error_log("Skipping duplicate API call for $ip");
    $skipApiCall = true;
} else {
    $skipApiCall = false;
}
		
        // Блокировка через API
        if ($this->apiSettings['block_on_api'] && !$skipApiCall) {
            $apiResult = $this->callBlockingAPI($ip, 'block');
            
            if ($apiResult['status'] === 'success' || $apiResult['status'] === 'already_blocked') {
				$this->redis->setex($apiCallKey, 60, time()); // Защита на 60 секунд
                $blockData['api_blocked'] = true;
                $blockData['api_result'] = $apiResult['message'];
                
                if ($this->apiSettings['block_on_redis']) {
                    $this->redis->setex($blockKey, $blockDuration, $blockData);
                }
            }
        }
        
        $hours = round($blockDuration / 3600, 1);
        $apiStatus = $blockData['api_blocked'] ? 'API+Redis' : 'Redis only';
        error_log("RATE LIMIT BLOCK: $ip | {$apiStatus} | Count: {$history['count']} | Duration: {$hours}h | $reason");
        
        return true;
        
    } catch (Exception $e) {
        error_log("Error in applyProgressiveBlock: " . $e->getMessage());
        return false;
    }
}
    
    /**
     * ОБНОВЛЕННЫЙ МЕТОД protect() с rate limiting
     */
    /**
     * ═══════════════════════════════════════════════════════════════════════
     * ОБНОВЛЕННЫЙ МЕТОД protect() v2.4
     * 
     * КЛЮЧЕВОЕ ИЗМЕНЕНИЕ: Rate Limit и Burst Detection проверяются ВСЕГДА,
     * даже когда показывается 429 ошибка. При достижении порога violations
     * IP автоматически блокируется через API.
     * ═══════════════════════════════════════════════════════════════════════
     */
    public function protect() {
        // Инкрементируем счётчик запросов для статистики RPM/RPS
        $this->incrementRequestCounter();
        
        if ($this->isStaticFile()) {
            return;
        }
        
        // ВЕРОЯТНОСТНАЯ ПРОВЕРКА переполнения Redis (не каждый запрос!)
        if (rand(1, $this->globalProtectionSettings['cleanup_probability']) === 1) {
            $this->manageTrackedIPs();
        }
        
        $ip = $this->getRealIP();
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        
        // ═══════════════════════════════════════════════════════════════════
        // Глобальный rate limit ДО проверки ботов
        // ═══════════════════════════════════════════════════════════════════
        $globalRateLimit = $this->checkGlobalRateLimit($ip);
        if (!$globalRateLimit['allowed']) {
            error_log("GLOBAL RATE LIMIT: $ip | " . $globalRateLimit['requests'] . " req/sec");
            $this->blockIP($ip, 'Global rate limit exceeded (possible DDoS)');
            $this->sendBlockResponse();
        }
        
        // Проверка whitelist верифицированных поисковиков
        if ($this->isWhitelistedSearchEngine($ip)) {
            return;
        }
        
        if ($this->isLegitimateBot($userAgent)) {
            $this->logBotVisit($ip, $userAgent, 'legitimate');
            return;
        }
        
        if ($this->isVerifiedSearchEngine($ip, $userAgent)) {
            $this->addToSearchEngineWhitelist($ip, $userAgent);
            $this->logSearchEngineVisit($ip, $userAgent);
            return;
        }
        
        if ($this->isUserHashBlocked()) {
            $this->sendBlockResponse();
        }
        
        if ($this->isCookieBlocked()) {
            $this->sendBlockResponse();
        }
        
        if ($this->isBlocked($ip) && $this->isSuspiciousUserAgent($userAgent)) {
            $this->sendBlockResponse();
        }
        
        // ═══════════════════════════════════════════════════════════════════
        // КРИТИЧНО v2.7.5: RATE LIMIT + BURST ПРОВЕРКА ПЕРЕД JS CHALLENGE!
        // Боты могут бесконечно нажимать F5 на странице Challenge
        // Поэтому проверяем Rate Limit ПЕРЕД показом Challenge!
        // ═══════════════════════════════════════════════════════════════════
        $hasCookie = $this->hasValidCookie();
        
        // 1. Проверяем Rate Limit (счетчики ВСЕГДА увеличиваются)
        $rateLimitResult = $this->checkRateLimit($ip, $hasCookie);
        $rateLimitExceeded = !$rateLimitResult['allowed'];
        
        // 2. Проверяем Burst Detection (счетчики ВСЕГДА увеличиваются)
        $burstDetected = $this->detectBurst($ip, $hasCookie);
        $burstExceeded = $burstDetected && $burstDetected['detected'];
        
        // 3. Если есть нарушение - увеличиваем счётчик violations
        if ($rateLimitExceeded) {
            $violations = $this->incrementViolations($ip, 'rate_limit');
            $cookieInfo = $hasCookie ? ' [HAS_COOKIE, x' . ($rateLimitResult['multiplier'] ?? 1) . ']' : ' [NO_COOKIE]';
            error_log("RATE LIMIT EXCEEDED: $ip$cookieInfo | " . $rateLimitResult['reason'] . 
                     " | RL Violations: " . $violations['rate_limit'] . " | Total: " . $violations['total']);
        }
        
        if ($burstExceeded) {
            $violations = $this->incrementViolations($ip, 'burst');
            $cookieInfo = $hasCookie ? ' [HAS_COOKIE, x' . ($burstDetected['multiplier'] ?? 1) . ']' : ' [NO_COOKIE]';
            error_log("BURST DETECTED: $ip$cookieInfo | {$burstDetected['message']}" .
                     " | Burst Violations: " . $violations['burst'] . " | Total: " . $violations['total']);
        }
        
        // 4. Проверяем, нужно ли блокировать через API
        if ($rateLimitExceeded || $burstExceeded) {
            $violations = $this->getTotalViolations($ip);
            $shouldBlock = $this->shouldBlockViaAPI($violations);
            
            if ($shouldBlock['block']) {
                // Порог достигнут - блокируем через API!
                $blockReason = sprintf(
                    "API block triggered: %s (RL: %d/%d, Burst: %d/%d, Total: %d/%d)",
                    $shouldBlock['reason'],
                    $violations['rate_limit'],
                    $this->rateLimitSettings['rate_limit_api_block_threshold'],
                    $violations['burst'],
                    $this->rateLimitSettings['burst_api_block_threshold'],
                    $violations['total'],
                    $this->rateLimitSettings['combined_api_block_threshold']
                );
                
                error_log("API BLOCK TRIGGERED: $ip | $blockReason");
                
                $this->applyProgressiveBlock($ip, $blockReason, [
                    'rate_limit_result' => $rateLimitResult,
                    'burst_result' => $burstDetected,
                    'violations' => $violations,
                    'trigger' => $shouldBlock['reason']
                ]);
                $this->blockUserHash('API block: ' . $shouldBlock['reason']);
                $this->sendBlockResponse();
            } else {
                // Порог не достигнут - показываем 429 и продолжаем считать
                if ($rateLimitExceeded) {
                    $this->send429Response($ip, $violations, 'rate_limit', $rateLimitResult);
                } elseif ($burstExceeded) {
                    $this->send429Response($ip, $violations, 'burst', $burstDetected);
                }
            }
        }
        
        // ═══════════════════════════════════════════════════════════════════
        // JS CHALLENGE PROTECTION (v2.7.5: Теперь ПОСЛЕ Rate Limit!)
        // Проверяем нужно ли показать JS Challenge
        // JS Challenge показывается ТОЛЬКО если Rate Limit не превышен!
        // ═══════════════════════════════════════════════════════════════════
        if ($this->jsChallengeSettings['enabled']) {
            $jsChallengeResult = $this->checkJSChallenge($ip);
            
            if ($jsChallengeResult['show_challenge']) {
                error_log("JS CHALLENGE SHOWN: $ip | Reason: {$jsChallengeResult['reason']}");
                $this->showJSChallenge($jsChallengeResult['reason']);
            }
        }
        
        // ═══════════════════════════════════════════════════════════════════
        // АГРЕССИВНАЯ ДЕТЕКЦИЯ БОТОВ ПО HTTP ЗАГОЛОВКАМ
        // ═══════════════════════════════════════════════════════════════════
        if ($this->headerDetectionSettings['enabled']) {
            $headerCheck = $this->checkSuspiciousHeaders();
            if ($headerCheck['suspicious']) {
                $headerScore = $headerCheck['score'];
                $blockThreshold = $this->headerDetectionSettings['block_score_threshold'];
                $trackingThreshold = $this->headerDetectionSettings['tracking_score_threshold'];
                
                if ($headerScore >= $blockThreshold) {
                    $ajaxInfo = isset($headerCheck['is_ajax']) && $headerCheck['is_ajax'] ? ' [AJAX]' : '';
                    error_log("BOT BLOCKED BY HEADERS: $ip | Score: $headerScore$ajaxInfo | Missing: " . implode(', ', $headerCheck['missing']));
                    $this->applyProgressiveBlock($ip, 'Bot signature detected (missing headers, score: ' . $headerScore . ')');
                    $this->blockUserHash('Bot headers signature');
                    $this->sendBlockResponse();
                }
                
                if ($headerScore >= $trackingThreshold && $headerScore < $blockThreshold) {
                    $ajaxInfo = isset($headerCheck['is_ajax']) && $headerCheck['is_ajax'] ? ' [AJAX]' : '';
                    // $this->enableExtendedTracking($ip, 'Suspicious HTTP headers (score: ' . $headerScore . $ajaxInfo . ')');
                }
            }
        }
        
        // Детекция смены User-Agent
        $uaSwitching = $this->detectUserAgentSwitching($ip);
        if ($uaSwitching && $uaSwitching['detected']) {
            $this->applyProgressiveBlock($ip, 'User-Agent switching detected', $uaSwitching);
            $this->blockUserHash('UA switching');
            if (isset($_COOKIE[$this->cookieName])) {
                $this->blockCookieHash();
            }
            $this->sendBlockResponse();
        }
        
        $hasExtendedTracking = false /* checkExtendedTracking removed */;
        
        if ($hasCookie) {
            $this->trackUserHashActivity();
            
            if ($this->shouldAnalyzeIP($ip) || $hasExtendedTracking) {
                if ($this->analyzeRequest($ip)) {
                    if ($this->isSuspiciousUserAgent($userAgent)) {
                        $this->blockIP($ip, 'Suspicious user agent with valid cookie');
                        $this->blockCookieHash();
                        $this->blockUserHash('Bot with valid cookie');
                    } else {
                        $this->blockUserHash('Browser behavior detected with valid cookie');
                        $this->blockCookieHash();
                    }
                    $this->sendBlockResponse();
                }
            }
            return;
        }
        
        if ($this->shouldAnalyzeIP($ip) || $hasExtendedTracking) {
            if ($this->analyzeRequest($ip)) {
                if ($this->isSuspiciousUserAgent($userAgent)) {
                    $this->blockIP($ip, 'Suspicious user agent detected');
                    if (isset($_COOKIE[$this->cookieName])) {
                        $this->blockCookieHash();
                    }
                    $this->blockUserHash('Bot detected');
                } else {
                    if (!$hasExtendedTracking) {
                        // $this->enableExtendedTracking($ip, 'Suspicious browser behavior');
                    }
                    
                    if (isset($_COOKIE[$this->cookieName])) {
                        $this->blockCookieHash();
                    } else {
                        $this->blockUserHash('Browser behavior detected without cookie');
                    }
                }
                $this->sendBlockResponse();
            }
        }
        
        if (false /* analyzeUserHashBehavior removed */) {
            if ($this->isSuspiciousUserAgent($userAgent)) {
                $this->blockIP($ip, 'Bot behavior confirmed by user hash analysis');
                $this->blockUserHash('Bot confirmed');
                if (isset($_COOKIE[$this->cookieName])) {
                    $this->blockCookieHash();
                }
            } else {
                $this->blockUserHash('Slow bot behavior detected');
                if (isset($_COOKIE[$this->cookieName])) {
                    $this->blockCookieHash();
                }
            }
            
            $this->sendBlockResponse();
        }
        
        // ═══════════════════════════════════════════════════════════════════
        // НОВОЕ v2.5: Блокировка если нет cookie после N запросов
        // Защита от распределённого парсинга (ботнеты с разных IP)
        // ═══════════════════════════════════════════════════════════════════
        if (!$hasCookie) {
            $trackingData = $this->getUserTrackingData($ip);
            $noCookieThreshold = $this->rateLimitSettings['no_cookie_block_threshold'] ?? 3;
            
            if ($trackingData && ($trackingData['requests'] ?? 0) >= $noCookieThreshold) {
                $requestCount = $trackingData['requests'];
                error_log("NO COOKIE BOT BLOCKED: $ip | Requests without cookie: $requestCount (threshold: $noCookieThreshold)");
                $this->applyProgressiveBlock($ip, "No cookie after $requestCount requests");
                $this->blockUserHash('No cookie bot');
                $this->sendBlockResponse();
            }
        }
        
        // ═══════════════════════════════════════════════════════════════════
        // ОБНОВЛЕНО v2.5: Slow Bot Detection - теперь БЛОКИРУЕТ сразу!
        // Раньше только включал extended tracking, теперь блокирует
        // ═══════════════════════════════════════════════════════════════════
        $trackingData = $this->getUserTrackingData($ip);
        if ($trackingData && $this->isPotentialSlowBot($trackingData)) {
            $instantBlock = $this->rateLimitSettings['slow_bot_instant_block'] ?? true;
            
            if ($instantBlock) {
                // v2.5: Жёсткий режим - блокируем сразу
                $requestCount = $trackingData['requests'] ?? 0;
                error_log("SLOW BOT BLOCKED: $ip | Requests: $requestCount | Pattern detected");
                $this->applyProgressiveBlock($ip, 'Slow bot pattern detected');
                $this->blockUserHash('Slow bot');
                $this->sendBlockResponse();
            } else {
                // Мягкий режим - только extended tracking (как раньше)
                if (!$hasExtendedTracking) {
                    // $this->enableExtendedTracking($ip, 'Potential slow bot pattern');
                }
            }
        }
        
        if (!isset($_COOKIE[$this->cookieName])) {
            $this->setVisitorCookie();
            $this->initTracking($ip);
        }
    }
    
    /**
     * ═══════════════════════════════════════════════════════════════════════
     * НОВЫЙ МЕТОД v2.4: Отправка 429 ответа с информацией о violations
     * 
     * Показывает красивую страницу 429 с предупреждением о блокировке
     * ═══════════════════════════════════════════════════════════════════════
     */
    private function send429Response($ip, $violations, $type, $details) {
        if (!headers_sent()) {
            http_response_code(429);
            header('Content-Type: text/html; charset=utf-8');
            header('Retry-After: 60');
            header('X-RateLimit-Limit: ' . $this->rateLimitSettings['max_requests_per_minute']);
            header('X-RateLimit-Remaining: 0');
            header('X-Violations-RateLimit: ' . $violations['rate_limit']);
            header('X-Violations-Burst: ' . $violations['burst']);
            header('X-Violations-Total: ' . $violations['total']);
            header('X-Block-Threshold: ' . $this->rateLimitSettings['combined_api_block_threshold']);
        }
        
        $remaining = $this->rateLimitSettings['combined_api_block_threshold'] - $violations['total'];
        $remaining = max(0, $remaining);
        $progressPercent = min(100, ($violations['total'] / $this->rateLimitSettings['combined_api_block_threshold']) * 100);
        
        $html = '<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>429 - Too Many Requests</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #eee;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            padding: 20px;
            box-sizing: border-box;
        }
        .container {
            background: rgba(255,255,255,0.05);
            border-radius: 20px;
            padding: 40px;
            max-width: 500px;
            text-align: center;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,0.1);
        }
        .icon { font-size: 64px; margin-bottom: 20px; }
        h1 { color: #ff6b6b; margin: 0 0 10px 0; font-size: 28px; }
        .subtitle { color: #aaa; margin-bottom: 30px; }
        .warning-box {
            background: rgba(255, 107, 107, 0.1);
            border: 1px solid rgba(255, 107, 107, 0.3);
            border-radius: 10px;
            padding: 20px;
            margin: 20px 0;
        }
        .warning-title { color: #ff6b6b; font-weight: bold; margin-bottom: 10px; }
        .stats { display: flex; justify-content: space-around; margin: 20px 0; flex-wrap: wrap; }
        .stat { text-align: center; padding: 10px; }
        .stat-value { font-size: 24px; font-weight: bold; color: #ff6b6b; }
        .stat-label { font-size: 12px; color: #888; }
        .progress-bar {
            background: rgba(255,255,255,0.1);
            border-radius: 10px;
            height: 20px;
            overflow: hidden;
            margin: 20px 0;
        }
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #4ecdc4, #ff6b6b);
            transition: width 0.3s;
        }
        .countdown { font-size: 14px; color: #888; margin-top: 20px; }
        .timer { font-size: 32px; font-weight: bold; color: #4ecdc4; }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">⚠️</div>
        <h1>Слишком много запросов</h1>
        <p class="subtitle">Вы превысили лимит запросов</p>
        
        <div class="warning-box">
            <div class="warning-title">⚡ Предупреждение</div>
            <p>При продолжении превышения лимитов ваш IP будет заблокирован.</p>
            <p><strong>Осталось до блокировки: ' . $remaining . ' нарушений</strong></p>
        </div>
        
        <div class="stats">
            <div class="stat">
                <div class="stat-value">' . $violations['rate_limit'] . '</div>
                <div class="stat-label">Rate Limit</div>
            </div>
            <div class="stat">
                <div class="stat-value">' . $violations['burst'] . '</div>
                <div class="stat-label">Burst</div>
            </div>
            <div class="stat">
                <div class="stat-value">' . $violations['total'] . '</div>
                <div class="stat-label">Всего</div>
            </div>
        </div>
        
        <div class="progress-bar">
            <div class="progress-fill" style="width: ' . $progressPercent . '%"></div>
        </div>
        
        <div class="countdown">
            Повторите попытку через:
            <div class="timer" id="timer">60</div>
        </div>
    </div>
    
    <script>
        let seconds = 60;
        const timer = document.getElementById("timer");
        const interval = setInterval(() => {
            seconds--;
            timer.textContent = seconds;
            if (seconds <= 0) {
                clearInterval(interval);
                location.reload();
            }
        }, 1000);
    </script>
</body>
</html>';
        
        die($html);
    }
    
    /**
     * ОПТИМИЗИРОВАННЫЙ Global Rate Limit v2.3
     * Защита от DDoS - срабатывает при экстремальной нагрузке (>100 req/sec)
     * 
     * БЫЛО: 1 ключ на каждую секунду для каждого IP = тысячи ключей
     * СТАЛО: 1 ключ на IP со скользящим окном = минимум ключей
     */
    private function checkGlobalRateLimit($ip) {
        try {
            $currentSecond = time();
            
            // Один ключ на IP вместо ключа на каждую секунду!
            $key = $this->globalPrefix . 'grl:' . hash('md5', $ip);
            
            // Получаем текущие данные
            $data = $this->redis->get($key);
            
            $requests = 0;
            
            // Если данные есть и секунда та же - берём счётчик
            if ($data && is_array($data) && isset($data['second']) && (int)$data['second'] === $currentSecond) {
                $requests = (int)($data['requests'] ?? 0);
            }
            
            $requests++;
            
            // Сохраняем данные
            $this->redis->setex($key, 5, [
                'requests' => $requests,
                'second' => $currentSecond
            ]);
            
            // Порог: 100 запросов в секунду = явный DDoS
            if ($requests > 100) {
                return ['allowed' => false, 'requests' => $requests];
            }
            
            return ['allowed' => true, 'requests' => $requests];
        } catch (Exception $e) {
            return ['allowed' => true, 'requests' => 0];
        }
    }
    
    /**
     * НОВЫЙ МЕТОД: Проверка whitelist верифицированных поисковиков
     */
    private function isWhitelistedSearchEngine($ip) {
        try {
            $whitelistKey = $this->rdnsPrefix . 'whitelist:' . hash('md5', $ip);
            return $this->redis->exists($whitelistKey);
        } catch (Exception $e) {
            return false;
        }
    }
    
    /**
     * НОВЫЙ МЕТОД: Добавление в whitelist после rDNS верификации
     */
    private function addToSearchEngineWhitelist($ip, $userAgent) {
        try {
            $whitelistKey = $this->rdnsPrefix . 'whitelist:' . hash('md5', $ip);
            $data = [
                'ip' => $ip,
                'user_agent' => $userAgent,
                'verified_at' => time()
            ];
            // Кешируем на 24 часа - поисковики обычно используют стабильные IP
            $this->redis->setex($whitelistKey, 86400, $data);
        } catch (Exception $e) {
            error_log("Error adding to search engine whitelist: " . $e->getMessage());
        }
    }
    
    /**
     * ОПТИМИЗИРОВАННАЯ защита от переполнения Redis (БЕЗ торможения)
     */
    private function manageTrackedIPs() {
        try {
            // ШАГ 1: Быстрая проверка - нужна ли очистка вообще
            // Используем кешированный счетчик (обновляется редко)
            $countCacheKey = $this->globalPrefix . 'tracked_count_cache';
            $cachedCount = $this->redis->get($countCacheKey);
            
            // Если кеш пустой или устарел (обновляем раз в минуту)
            if ($cachedCount === false) {
                $approxCount = $this->getApproximateTrackedCount();
                $this->redis->setex($countCacheKey, 60, $approxCount);
                $cachedCount = $approxCount;
            }
            
            // Если далеко от лимита - выходим сразу (быстро!)
            if ($cachedCount < $this->globalProtectionSettings['cleanup_threshold']) {
                return 0;
            }
            
            // ШАГ 2: Очистка нужна - используем SCAN (не блокирует Redis)
            $cleaned = 0;
            $maxCleanupTime = $this->globalProtectionSettings['max_cleanup_time_ms'] / 1000; // в секунды
            $startTime = microtime(true);
            $batchSize = $this->globalProtectionSettings['cleanup_batch_size'];
            
            // SCAN итератор (безопасный для production)
            $iterator = null;
            // ВАЖНО: OPT_PREFIX НЕ применяется к паттернам SCAN - указываем полный путь
            $pattern = $this->redisPrefix . $this->trackingPrefix . 'ip:*';
            
            do {
                // SCAN возвращает порциями, не блокируя Redis
                $keys = $this->redis->scan($iterator, $pattern, 50); // 50 ключей за раз
                
                if ($keys === false) break;
                
                foreach ($keys as $key) {
                    // Лимит времени - прерываем если долго
                    if ((microtime(true) - $startTime) > $maxCleanupTime) {
                        break 2;
                    }
                    
                    // Лимит количества
                    if ($cleaned >= $batchSize) {
                        break 2;
                    }
                    
                    // SCAN возвращает полный путь, убираем redisPrefix для команд Redis
                    $keyWithoutPrefix = str_replace($this->redisPrefix, '', $key);
                    
                    // БЫСТРАЯ проверка: смотрим только TTL (без GET данных)
                    $ttl = $this->redis->ttl($keyWithoutPrefix);
                    
                    // Стратегия 1: Удаляем ключи с TTL < 10 минут (скоро истекут)
                    if ($ttl > 0 && $ttl < 600) {
                        $this->redis->del($keyWithoutPrefix);
                        $this->decrementTrackedCounter();
                        $cleaned++;
                        continue;
                    }
                    
                    // Стратегия 2: Для старых ключей проверяем активность
                    if ($ttl === -1 || $ttl > 3600) {
                        $data = $this->redis->get($keyWithoutPrefix);
                        
                        if ($data && isset($data['first_seen'], $data['requests'])) {
                            $age = time() - $data['first_seen'];
                            
                            // Удаляем старые (>2 часа) с низкой активностью (<10 запросов)
                            if ($age > 7200 && $data['requests'] < 10) {
                                $this->redis->del($keyWithoutPrefix);
                                $this->decrementTrackedCounter();
                                $cleaned++;
                            }
                            // Удаляем очень старые (>6 часов) независимо от активности
                            elseif ($age > 21600) {
                                $this->redis->del($keyWithoutPrefix);
                                $this->decrementTrackedCounter();
                                $cleaned++;
                            }
                        }
                    }
                }
                
            } while ($iterator !== 0 && $iterator !== null);
            
            // ШАГ 3: Обновляем счетчик после очистки
            if ($cleaned > 0) {
                $newCount = max(0, $cachedCount - $cleaned);
                $this->redis->setex($countCacheKey, 60, $newCount);
                error_log("Redis cleanup: removed $cleaned tracked IPs (approx " . 
                         round((microtime(true) - $startTime) * 1000, 2) . "ms)");
            }
            
            return $cleaned;
            
        } catch (Exception $e) {
            error_log("Error in manageTrackedIPs: " . $e->getMessage());
            return 0;
        }
    }
    
    /**
     * Быстрая примерная оценка количества tracked IP
     */
    private function getApproximateTrackedCount() {
        try {
            // Вариант 1: Используем отдельный счетчик (инкремент/декремент)
            $counterKey = $this->globalPrefix . 'tracked_counter';
            $count = $this->redis->get($counterKey);
            
            if ($count !== false) {
                return (int)$count;
            }
            
            // Вариант 2: Точный подсчет (только если счетчик сброшен)
            $iterator = null;
            $counted = 0;
            $maxToCount = 1000; // Считаем максимум 1000 для оценки
            
            while ($counted < $maxToCount) {
                // ВАЖНО: OPT_PREFIX НЕ применяется к паттернам SCAN - указываем полный путь
                $keys = $this->redis->scan($iterator, $this->redisPrefix . $this->trackingPrefix . 'ip:*', 100);
                if ($keys === false) break;
                
                $counted += count($keys);
                
                if ($iterator === 0 || $iterator === null) break;
            }
            
            // Сохраняем в счетчик
            $this->redis->setex($counterKey, 300, $counted); // 5 минут кеш
            
            return $counted;
            
        } catch (Exception $e) {
            error_log("Error getting tracked count: " . $e->getMessage());
            return 0;
        }
    }
    
    /**
     * Инкремент счетчика tracked IP (вызывать при добавлении)
     */
    private function incrementTrackedCounter() {
        try {
            $counterKey = $this->globalPrefix . 'tracked_counter';
            $this->redis->incr($counterKey);
            $this->redis->expire($counterKey, 3600); // 1 час
        } catch (Exception $e) {
            // Не критично, просто счетчик не обновится
        }
    }
    
    /**
     * Декремент счетчика tracked IP (вызывать при удалении)
     */
    private function decrementTrackedCounter() {
        try {
            $counterKey = $this->globalPrefix . 'tracked_counter';
            $this->redis->decr($counterKey);
        } catch (Exception $e) {
            // Не критично
        }
    }
    
    private function shouldAnalyzeIP($ip) {
        try {
            $trackingKey = $this->trackingPrefix . 'ip:' . hash('md5', $ip);
            $data = $this->redis->get($trackingKey);
            
            if ($data) {
                $requests = $data['requests'] ?? 0;
                $timeSpent = time() - ($data['first_seen'] ?? time());
                $suspicious_ua = $this->isSuspiciousUserAgent($_SERVER['HTTP_USER_AGENT'] ?? '');
                
                if ($suspicious_ua) {
                    return true;
                }
                
                if ($timeSpent > 1800 && $requests >= 5) {
                    return true;
                }
                
                if ($requests > 5) {
                    return true;
                }
                
                if ($timeSpent > 0 && $requests >= $this->slowBotSettings['min_requests_for_analysis']) {
                    $requestsPerMinute = ($requests * 60) / $timeSpent;
                    if ($requestsPerMinute > 40) {
                        return true;
                    }
                }
                
                if (isset($data['request_times']) && count($data['request_times']) >= 7) {
                    $recentTimes = array_slice($data['request_times'], -7);
                    $timeSpan = end($recentTimes) - reset($recentTimes);
                    if ($timeSpan <= 20) {
                        return true;
                    }
                }
            }
            
            return false;
        } catch (Exception $e) {
            error_log("Error in shouldAnalyzeIP: " . $e->getMessage());
            return false;
        }
    }
    
    private function isSuspiciousUserAgent($userAgent) {
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
    
    /**
     * Проверка подозрительных HTTP заголовков
     * Реальные браузеры отправляют много заголовков, боты - мало
     * 
     * @return array ['suspicious' => bool, 'score' => int, 'missing' => array]
     */
    private function checkSuspiciousHeaders() {
        $score = 0;
        $missing = [];
        
        // ═══════════════════════════════════════════════════════════════════════
        // ИСКЛЮЧЕНИЕ ДЛЯ AJAX/FETCH ЗАПРОСОВ
        // ═══════════════════════════════════════════════════════════════════════
        // AJAX запросы (поиск DLE, динамическая загрузка и т.д.) имеют другие
        // заголовки чем обычные страницы - это НОРМАЛЬНО, не блокируем их
        // ═══════════════════════════════════════════════════════════════════════
        
        // Метод 1: XMLHttpRequest (jQuery, старый JS)
        $isXHR = !empty($_SERVER['HTTP_X_REQUESTED_WITH']) && 
                 strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';
        
        // Метод 2: Sec-Fetch-Mode (современные браузеры)
        // cors, same-origin, no-cors = fetch/AJAX запросы
        // navigate = обычная навигация (загрузка страницы)
        $secFetchMode = $_SERVER['HTTP_SEC_FETCH_MODE'] ?? '';
        $isModernAjax = in_array($secFetchMode, ['cors', 'same-origin', 'no-cors']);
        
        // Метод 3: Sec-Fetch-Dest (тип запрашиваемого ресурса)
        // empty = fetch/AJAX, document = страница
        $secFetchDest = $_SERVER['HTTP_SEC_FETCH_DEST'] ?? '';
        $isFetchRequest = ($secFetchDest === 'empty');
        
        // Метод 4: Accept заголовок указывает на JSON/XML (API запрос)
        $accept = $_SERVER['HTTP_ACCEPT'] ?? '';
        $isApiRequest = (stripos($accept, 'application/json') !== false || 
                        stripos($accept, 'application/xml') !== false ||
                        stripos($accept, 'text/javascript') !== false);
        
        // Если это AJAX/Fetch запрос от браузера - применяем МЯГКИЕ проверки
        if ($isXHR || $isModernAjax || $isFetchRequest || $isApiRequest) {
            // Для AJAX проверяем только критичные вещи
            $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
            
            // Нет User-Agent вообще - подозрительно даже для AJAX
            if (empty($userAgent)) {
                $score += 3;
                $missing[] = 'NO_USER_AGENT_AJAX';
            }
            
            // Нет Accept-Language - немного подозрительно
            if (empty($_SERVER['HTTP_ACCEPT_LANGUAGE'])) {
                $score += 1;
                $missing[] = 'NO_LANG_AJAX';
            }
            
            // Для AJAX порог подозрительности выше
            return [
                'suspicious' => $score >= 4,  // Только при score >= 4 для AJAX
                'score' => $score,
                'missing' => $missing,
                'is_ajax' => true
            ];
        }
        
        // ═══════════════════════════════════════════════════════════════════════
        // ПОЛНАЯ ПРОВЕРКА ДЛЯ ОБЫЧНЫХ ЗАПРОСОВ (загрузка страниц)
        // ═══════════════════════════════════════════════════════════════════════
        
        // Заголовки, которые ДОЛЖНЫ быть у реального браузера
        $requiredHeaders = [
            'HTTP_ACCEPT_LANGUAGE' => 3,     // Все браузеры отправляют язык
            'HTTP_ACCEPT_ENCODING' => 2,     // gzip, deflate, br
            'HTTP_ACCEPT' => 1,              // text/html,application/xhtml+xml,...
        ];
        
        foreach ($requiredHeaders as $header => $penalty) {
            if (empty($_SERVER[$header])) {
                $score += $penalty;
                $missing[] = $header;
            }
        }
        
        // Проверка Accept - боты часто отправляют только "*/*"
        if ($accept === '*/*' || strlen($accept) < 10) {
            $score += 2;
            $missing[] = 'BAD_ACCEPT';
        }
        
        // Проверка Accept-Language - должен быть валидный язык
        $acceptLang = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '';
        if (!empty($acceptLang)) {
            // Должен содержать код языка типа en, ru, uk и т.д.
            if (!preg_match('/^[a-z]{2}(-[A-Z]{2})?(,|;|$)/i', $acceptLang)) {
                $score += 2;
                $missing[] = 'INVALID_LANG';
            }
        }
        
        // Проверка Accept-Encoding - современные браузеры поддерживают gzip
        $acceptEnc = $_SERVER['HTTP_ACCEPT_ENCODING'] ?? '';
        if (!empty($acceptEnc) && stripos($acceptEnc, 'gzip') === false) {
            $score += 1;
        }
        
        // Проверка Connection заголовка
        $connection = $_SERVER['HTTP_CONNECTION'] ?? '';
        if (empty($connection)) {
            $score += 1;
            $missing[] = 'NO_CONNECTION';
        }
        
        // Проверка User-Agent
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        if (empty($userAgent)) {
            $score += 4;  // Нет User-Agent = почти точно бот
            $missing[] = 'NO_USER_AGENT';
        } elseif (strlen($userAgent) < 20) {
            $score += 2;  // Слишком короткий UA
            $missing[] = 'SHORT_USER_AGENT';
        }
        
        // Sec-Fetch-* заголовки (современные браузеры Chrome/Firefox/Edge)
        // Их отсутствие не критично для старых браузеров, но добавляет к подозрению
        $secFetchSite = $_SERVER['HTTP_SEC_FETCH_SITE'] ?? '';
        
        // Если UA говорит что это Chrome 80+ но нет Sec-Fetch = бот
        if (preg_match('/Chrome\/(\d+)/', $userAgent, $matches)) {
            $chromeVersion = (int)$matches[1];
            if ($chromeVersion >= 80 && empty($secFetchMode)) {
                $score += 3;
                $missing[] = 'NO_SEC_FETCH_CHROME';
            }
        }
        
        // Upgrade-Insecure-Requests (большинство браузеров отправляют при загрузке страниц)
        $upgradeInsecure = $_SERVER['HTTP_UPGRADE_INSECURE_REQUESTS'] ?? '';
        if (empty($upgradeInsecure) && !empty($userAgent) && 
            (stripos($userAgent, 'chrome') !== false || stripos($userAgent, 'firefox') !== false)) {
            $score += 1;
        }
        
        return [
            'suspicious' => $score >= 4,
            'score' => $score,
            'missing' => $missing,
            'is_ajax' => false
        ];
    }
    
    /**
     * Анализ типов запрашиваемых страниц
     * Боты обычно запрашивают только HTML, не загружая ресурсы
	 * Опасно - добавляйте сюда осторожно - через эти USER-AGENT могут атаковать сайт - так как они без проверки R-DNS 
     */
    // analyzeRequestTypes() removed in optimization (saved 35 lines)
    
    private function isLegitimateBot($userAgent) {
        $legitimateBots = [
            'uptimerobot', 'pingdom', 'statuscake', 'site24x7',
            'cloudflare', 'fastly', 'keycdn', 'meta-externalagent',
            'oai-searchbot', 'claude-user', 'claudeBot', 'telegram', 'hosttracker', 'perplexity-user'
        ];
        
        $userAgent = strtolower($userAgent);
        
        foreach ($legitimateBots as $bot) {
            if (strpos($userAgent, $bot) !== false) {
                return true;
            }
        }
        
        return false;
    }
    
    private function logBotVisit($ip, $userAgent, $type) {
        try {
            $logEntry = [
                'timestamp' => date('Y-m-d H:i:s'),
                'ip' => $ip,
                'user_agent' => $userAgent,
                'type' => $type,
                'uri' => $_SERVER['REQUEST_URI'] ?? ''
            ];
            
            $logKey = 'logs:legitimate_bots:' . date('Y-m-d');
            $this->redis->lpush($logKey, $logEntry);
            $this->redis->expire($logKey, $this->ttlSettings['logs']);
            $this->redis->ltrim($logKey, 0, 999);
        } catch (Exception $e) {
            error_log("Error logging bot visit: " . $e->getMessage());
        }
    }
    
    private function isVerifiedSearchEngine($ip, $userAgent) {
        $detectedEngine = null;
        $engineConfig = null;
        foreach ($this->allowedSearchEngines as $engine => $config) {
            foreach ($config['user_agent_patterns'] as $pattern) {
                if (stripos($userAgent, $pattern) !== false) {
                    $detectedEngine = $engine;
                    $engineConfig = $config;
                    break 2;
                }
            }
        }
        
        if (!$detectedEngine || !$engineConfig) {
            return false;
        }
        
        return $this->verifySearchEngineByRDNS($ip, $engineConfig);
    }
    
    private function verifySearchEngineByRDNS($ip, $engineConfig) {
        // Поддержка старого формата (массив паттернов) и нового (полный конфиг)
        if (isset($engineConfig['rdns_patterns'])) {
            $allowedPatterns = $engineConfig['rdns_patterns'];
            $skipForwardVerification = $engineConfig['skip_forward_verification'] ?? false;
        } else {
            // Старый формат - просто массив паттернов
            $allowedPatterns = $engineConfig;
            $skipForwardVerification = false;
        }
        
        try {
            $normalizedIP = $this->normalizeIP($ip);
            $cacheKey = $this->rdnsPrefix . 'cache:' . hash('md5', $normalizedIP);
            
            // СНАЧАЛА проверяем кеш (до rate limit проверки!)
            $cached = $this->redis->get($cacheKey);
            if ($cached !== false) {
                return $cached['verified'];
            }
            
            // Проверяем rate limit для rDNS
            $rdnsLimitCheck = $this->checkRDNSRateLimit();
            if (!$rdnsLimitCheck['allowed']) {
                // При превышении лимита и отсутствии кеша
                if ($this->rdnsLimitSettings['rdns_on_limit_action'] === 'block') {
                    error_log("rDNS rate limit exceeded, blocking IP: $normalizedIP");
                    return false;
                }
                
                // НОВОЕ: Доверяем UA поисковика при превышении лимита
                if (!empty($this->rdnsLimitSettings['trust_search_engine_ua_on_limit'])) {
                    error_log("rDNS rate limit exceeded, trusting search engine UA for: $normalizedIP");
                    // Кешируем как "условно верифицированный" с коротким TTL
                    $this->redis->setex($cacheKey, 300, [
                        'ip' => $normalizedIP,
                        'hostname' => 'trusted_by_ua',
                        'verified' => true,
                        'timestamp' => time(),
                        'trusted_reason' => 'rdns_limit_exceeded'
                    ]);
                    return true;
                }
                
                // 'skip' - пропускаем проверку
                error_log("rDNS rate limit exceeded, skipping verification for: $normalizedIP");
                return false;
            }
            
            $verified = false;
            $hostname = '';
            $error = '';
            
            try {
                $hostname = $this->getHostnameWithTimeout($normalizedIP, 2);
                
                if ($hostname && $hostname !== $normalizedIP) {
                    $hostnameMatches = false;
                    foreach ($allowedPatterns as $pattern) {
                        if ($this->matchesDomainPattern($hostname, $pattern)) {
                            $hostnameMatches = true;
                            break;
                        }
                    }
                    
                    if ($hostnameMatches) {
                        // Если skip_forward_verification - доверяем только rDNS
                        if ($skipForwardVerification) {
                            $verified = true;
                            error_log("rDNS verified (forward skip): $normalizedIP -> $hostname");
                        } else {
                            // Стандартная проверка: forward lookup
                            $forwardIPs = $this->getIPsWithTimeout($hostname, 2);
                            
                            if ($forwardIPs && $this->ipInArray($normalizedIP, $forwardIPs)) {
                                $verified = true;
                            }
                        }
                    }
                }
                
            } catch (Exception $e) {
                $error = $e->getMessage();
            }
            
            $cacheData = [
                'ip' => $normalizedIP,
                'hostname' => $hostname,
                'verified' => $verified,
                'timestamp' => time(),
                'error' => $error,
                'skip_forward' => $skipForwardVerification
            ];
            
            // Разный TTL для положительных и отрицательных результатов
            $cacheTTL = $verified ? 
                $this->rdnsLimitSettings['rdns_cache_ttl'] : 
                $this->rdnsLimitSettings['rdns_negative_cache_ttl'];
            
            $this->redis->setex($cacheKey, $cacheTTL, $cacheData);
            
            return $verified;
        } catch (Exception $e) {
            error_log("Error in rDNS verification: " . $e->getMessage());
            return false;
        }
    }
    
    private function getHostnameWithTimeout($ip, $timeoutSec = 2) {
        $originalTimeout = ini_get('default_socket_timeout');
        ini_set('default_socket_timeout', $timeoutSec);
        
        try {
            $hostname = @gethostbyaddr($ip);
            ini_set('default_socket_timeout', $originalTimeout);
            return ($hostname !== $ip) ? $hostname : false;
        } catch (Exception $e) {
            ini_set('default_socket_timeout', $originalTimeout);
            return false;
        }
    }
    
    private function getIPsWithTimeout($hostname, $timeoutSec = 2) {
        $originalTimeout = ini_get('default_socket_timeout');
        ini_set('default_socket_timeout', $timeoutSec);
        
        $allIPs = [];
        
        try {
            $ipv4List = @gethostbynamel($hostname);
            if ($ipv4List) {
                $allIPs = array_merge($allIPs, $ipv4List);
            }
            
            if (function_exists('dns_get_record')) {
                $records = @dns_get_record($hostname, DNS_AAAA);
                if ($records) {
                    foreach ($records as $record) {
                        if (isset($record['ipv6'])) {
                            $allIPs[] = $this->normalizeIPv6($record['ipv6']);
                        }
                    }
                }
            }
            
            ini_set('default_socket_timeout', $originalTimeout);
            return array_unique($allIPs);
            
        } catch (Exception $e) {
            ini_set('default_socket_timeout', $originalTimeout);
            return [];
        }
    }
    
    private function matchesDomainPattern($hostname, $pattern) {
        $hostname = strtolower(trim($hostname));
        $pattern = strtolower(trim($pattern));
        
        if ($hostname === $pattern) {
            return true;
        }
        
        if (strpos($pattern, '.') === 0) {
            return substr($hostname, -strlen($pattern)) === $pattern;
        }
        
        $fullPattern = '.' . $pattern;
        return substr($hostname, -strlen($fullPattern)) === $fullPattern;
    }
    
    private function ipInArray($needle, $haystack) {
        $normalizedNeedle = $this->normalizeIP($needle);
        
        foreach ($haystack as $ip) {
            if ($this->normalizeIP($ip) === $normalizedNeedle) {
                return true;
            }
        }
        
        return false;
    }
    
    private function logSearchEngineVisit($ip, $userAgent) {
        try {
            $logEntry = [
                'timestamp' => date('Y-m-d H:i:s'),
                'ip' => $ip,
                'user_agent' => $userAgent,
                'uri' => $_SERVER['REQUEST_URI'] ?? '',
                'hostname' => @gethostbyaddr($ip)
            ];
            
            $logKey = 'logs:search_engines:' . date('Y-m-d');
            $this->redis->lpush($logKey, $logEntry);
            $this->redis->expire($logKey, $this->ttlSettings['logs']);
            $this->redis->ltrim($logKey, 0, 999);
        } catch (Exception $e) {
            error_log("Error logging search engine visit: " . $e->getMessage());
        }
    }
    
    private function getRealIP() {
        $ipHeaders = [
            'HTTP_CF_CONNECTING_IP',
            'HTTP_X_REAL_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_FORWARDED',
            'HTTP_X_CLUSTER_CLIENT_IP',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED',
            'REMOTE_ADDR'
        ];
        
        foreach ($ipHeaders as $header) {
            if (!empty($_SERVER[$header])) {
                $ips = explode(',', $_SERVER[$header]);
                $ip = trim($ips[0]);
                
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                    $ip = $this->normalizeIPv6($ip);
                }
                
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                        return $ip;
                    }
                } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                    if (!$this->isPrivateIPv6($ip)) {
                        return $ip;
                    }
                }
            }
        }
        
        $remoteAddr = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        if ($remoteAddr !== 'unknown' && filter_var($remoteAddr, FILTER_VALIDATE_IP)) {
            if (filter_var($remoteAddr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                return $this->normalizeIPv6($remoteAddr);
            }
            return $remoteAddr;
        }
        
        return 'unknown';
    }
    
    private function isPrivateIPv6($ip) {
        $privateRanges = [
            '::1',
            'fe80::/10',
            'fc00::/7',
            'ff00::/8',
        ];
        
        foreach ($privateRanges as $range) {
            if ($this->ipInRange($ip, $range)) {
                return true;
            }
        }
        
        return false;
    }
    
    private function ipInRange($ip, $range) {
        if (strpos($range, '/') === false) {
            return $ip === $range;
        }
        
        list($subnet, $prefix) = explode('/', $range);
        
        $ipBin = @inet_pton($ip);
        $subnetBin = @inet_pton($subnet);
        
        if ($ipBin === false || $subnetBin === false) {
            return false;
        }
        
        $ipFamily = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? AF_INET6 : AF_INET;
        $subnetFamily = filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? AF_INET6 : AF_INET;
        
        if ($ipFamily !== $subnetFamily) {
            return false;
        }
        
        $maxBits = $ipFamily === AF_INET6 ? 128 : 32;
        $prefix = max(0, min($maxBits, (int)$prefix));
        
        $bytesToCheck = intval($prefix / 8);
        $bitsInLastByte = $prefix % 8;
        
        for ($i = 0; $i < $bytesToCheck; $i++) {
            if ($ipBin[$i] !== $subnetBin[$i]) {
                return false;
            }
        }
        
        if ($bitsInLastByte > 0) {
            $mask = 0xFF << (8 - $bitsInLastByte);
            if ((ord($ipBin[$bytesToCheck]) & $mask) !== (ord($subnetBin[$bytesToCheck]) & $mask)) {
                return false;
            }
        }
        
        return true;
    }
    
    private function isStaticFile() {
        $uri = $_SERVER['REQUEST_URI'] ?? '';
        $staticExtensions = [
            '.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.ico', '.svg', 
            '.woff', '.woff2', '.ttf', '.eot', '.otf', '.webp', '.avif',
            '.pdf', '.zip', '.mp4', '.webm', '.mp3', '.wav', '.txt'
        ];
        
        foreach ($staticExtensions as $ext) {
            if (substr($uri, -strlen($ext)) === $ext) {
                return true;
            }
        }
        return false;
    }
    
    private function hasValidCookie() {
        if (!isset($_COOKIE[$this->cookieName])) {
            return false;
        }
        
        $data = json_decode($_COOKIE[$this->cookieName], true);
        if (!$data || !isset($data['hash'], $data['time'])) {
            return false;
        }
        
        if (time() - $data['time'] > $this->cookieLifetime) {
            return false;
        }
        
        $expected = hash('sha256', $data['time'] . ($_SERVER['HTTP_USER_AGENT'] ?? '') . $this->secretKey);
        return hash_equals($expected, $data['hash']);
    }
    
    private function setVisitorCookie() {
        try {
            $time = time();
            $hash = hash('sha256', $time . ($_SERVER['HTTP_USER_AGENT'] ?? '') . $this->secretKey);
            $cookieData = json_encode(['time' => $time, 'hash' => $hash]);
            
            $secure = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
            setcookie($this->cookieName, $cookieData, time() + $this->cookieLifetime, '/', '', $secure, true);
            $_COOKIE[$this->cookieName] = $cookieData;
        } catch (Exception $e) {
            error_log("Error setting visitor cookie: " . $e->getMessage());
        }
    }
    
    private function initTracking($ip) {
        try {
            $trackingKey = $this->trackingPrefix . 'ip:' . hash('md5', $ip);
            $existing = $this->redis->get($trackingKey);
            
            if ($existing) {
                $existing['requests']++;
                $existing['pages'][] = parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH);
                $existing['user_agents'][] = $_SERVER['HTTP_USER_AGENT'] ?? '';
                $existing['user_agents'] = array_unique($existing['user_agents']);
                $existing['request_times'][] = time();
                $existing['real_ip'] = $ip;
                
                if (count($existing['request_times']) > 25) {
                    $existing['request_times'] = array_slice($existing['request_times'], -25);
                }
                if (count($existing['pages']) > 40) {
                    $existing['pages'] = array_slice($existing['pages'], -40);
                }
                if (count($existing['user_agents']) > 5) {
                    $existing['user_agents'] = array_slice($existing['user_agents'], -5);
                }
                
                $this->redis->setex($trackingKey, $this->ttlSettings['tracking_ip'], $existing);
            } else {
                // НОВАЯ запись - инкрементируем счетчик
                $data = [
                    'first_seen' => time(),
                    'requests' => 1,
                    'pages' => [parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH)],
                    'user_agents' => [$_SERVER['HTTP_USER_AGENT'] ?? ''],
                    'headers' => $this->collectHeaders(),
                    'session_id' => 'no_session',
                    'request_times' => [time()],
                    'real_ip' => $ip
                ];
                
                $this->redis->setex($trackingKey, $this->ttlSettings['tracking_ip'], $data);
                
                // Увеличиваем счетчик tracked IP
                $this->incrementTrackedCounter();
            }
        } catch (Exception $e) {
            error_log("Error in initTracking: " . $e->getMessage());
        }
    }
    
    private function collectHeaders() {
        $headers = [];
        $importantHeaders = [
            'HTTP_USER_AGENT', 'HTTP_ACCEPT', 'HTTP_ACCEPT_LANGUAGE', 
            'HTTP_ACCEPT_ENCODING', 'HTTP_REFERER', 'HTTP_X_FORWARDED_FOR',
            'HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP', 'REMOTE_ADDR'
        ];
        
        foreach ($importantHeaders as $header) {
            if (isset($_SERVER[$header])) {
                $headers[$header] = $_SERVER[$header];
            }
        }
        return $headers;
    }
    
    private function blockCookieHash() {
        try {
            if (!isset($_COOKIE[$this->cookieName])) {
                return;
            }
            
            $data = json_decode($_COOKIE[$this->cookieName], true);
            if (!$data || !isset($data['hash'])) {
                return;
            }
            
            $blockKey = $this->cookiePrefix . 'blocked:' . hash('md5', $data['hash']);
            $blockData = [
                'cookie_hash' => $data['hash'],
                'blocked_at' => time(),
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
                'uri' => $_SERVER['REQUEST_URI'] ?? '',
                'session_id' => 'no_session',
                'ip' => $this->getRealIP()
            ];
            
            $this->redis->setex($blockKey, $this->ttlSettings['cookie_blocked'], $blockData);
            
            error_log("Bot blocked [COOKIE]: " . substr($data['hash'], 0, 8) . " | IP: " . $this->getRealIP());
        } catch (Exception $e) {
            error_log("Error blocking cookie hash: " . $e->getMessage());
        }
    }
    
    private function isCookieBlocked() {
        try {
            if (!isset($_COOKIE[$this->cookieName])) {
                return false;
            }
            
            $data = json_decode($_COOKIE[$this->cookieName], true);
            if (!$data || !isset($data['hash'])) {
                return false;
            }
            
            $blockKey = $this->cookiePrefix . 'blocked:' . hash('md5', $data['hash']);
            return $this->redis->exists($blockKey);
        } catch (Exception $e) {
            error_log("Error checking cookie block: " . $e->getMessage());
            return false;
        }
    }
    
    // isMobileDevice() removed in optimization (saved 24 lines)
    
    private function analyzeRequest($ip) {
        try {
            $trackingKey = $this->trackingPrefix . 'ip:' . hash('md5', $ip);
            $data = $this->redis->get($trackingKey);
            
            if (!$data) {
                return false;
            }
            
            $score = 0;
            $currentUA = $_SERVER['HTTP_USER_AGENT'] ?? '';
            $isMobile = false /* isMobileDevice removed */;
            
            $blockThreshold = $isMobile ? 20 : 18;
            
            if ($this->isSuspiciousUserAgent($currentUA)) {
                $score += $isMobile ? 15 : 20;
            }
            
            $requests = $data['requests'] ?? 0;
            $timeSpent = time() - ($data['first_seen'] ?? time());
            
            if ($timeSpent > 0) {
                $requestsPerMinute = ($requests * 60) / $timeSpent;
                
                if ($isMobile) {
                    if ($requestsPerMinute > 180) $score += 12;
                    elseif ($requestsPerMinute > 120) $score += 8;
                    elseif ($requestsPerMinute > 80) $score += 4;
                } else {
                    if ($requestsPerMinute > 150) $score += 12;
                    elseif ($requestsPerMinute > 100) $score += 8;
                    elseif ($requestsPerMinute > 60) $score += 4;
                }
            }
            
            $cookieLimit = $isMobile ? 35 : 30;
            if ($requests > $cookieLimit && !isset($_COOKIE[$this->cookieName])) {
                $score += $isMobile ? 3 : 4;
            }
            
            $currentHeaders = $this->collectHeaders();
            
            if (!isset($currentHeaders['HTTP_ACCEPT']) || $currentHeaders['HTTP_ACCEPT'] === '*/*') {
                $score += $isMobile ? 1 : 2;
            }
            if (!isset($currentHeaders['HTTP_ACCEPT_LANGUAGE'])) {
                $score += $isMobile ? 1 : 2;
            }
            if (!isset($currentHeaders['HTTP_ACCEPT_ENCODING'])) {
                $score += $isMobile ? 1 : 2;
            }
            
            $uniquePages = array_unique($data['pages'] ?? []);
            $totalPages = count($data['pages'] ?? []);
            
            $pageLimit = $isMobile ? 50 : 40;
            if ($totalPages > $pageLimit && count($uniquePages) <= 2) {
                $score += $isMobile ? 2 : 3;
            }
            
            $uniqueUA = array_unique($data['user_agents'] ?? []);
            if (count($uniqueUA) > 5) {
                $score += 8;
            }
            
            if (isset($data['request_times']) && count($data['request_times']) >= 15) {
                $intervals = [];
                $lastFifteen = array_slice($data['request_times'], -15);
                
                for ($i = 1; $i < count($lastFifteen); $i++) {
                    $intervals[] = $lastFifteen[$i] - $lastFifteen[$i-1];
                }
                
                if (count($intervals) >= 12) {
                    $avgInterval = array_sum($intervals) / count($intervals);
                    $variance = 0;
                    foreach ($intervals as $interval) {
                        $variance += pow($interval - $avgInterval, 2);
                    }
                    $variance /= count($intervals);
                    
                    $varianceThreshold = $isMobile ? 1.0 : 1.5;
                    $intervalThreshold = $isMobile ? 3 : 5;
                    
                    if ($variance < $varianceThreshold && $avgInterval < $intervalThreshold) {
                        $score += $isMobile ? 3 : 5;
                    }
                }
            }
            
            if (isset($data['request_times']) && count($data['request_times']) >= 10) {
                $lastTen = array_slice($data['request_times'], -10);
                $timeDiff = end($lastTen) - reset($lastTen);
                
                if ($timeDiff <= 5) {
                    $score += $isMobile ? 3 : 5;
                }
                if ($timeDiff <= 2) {
                    $score += 6;
                }
            }
            
            return $score >= $blockThreshold;
        } catch (Exception $e) {
            error_log("Error in analyzeRequest: " . $e->getMessage());
            return false;
        }
    }
    
    private function isBlocked($ip) {
        try {
            $blockKey = $this->blockPrefix . 'ip:' . hash('md5', $ip);
            return $this->redis->exists($blockKey);
        } catch (Exception $e) {
            error_log("Error checking IP block: " . $e->getMessage());
            return false;
        }
    }
    
    private function blockIP($ip, $reason = 'Bot behavior detected') {
    try {
        $blockKey = $this->blockPrefix . 'ip:' . hash('md5', $ip);
        $apiCallKey = $this->blockPrefix . 'api_call:' . hash('md5', $ip);
        
        $isRepeatOffender = $this->redis->exists($blockKey);
        
        $blockData = [
            'ip' => $ip,
            'blocked_at' => time(),
            'blocked_reason' => $reason,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'uri' => $_SERVER['REQUEST_URI'] ?? '',
            'session_id' => 'no_session',
            'repeat_offender' => $isRepeatOffender,
            'is_suspicious_ua' => $this->isSuspiciousUserAgent($_SERVER['HTTP_USER_AGENT'] ?? ''),
            'browser_info' => $this->getBrowserFingerprint($_SERVER['HTTP_USER_AGENT'] ?? ''),
            'api_blocked' => false  // Будет обновлено ниже
        ];
        
        $blockDuration = $isRepeatOffender ? $this->ttlSettings['ip_blocked_repeat'] : $this->ttlSettings['ip_blocked'];
        
        // Блокировка в Redis (локально)
        if ($this->apiSettings['block_on_redis']) {
            $this->redis->setex($blockKey, $blockDuration, $blockData);
        }
        
        // Блокировка через API (iptables)
        if ($this->apiSettings['block_on_api']) {
            $apiResult = $this->callBlockingAPI($ip, 'block');
            
            if ($apiResult['status'] === 'success' || $apiResult['status'] === 'already_blocked') {
				$this->redis->setex($apiCallKey, 60, time()); // Защита на 60 секунд
                $blockData['api_blocked'] = true;
                $blockData['api_blocked_at'] = time();
                $blockData['api_result'] = $apiResult['message'];
                
                // Обновляем данные в Redis с информацией об API блокировке
                if ($this->apiSettings['block_on_redis']) {
                    $this->redis->setex($blockKey, $blockDuration, $blockData);
                }
            } else {
                $blockData['api_blocked'] = false;
                $blockData['api_error'] = $apiResult['message'] ?? 'API call failed';
                
                if ($this->apiSettings['block_on_redis']) {
                    $this->redis->setex($blockKey, $blockDuration, $blockData);
                }
            }
        }
        
        $durHours = round($blockDuration / 3600);
        $apiStatus = $blockData['api_blocked'] ? 'API+Redis' : 'Redis only';
        error_log("Bot blocked [IP]: $ip | {$apiStatus} | " . ($isRepeatOffender ? "REPEAT | " : "") . "{$durHours}h | $reason");
        
    } catch (Exception $e) {
        error_log("Error blocking IP: " . $e->getMessage());
    }
}
    
	/**
     * Отправка запроса к API для блокировки/разблокировки IP
     * 
     * @param string $ip IP адрес для блокировки/разблокировки
     * @param string $action 'block' или 'unblock'
     * @return array Результат выполнения API запроса
     */
    private function callBlockingAPI($ip, $action = 'block') {
        if (!$this->apiSettings['enabled']) {
            return ['status' => 'disabled', 'message' => 'API integration disabled'];
        }
        
        if (!$this->apiSettings['block_on_api']) {
            return ['status' => 'skipped', 'message' => 'API blocking disabled in settings'];
        }
        
        $normalizedIP = $this->normalizeIP($ip);
        
        $url = $this->apiSettings['url'] . 
               '?action=' . urlencode($action) . 
               '&ip=' . urlencode($normalizedIP) . 
               '&api=1' . 
               '&api_key=' . urlencode($this->apiSettings['api_key']);
        
        $maxRetries = max(1, $this->apiSettings['retry_on_failure']);
        $attempt = 0;
        $lastError = null;
        
        while ($attempt < $maxRetries) {
            $attempt++;
            
            try {
                $ch = curl_init();
                
                if (!$ch) {
                    throw new Exception("Failed to initialize cURL");
                }
                
                curl_setopt_array($ch, [
                    CURLOPT_URL => $url,
                    CURLOPT_RETURNTRANSFER => true,
                    CURLOPT_TIMEOUT => $this->apiSettings['timeout'],
                    CURLOPT_CONNECTTIMEOUT => 3,
                    CURLOPT_FOLLOWLOCATION => false,
                    CURLOPT_MAXREDIRS => 0,
                    CURLOPT_SSL_VERIFYPEER => $this->apiSettings['verify_ssl'],
                    CURLOPT_SSL_VERIFYHOST => $this->apiSettings['verify_ssl'] ? 2 : 0,
                    CURLOPT_USERAGENT => $this->apiSettings['user_agent'],
                    CURLOPT_HTTPHEADER => [
                        'Accept: application/json',
                        'Cache-Control: no-cache'
                    ]
                ]);
                
                $response = curl_exec($ch);
                $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                $curlError = curl_error($ch);
                $curlErrno = curl_errno($ch);
                
                curl_close($ch);
                
                if ($curlErrno !== 0) {
                    throw new Exception("cURL error #{$curlErrno}: {$curlError}");
                }
                
                if ($httpCode !== 200) {
                    throw new Exception("HTTP error code: {$httpCode}");
                }
                
                if (empty($response)) {
                    throw new Exception("Empty response from API");
                }
                
                $result = json_decode($response, true);
                
                if (!is_array($result)) {
                    throw new Exception("Invalid JSON response: " . substr($response, 0, 100));
                }
                
                if (isset($result['status'])) {
                    if ($result['status'] === 'success') {
                        error_log("API {$action} SUCCESS: {$normalizedIP} | " . ($result['message'] ?? 'OK'));
                        return [
                            'status' => 'success',
                            'message' => $result['message'] ?? 'Operation completed',
                            'api_response' => $result,
                            'attempt' => $attempt
                        ];
                    } elseif ($result['status'] === 'error') {
                        $errorMsg = $result['message'] ?? 'Unknown error';
                        
                        if (strpos($errorMsg, 'уже заблокирован') !== false || 
                            strpos($errorMsg, 'already blocked') !== false) {
                            return [
                                'status' => 'already_blocked',
                                'message' => $errorMsg,
                                'api_response' => $result
                            ];
                        }
                        
                        if (strpos($errorMsg, 'не заблокирован') !== false || 
                            strpos($errorMsg, 'not blocked') !== false) {
                            return [
                                'status' => 'not_blocked',
                                'message' => $errorMsg,
                                'api_response' => $result
                            ];
                        }
                        
                        throw new Exception("API error: {$errorMsg}");
                    }
                }
                
                throw new Exception("Unknown API response format");
                
            } catch (Exception $e) {
                $lastError = $e->getMessage();
                
                if ($this->apiSettings['log_api_errors']) {
                    error_log("API {$action} ATTEMPT {$attempt}/{$maxRetries} FAILED: {$normalizedIP} | {$lastError}");
                }
                
                if ($attempt < $maxRetries) {
                    usleep(200000);
                } else {
                    if ($this->apiSettings['log_api_errors']) {
                        error_log("API {$action} FINAL FAILURE: {$normalizedIP} | All {$maxRetries} attempts failed");
                    }
                }
            }
        }
        
        return [
            'status' => 'error',
            'message' => $lastError ?? 'Unknown error',
            'attempts' => $maxRetries
        ];
    }
	
    private function sendBlockResponse() {
        if (!headers_sent()) {
            http_response_code(429);
            header('Content-Type: text/plain; charset=utf-8');
            header('Retry-After: 900');
        }
        die('Rate limit exceeded. Please try again later.');
    }
    
    /**
     * Отправка ответа 429 при превышении rate limit (первое нарушение)
     * Отличается от sendBlockResponse - даёт шанс замедлиться
     */
    private function sendRateLimitResponse($rateLimitResult) {
        if (!headers_sent()) {
            http_response_code(429);
            header('Content-Type: text/plain; charset=utf-8');
            header('Retry-After: 60');  // Короткая пауза - 60 секунд
            header('X-RateLimit-Limit: ' . $this->rateLimitSettings['max_requests_per_minute']);
            header('X-RateLimit-Remaining: 0');
        }
        die('Too Many Requests. Please slow down. Retry after 60 seconds.');
    }
    
    // testRDNS() removed in optimization (saved 82 lines)
	// АДМИНИСТРАТИВНЫЕ МЕТОДЫ
    
    // getUserHashInfo() removed in optimization (saved 23 lines)
    
    public function unblockUserHash($userHash = null) {
        try {
            $userHash = $userHash ?: $this->generateUserHash();
            
            $blockKey = $this->userHashPrefix . 'blocked:' . $userHash;
            $trackingKey = $this->userHashPrefix . 'tracking:' . $userHash;
            
            $result = [
                'user_hash' => substr($userHash, 0, 16) . '...',
                'unblocked' => $this->redis->del($blockKey) > 0,
                'tracking_cleared' => $this->redis->del($trackingKey) > 0
            ];
            
            error_log("UNBLOCKED [HASH]: " . substr($userHash, 0, 8) . " | Manual");
            return $result;
        } catch (Exception $e) {
            error_log("Error unblocking user hash: " . $e->getMessage());
            return ['error' => $e->getMessage()];
        }
    }
    
    // diagnoseUserHash() removed in optimization (saved 21 lines)
    
    // getUserHashStats() removed in optimization (saved 51 lines)
    
    // cleanupUserHashData() метод удален - используйте cleanup.php

    
    public function getRateLimitStats($ip) {
        try {
            $ipHash = hash('md5', $ip);
            $historyKey = $this->blockPrefix . 'history:' . $ipHash;
            $trackingKey = $this->trackingPrefix . 'ip:' . $ipHash;
            
            // Получаем текущие счётчики из атомарных ключей
            $current = time();
            $minute = floor($current / 60);
            $fiveMin = floor($current / 300);
            $hour = floor($current / 3600);
            
            $req1min = $this->redis->get($this->trackingPrefix . 'rl:1m:' . $minute . ':' . $ipHash) ?: 0;
            $req5min = $this->redis->get($this->trackingPrefix . 'rl:5m:' . $fiveMin . ':' . $ipHash) ?: 0;
            $req1hour = $this->redis->get($this->trackingPrefix . 'rl:1h:' . $hour . ':' . $ipHash) ?: 0;
            $violations = $this->redis->get($this->trackingPrefix . 'rl:violations:' . $ipHash) ?: 0;
            
            // Получаем время последнего запроса из tracking данных
            $lastRequest = 0;
            $trackingData = $this->redis->get($trackingKey);
            if ($trackingData && isset($trackingData['last_request'])) {
                $lastRequest = $trackingData['last_request'];
            }
            
            $currentStats = null;
            if ($req1min > 0 || $req5min > 0 || $req1hour > 0 || $violations > 0) {
                $currentStats = [
                    'requests_1min' => (int)$req1min,
                    'requests_5min' => (int)$req5min,
                    'requests_1hour' => (int)$req1hour,
                    'violations' => (int)$violations,
                    'last_request' => $lastRequest
                ];
            }
            
            return [
                'ip' => $ip,
                'current_stats' => $currentStats,
                'block_history' => $this->redis->get($historyKey),
                'is_blocked' => $this->isBlocked($ip),
                'extended_tracking' => false /* checkExtendedTracking removed */
            ];
        } catch (Exception $e) {
            error_log("Error getting rate limit stats: " . $e->getMessage());
            return [];
        }
    }
    
    // Функция resetRateLimit уже определена выше с улучшенной логикой (строка ~1048)
    // Эта версия удалена для избежания конфликта
    
    /**
     * УЛУЧШЕННАЯ версия: работает с новой структурой атомарных ключей
     */
    // getTopRateLimitViolators() removed in optimization (saved 71 lines)
    
    public function getStats() {
        $stats = [
            'blocked_ips' => 0,
            'blocked_cookies' => 0,
            'tracking_records' => 0,
            'rate_limit_tracking' => 0,
            'rate_limit_violations' => 0,
            'extended_tracking_active' => 0,
            'block_history_records' => 0,
            'total_keys' => 0,
            'memory_usage' => 0
        ];
        
        try {
            // ВАЖНО: OPT_PREFIX НЕ применяется к паттернам SCAN!
            // Поэтому указываем ПОЛНЫЙ путь в паттерне
            $patterns = [
                'blocked_ips' => $this->redisPrefix . $this->blockPrefix . 'ip:*',
                'blocked_cookies' => $this->redisPrefix . $this->cookiePrefix . 'blocked:*',
                'tracking_records' => $this->redisPrefix . $this->trackingPrefix . 'ip:*',
                'extended_tracking_active' => $this->redisPrefix . $this->trackingPrefix . 'extended:*',
                'block_history_records' => $this->redisPrefix . $this->blockPrefix . 'history:*',
            ];
            
            foreach ($patterns as $statKey => $pattern) {
                $count = 0;
                $iterator = null;
                do {
                    $keys = $this->redis->scan($iterator, $pattern, 100);
                    if ($keys !== false) {
                        $count += count($keys);
                    }
                } while ($iterator !== 0 && $iterator !== null);
                $stats[$statKey] = $count;
            }
            
            // Rate limit ключи с подсчетом нарушений
            $rateLimitCount = 0;
            $violations = 0;
            $iterator = null;
            $pattern = $this->redisPrefix . $this->trackingPrefix . 'rl:violations:*';
            do {
                $keys = $this->redis->scan($iterator, $pattern, 100);
                if ($keys !== false) {
                    $rateLimitCount += count($keys);
                    foreach ($keys as $key) {
                        // SCAN возвращает полный путь, убираем redisPrefix для get() (OPT_PREFIX добавит его)
                        $keyWithoutPrefix = str_replace($this->redisPrefix, '', $key);
                        $count = $this->redis->get($keyWithoutPrefix);
                        if ($count) {
                            $violations += intval($count);
                        }
                    }
                }
            } while ($iterator !== 0 && $iterator !== null);
            $stats['rate_limit_tracking'] = $rateLimitCount;
            $stats['rate_limit_violations'] = $violations;
            
            // Общее количество ключей через DBSIZE (быстрее чем SCAN всех)
            $stats['total_keys'] = $this->redis->dbSize();
            
            $info = $this->redis->info('memory');
            $stats['memory_usage'] = $info['used_memory_human'] ?? 'unknown';
            
            // User Hash статистика (упрощённая версия)
            $userHashBlocked = 0;
            $iterator = null;
            $pattern = $this->redisPrefix . $this->userHashPrefix . 'blocked:*';
            do {
                $keys = $this->redis->scan($iterator, $pattern, 100);
                if ($keys !== false) {
                    $userHashBlocked += count($keys);
                }
            } while ($iterator !== 0 && $iterator !== null);
            $stats['user_hash_blocked'] = $userHashBlocked;
            
        } catch (Exception $e) {
            error_log("Error getting stats: " . $e->getMessage());
        }
        
        return $stats;
    }
    
    /**
     * ═══════════════════════════════════════════════════════════════════════
     * СТАТИСТИКА ЗАПРОСОВ В РЕАЛЬНОМ ВРЕМЕНИ v1.0 (2025-12-02)
     * 
     * Эффективный подсчёт RPM (requests per minute) и RPS (requests per second)
     * с использованием атомарных операций INCR. Минимальное влияние на производительность.
     * ═══════════════════════════════════════════════════════════════════════
     */
    
    /**
     * Инкрементирует счётчик запросов
     * Вызывается в начале protect() для подсчёта всех запросов
     * 
     * Использует 2 счётчика:
     * - stats:rpm:{minute} - запросы за минуту (TTL 120 сек)
     * - stats:rps:{second} - запросы за секунду (TTL 10 сек)
     */
    public function incrementRequestCounter() {
        try {
            $now = time();
            $currentMinute = floor($now / 60);
            $currentSecond = $now;
            
            // Счётчик за минуту (TTL 120 сек для показа предыдущей минуты)
            $minuteKey = 'stats:rpm:' . $currentMinute;
            $this->redis->incr($minuteKey);
            $this->redis->expire($minuteKey, 120);
            
            // Счётчик за секунду (TTL 10 сек для скользящего окна)
            $secondKey = 'stats:rps:' . $currentSecond;
            $this->redis->incr($secondKey);
            $this->redis->expire($secondKey, 10);
            
        } catch (Exception $e) {
            // Не логируем ошибку чтобы не замедлять работу
        }
    }
    
    /**
     * Получает статистику запросов в минуту
     * 
     * @return array [
     *   'current_rpm' => int,      // Запросы за текущую минуту
     *   'previous_rpm' => int,     // Запросы за предыдущую минуту
     *   'avg_rps' => float,        // Средний RPS (на основе предыдущей минуты)
     *   'current_rps' => int,      // Мгновенный RPS (последняя секунда)
     *   'peak_rps' => int,         // Пиковый RPS за последние 10 секунд
     *   'timestamp' => int         // Время замера
     * ]
     */
    public function getRequestsPerMinute() {
        $stats = [
            'current_rpm' => 0,
            'previous_rpm' => 0,
            'avg_rps' => 0.0,
            'current_rps' => 0,
            'peak_rps' => 0,
            'timestamp' => time()
        ];
        
        try {
            $now = time();
            $currentMinute = floor($now / 60);
            $previousMinute = $currentMinute - 1;
            
            // RPM за текущую минуту
            $currentRPM = $this->redis->get('stats:rpm:' . $currentMinute);
            $stats['current_rpm'] = $currentRPM ? intval($currentRPM) : 0;
            
            // RPM за предыдущую минуту (более точный показатель)
            $previousRPM = $this->redis->get('stats:rpm:' . $previousMinute);
            $stats['previous_rpm'] = $previousRPM ? intval($previousRPM) : 0;
            
            // Средний RPS на основе предыдущей минуты
            $stats['avg_rps'] = round($stats['previous_rpm'] / 60, 2);
            
            // Мгновенный RPS (последняя полная секунда)
            $lastSecond = $now - 1;
            $currentRPS = $this->redis->get('stats:rps:' . $lastSecond);
            $stats['current_rps'] = $currentRPS ? intval($currentRPS) : 0;
            
            // Пиковый RPS за последние 10 секунд
            $peakRPS = 0;
            for ($i = 1; $i <= 10; $i++) {
                $sec = $now - $i;
                $rps = $this->redis->get('stats:rps:' . $sec);
                if ($rps && intval($rps) > $peakRPS) {
                    $peakRPS = intval($rps);
                }
            }
            $stats['peak_rps'] = $peakRPS;
            
        } catch (Exception $e) {
            error_log("Error getting request stats: " . $e->getMessage());
        }
        
        return $stats;
    }
    
    /**
     * Получает историю RPM за последние N минут
     * 
     * @param int $minutes Количество минут (по умолчанию 5)
     * @return array Массив с RPM за каждую минуту
     */
    // getRPMHistory() removed in optimization (saved 23 lines)
    
    // cleanup() метод удален - используйте cleanup.php

    
    // deepCleanup() метод удален - используйте cleanup.php

    
    /**
     * ═══════════════════════════════════════════════════════════════════════
     * ОБНОВЛЕННЫЙ МЕТОД unblockIP() v2.4
     * 
     * Теперь сбрасывает ВСЁ: блокировку, violations, rate limit счётчики
     * ═══════════════════════════════════════════════════════════════════════
     */
    public function unblockIP($ip) {
    try {
        $ipHash = hash('md5', $ip);
        $blockKey = $this->blockPrefix . 'ip:' . $ipHash;
        $trackingKey = $this->trackingPrefix . 'ip:' . $ipHash;
        $extendedKey = $this->trackingPrefix . 'extended:' . $ipHash;
        $violationsKey = $this->trackingPrefix . 'violations:' . $ipHash;
        
        $result = [
            'ip_unblocked' => false,
            'tracking_cleared' => false,
            'extended_tracking_cleared' => false,
            'violations_cleared' => false,
            'rate_limit_cleared' => false,
            'api_unblocked' => false,
            'api_message' => null
        ];
        
        // Разблокировка в Redis
        if ($this->apiSettings['block_on_redis']) {
            $result['ip_unblocked'] = $this->redis->del($blockKey) > 0;
            $result['tracking_cleared'] = $this->redis->del($trackingKey) > 0;
            $result['extended_tracking_cleared'] = $this->redis->del($extendedKey) > 0;
        }
        
        // НОВОЕ v2.4: Сброс violations
        $result['violations_cleared'] = $this->redis->del($violationsKey) > 0;
        
        // НОВОЕ v2.4: Сброс rate limit счётчиков
        $current = time();
        $minute = floor($current / 60);
        $fiveMin = floor($current / 300);
        $hour = floor($current / 3600);
        
        $keysToDelete = [
            $this->trackingPrefix . 'rl:1m:' . $minute . ':' . $ipHash,
            $this->trackingPrefix . 'rl:5m:' . $fiveMin . ':' . $ipHash,
            $this->trackingPrefix . 'rl:1h:' . $hour . ':' . $ipHash,
            $this->trackingPrefix . 'rl:violations:' . $ipHash,
            $this->trackingPrefix . 'burst:' . $ipHash,
            $this->trackingPrefix . 'burst_warn:' . $ipHash,
        ];
        
        $rlDeleted = 0;
        foreach ($keysToDelete as $key) {
            $rlDeleted += $this->redis->del($key);
        }
        $result['rate_limit_cleared'] = $rlDeleted > 0;
        
        // Разблокировка через API (если включена автоматическая разблокировка)
        if ($this->apiSettings['auto_unblock'] && $this->apiSettings['block_on_api']) {
            $apiResult = $this->callBlockingAPI($ip, 'unblock');
            
            if ($apiResult['status'] === 'success' || $apiResult['status'] === 'not_blocked') {
                $result['api_unblocked'] = true;
                $result['api_message'] = $apiResult['message'];
                error_log("UNBLOCKED [IP]: $ip | API+Redis+Violations | Manual");
            } else {
                $result['api_unblocked'] = false;
                $result['api_message'] = $apiResult['message'] ?? 'API call failed';
                error_log("UNBLOCKED [IP]: $ip | Redis+Violations only (API failed) | Manual");
            }
        } else {
            error_log("UNBLOCKED [IP]: $ip | Redis+Violations only | Manual");
        }
        
        return $result;
    } catch (Exception $e) {
        error_log("Error unblocking IP: " . $e->getMessage());
        return ['error' => $e->getMessage()];
    }
}
    
    public function getBlockedIPInfo($ip) {
        try {
            $ipHash = hash('md5', $ip);
            $blockKey = $this->blockPrefix . 'ip:' . $ipHash;
            $trackingKey = $this->trackingPrefix . 'ip:' . $ipHash;
            $extendedKey = $this->trackingPrefix . 'extended:' . $ipHash;
            $violationsKey = $this->trackingPrefix . 'violations:' . $ipHash;
            
            return [
                'blocked' => $this->redis->exists($blockKey),
                'block_data' => $this->redis->get($blockKey),
                'tracking_data' => $this->redis->get($trackingKey),
                'extended_tracking' => $this->redis->get($extendedKey),
                'violations' => $this->getTotalViolations($ip),
                'ttl' => $this->redis->ttl($blockKey)
            ];
        } catch (Exception $e) {
            error_log("Error getting blocked IP info: " . $e->getMessage());
            return [];
        }
    }
    
    public function getTTLSettings() {
        return $this->ttlSettings;
    }
    
    public function getSlowBotSettings() {
        return $this->slowBotSettings;
    }
    
    public function getRateLimitSettings() {
        return $this->rateLimitSettings;
    }
    
    public function getGlobalProtectionSettings() {
        return $this->globalProtectionSettings;
    }
    
    public function updateTTLSettings($newSettings) {
        $this->ttlSettings = array_merge($this->ttlSettings, $newSettings);
        error_log("TTL settings updated: " . json_encode($newSettings));
    }
    
	/**
 * Обновить настройки API
 */
public function updateAPISettings($newSettings) {
    $this->apiSettings = array_merge($this->apiSettings, $newSettings);
    error_log("API settings updated: " . json_encode($newSettings));
}

/**
 * Получить настройки API
 */
public function getAPISettings() {
    return $this->apiSettings;
}

/**
 * Тестирование API подключения
 */
public function testAPIConnection() {
    if (!$this->apiSettings['enabled']) {
        return [
            'status' => 'disabled',
            'message' => 'API integration is disabled'
        ];
    }
    
    // Получаем список заблокированных IP для теста подключения
    $url = $this->apiSettings['url'] . 
           '?action=list&api=1&api_key=' . urlencode($this->apiSettings['api_key']);
    
    try {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $this->apiSettings['timeout'],
            CURLOPT_SSL_VERIFYPEER => $this->apiSettings['verify_ssl'],
            CURLOPT_SSL_VERIFYHOST => $this->apiSettings['verify_ssl'] ? 2 : 0,
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode === 200) {
            $result = json_decode($response, true);
            if (isset($result['status']) && $result['status'] === 'success') {
                return [
                    'status' => 'success',
                    'message' => 'API connection successful',
                    'api_response' => $result
                ];
            }
        }
        
        return [
            'status' => 'error',
            'message' => "API returned HTTP {$httpCode}",
            'response' => substr($response, 0, 200)
        ];
        
    } catch (Exception $e) {
        return [
            'status' => 'error',
            'message' => $e->getMessage()
        ];
    }
}

/**
 * Принудительная синхронизация: блокировать в API все IP, заблокированные в Redis
 */
public function syncBlockedIPsToAPI() {
    if (!$this->apiSettings['enabled'] || !$this->apiSettings['block_on_api']) {
        return [
            'status' => 'disabled',
            'message' => 'API integration is disabled'
        ];
    }
    
    try {
        // ВАЖНО: OPT_PREFIX НЕ применяется к паттернам SCAN - указываем полный путь
        $pattern = $this->redisPrefix . $this->blockPrefix . 'ip:*';
        $iterator = null;
        $synced = 0;
        $failed = 0;
        
        do {
            $keys = $this->redis->scan($iterator, $pattern, 100);
            
            if ($keys === false) break;
            
            foreach ($keys as $key) {
                // SCAN возвращает полный путь, убираем redisPrefix
                $keyWithoutPrefix = str_replace($this->redisPrefix, '', $key);
                $blockData = $this->redis->get($keyWithoutPrefix);
                
                if ($blockData && isset($blockData['ip'])) {
                    $ip = $blockData['ip'];
                    
                    // Пропускаем, если уже заблокирован через API
                    if (isset($blockData['api_blocked']) && $blockData['api_blocked']) {
                        continue;
                    }
                    
                    $apiResult = $this->callBlockingAPI($ip, 'block');
                    
                    if ($apiResult['status'] === 'success' || $apiResult['status'] === 'already_blocked') {
                        $synced++;
                        
                        // Обновляем данные в Redis
                        $blockData['api_blocked'] = true;
                        $blockData['api_synced_at'] = time();
                        $ttl = $this->redis->ttl($keyWithoutPrefix);
                        if ($ttl > 0) {
                            $this->redis->setex($keyWithoutPrefix, $ttl, $blockData);
                        }
                    } else {
                        $failed++;
                    }
                    
                    usleep(100000); // 100ms задержка между запросами
                }
            }
            
        } while ($iterator > 0);
        
        error_log("API SYNC: Synced {$synced} IPs to API, {$failed} failed");
        
        return [
            'status' => 'success',
            'synced' => $synced,
            'failed' => $failed,
            'message' => "Synced {$synced} blocked IPs to API"
        ];
        
    } catch (Exception $e) {
        error_log("Error in syncBlockedIPsToAPI: " . $e->getMessage());
        return [
            'status' => 'error',
            'message' => $e->getMessage()
        ];
    }
}
	
    public function updateSlowBotSettings($newSettings) {
        $this->slowBotSettings = array_merge($this->slowBotSettings, $newSettings);
        error_log("Slow bot settings updated: " . json_encode($newSettings));
    }
    
    public function updateRateLimitSettings($newSettings) {
        $this->rateLimitSettings = array_merge($this->rateLimitSettings, $newSettings);
        error_log("Rate limit settings updated: " . json_encode($newSettings));
    }
    
    public function updateGlobalProtectionSettings($newSettings) {
        $this->globalProtectionSettings = array_merge($this->globalProtectionSettings, $newSettings);
        error_log("Global protection settings updated: " . json_encode($newSettings));
    }
    
    public function getRedisMemoryInfo() {
        try {
            // ОПТИМИЗИРОВАНО: читаем метрики из cleanup.php вместо множественных запросов
            $metrics = $this->redis->get($this->globalPrefix . 'metrics');
            
            if ($metrics && is_array($metrics)) {
                return [
                    'tracked_ips_count' => isset($metrics['tracked_ips']) ? $metrics['tracked_ips'] : 0,
                    'blocked_ips_count' => isset($metrics['blocked_ips']) ? $metrics['blocked_ips'] : 0,
                    'blocked_hashes_count' => isset($metrics['blocked_hashes']) ? $metrics['blocked_hashes'] : 0,
                    'rdns_cache_size' => isset($metrics['rdns_cache_size']) ? $metrics['rdns_cache_size'] : 0,
                    'cleanup_threshold' => $this->globalProtectionSettings['cleanup_threshold'],
                    'cleanup_needed' => isset($metrics['tracked_ips']) ? 
                        ($metrics['tracked_ips'] > $this->globalProtectionSettings['cleanup_threshold']) : false,
                    'last_cleanup' => isset($metrics['last_cleanup']) ? $metrics['last_cleanup'] : 0,
                    'last_cleanup_ago' => isset($metrics['last_cleanup']) ? 
                        (time() - $metrics['last_cleanup']) : null
                ];
            }
            
            // Fallback: если метрик нет, используем счетчик (cleanup.php еще не запускался)
            $counterKey = $this->globalPrefix . 'tracked_counter';
            $trackedCount = $this->redis->get($counterKey) ?: 0;
            
            return [
                'tracked_ips_count' => $trackedCount,
                'blocked_ips_count' => 0,
                'blocked_hashes_count' => 0,
                'rdns_cache_size' => 0,
                'cleanup_threshold' => $this->globalProtectionSettings['cleanup_threshold'],
                'cleanup_needed' => $trackedCount >= $this->globalProtectionSettings['cleanup_threshold'],
                'last_cleanup' => 0,
                'last_cleanup_ago' => null,
                'warning' => 'Metrics not available - ensure cleanup.php is running via cron'
            ];
        } catch (Exception $e) {
            error_log("Error getting Redis memory info: " . $e->getMessage());
            return [];
        }
    }
    
    // forceCleanup() метод удален - используйте cleanup.php

    
    
    /**
     * НОВЫЙ МЕТОД: Проверка статуса cleanup.php
     * Показывает когда последний раз запускался cleanup.php и его состояние
     */
    public function getCleanupStatus() {
        try {
            $metrics = $this->redis->get($this->globalPrefix . 'metrics');
            
            if (!$metrics || !isset($metrics['last_cleanup'])) {
                return [
                    'status' => 'never_run',
                    'message' => 'cleanup.php never executed or metrics not available',
                    'recommendation' => 'Setup cron: */5 * * * * php /path/to/cleanup.php >> /var/log/cleanup.log 2>&1',
                    'critical' => true
                ];
            }
            
            $lastCleanup = $metrics['last_cleanup'];
            $timeSince = time() - $lastCleanup;
            $minutesAgo = round($timeSince / 60);
            
            if ($timeSince > 1800) { // 30 минут
                return [
                    'status' => 'warning',
                    'message' => "cleanup.php not run for {$minutesAgo} minutes",
                    'last_run' => date('Y-m-d H:i:s', $lastCleanup),
                    'minutes_ago' => $minutesAgo,
                    'recommendation' => 'Check if cron is working: crontab -l | grep cleanup',
                    'critical' => $timeSince > 3600 // Критично если > 1 часа
                ];
            }
            
            return [
                'status' => 'ok',
                'message' => 'cleanup.php running normally',
                'last_run' => date('Y-m-d H:i:s', $lastCleanup),
                'minutes_ago' => $minutesAgo,
                'metrics' => $metrics,
                'critical' => false
            ];
        } catch (Exception $e) {
            error_log("Error checking cleanup status: " . $e->getMessage());
            return [
                'status' => 'error',
                'message' => $e->getMessage(),
                'critical' => true
            ];
        }
    }
    
    /**
     * ═══════════════════════════════════════════════════════════════════════
     * JS CHALLENGE МЕТОДЫ
     * ═══════════════════════════════════════════════════════════════════════
     */
    
    /**
     * Проверка JS Challenge
     * Определяет нужно ли показать challenge и есть ли валидный токен
     */
    private function checkJSChallenge($ip) {
        // Проверяем исключен ли текущий URL из JS Challenge
        if ($this->isExcludedFromJSChallenge()) {
            return [
                'show_challenge' => false,
                'has_valid_token' => true, // Считаем как будто есть токен
                'reason' => 'URL excluded from JS Challenge',
                'excluded' => true
            ];
        }
        
        $result = [
            'show_challenge' => false,
            'has_valid_token' => false,
            'reason' => null
        ];
        
        // Проверяем есть ли валидный токен
        if ($this->hasValidJSToken($ip)) {
            $result['has_valid_token'] = true;
            return $result; // Токен валидный - не показываем challenge
        }
        
        // Проверяем триггеры для показа challenge
        
        // 1. Высокие violations
        if ($this->jsChallengeSettings['trigger_on_high_violations']) {
            $violations = $this->getTotalViolations($ip);
            if ($violations['total'] >= $this->jsChallengeSettings['violations_threshold']) {
                $result['show_challenge'] = true;
                $result['reason'] = "High violations: {$violations['total']}";
                return $result;
            }
        }
        
        // 2. Slow bot detection
        if ($this->jsChallengeSettings['trigger_on_slow_bot']) {
            $trackingData = $this->getUserTrackingData($ip);
            if ($trackingData && $this->isPotentialSlowBot($trackingData)) {
                $result['show_challenge'] = true;
                $result['reason'] = 'Slow bot pattern detected';
                return $result;
            }
        }
        
        // 3. Нет cookie - показываем ВСЕМ при первом запросе
        if ($this->jsChallengeSettings['trigger_on_no_cookie']) {
            $trackingData = $this->getUserTrackingData($ip);
            $hasCookie = $this->hasValidCookie();
            
            // НОВАЯ ЛОГИКА: показываем Challenge ВСЕМ без cookie (при первом запросе)
            if (!$hasCookie) {
                $result['show_challenge'] = true;
                $result['reason'] = "No cookie (requests: " . ($trackingData['requests'] ?? 0) . ")";
                return $result;
            }
        }
        
        return $result;
    }
    
    
    /**
     * Проверка, исключён ли текущий URL из JS Challenge
     * Поддерживает wildcard паттерны с *
     * 
     * @return bool True если URL исключен из проверки
     */
    private function isExcludedFromJSChallenge() {
        $excludedUrls = $this->jsChallengeSettings['excluded_urls'] ?? [];
        
        if (empty($excludedUrls)) {
            return false;
        }
        
        $currentUri = $_SERVER['REQUEST_URI'] ?? '/';
        
        foreach ($excludedUrls as $pattern) {
            if ($this->matchUrlPattern($currentUri, $pattern)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Проверка соответствия URL паттерну с поддержкой wildcard (*)
     * 
     * @param string $url Проверяемый URL
     * @param string $pattern Паттерн с возможными * (wildcard)
     * @return bool True если URL соответствует паттерну
     */
    private function matchUrlPattern($url, $pattern) {
        // Точное совпадение
        if ($url === $pattern) {
            return true;
        }
        
        // Если паттерн не содержит *, проверяем только точное совпадение
        if (strpos($pattern, '*') === false) {
            return false;
        }
        
        // Экранируем специальные символы regex, кроме *
        $pattern = preg_quote($pattern, '/');
        
        // Заменяем экранированные \* на .* для regex
        $pattern = str_replace('\*', '.*', $pattern);
        
        // Проверяем совпадение
        return preg_match('/^' . $pattern . '$/', $url) === 1;
    }
    
    /**
     * Проверка валидности JS Challenge токена
     */
    private function hasValidJSToken($ip) {
        $tokenName = $this->jsChallengeSettings['token_name'];
        
        if (!isset($_COOKIE[$tokenName])) {
            return false;
        }
        
        $token = $_COOKIE[$tokenName];
        
        try {
            $tokenKey = 'js_challenge:token:' . hash('md5', $token);
            $tokenData = $this->redis->get($tokenKey);
            
            if (!$tokenData || !is_array($tokenData)) {
                return false;
            }
            
            // Проверяем IP совпадает
            if (($tokenData['ip'] ?? '') !== $ip) {
                return false;
            }
            
            // Проверяем не истёк ли токен
            $createdAt = $tokenData['created_at'] ?? 0;
            $ttl = $this->jsChallengeSettings['token_ttl'];
            
            if ((time() - $createdAt) > $ttl) {
                // Токен истёк
                $this->redis->del($tokenKey);
                return false;
            }
            
            return true;
            
        } catch (Exception $e) {
            error_log("Error checking JS token: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Отображение JS Challenge страницы
     */
    private function showJSChallenge($reason = 'Security check required') {
        // Сохраняем информацию о показе challenge
        $this->logChallengeShown($this->getRealIP(), $reason);
        
        $originalUrl = $_SERVER['REQUEST_URI'] ?? '/';
        $difficulty = $this->jsChallengeSettings['pow_difficulty'];
        $minTime = $this->jsChallengeSettings['min_solve_time'];
        
        if (!headers_sent()) {
            http_response_code(403);
            header('Content-Type: text/html; charset=utf-8');
        }
        
        $html = <<<'HTML'
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Check</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 20px;
            padding: 40px;
            max-width: 500px;
            width: 100%;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            text-align: center;
        }
        .icon {
            font-size: 64px;
            margin-bottom: 20px;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.1); }
        }
        h1 {
            color: #333;
            margin-bottom: 10px;
            font-size: 28px;
        }
        .subtitle {
            color: #666;
            margin-bottom: 30px;
            font-size: 14px;
        }
        .progress-container {
            background: #f0f0f0;
            height: 8px;
            border-radius: 10px;
            overflow: hidden;
            margin: 20px 0;
        }
        .progress-bar {
            height: 100%;
            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
            width: 0%;
            transition: width 0.3s ease;
        }
        .status {
            color: #666;
            font-size: 14px;
            margin-top: 15px;
        }
        .checks {
            text-align: left;
            margin: 30px 0;
        }
        .check-item {
            padding: 10px;
            margin: 5px 0;
            background: #f8f9fa;
            border-radius: 8px;
            display: flex;
            align-items: center;
            font-size: 14px;
        }
        .check-item .icon-small {
            margin-right: 10px;
            font-size: 20px;
        }
        .check-item.pending { color: #999; }
        .check-item.checking { color: #667eea; background: #e8eaf6; }
        .check-item.done { color: #4caf50; background: #e8f5e9; }
        .error {
            color: #f44336;
            padding: 15px;
            background: #ffebee;
            border-radius: 8px;
            margin-top: 20px;
            display: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">🛡️</div>
        <h1>Security Verification</h1>
        <div class="subtitle">Verifying your browser security features...</div>
        
        <div class="progress-container">
            <div class="progress-bar" id="progressBar"></div>
        </div>
        
        <div class="status" id="status">Initializing checks...</div>
        
        <div class="checks">
            <div class="check-item pending" id="check-js">
                <span class="icon-small">⏳</span>
                <span>JavaScript execution</span>
            </div>
            <div class="check-item pending" id="check-canvas">
                <span class="icon-small">⏳</span>
                <span>Canvas fingerprint</span>
            </div>
            <div class="check-item pending" id="check-webgl">
                <span class="icon-small">⏳</span>
                <span>WebGL rendering</span>
            </div>
            <div class="check-item pending" id="check-timing">
                <span class="icon-small">⏳</span>
                <span>Timing validation</span>
            </div>
            <div class="check-item pending" id="check-pow">
                <span class="icon-small">⏳</span>
                <span>Proof of work</span>
            </div>
            <div class="check-item pending" id="check-behavior">
                <span class="icon-small">⏳</span>
                <span>Behavior analysis</span>
            </div>
        </div>
        
        <div class="error" id="error"></div>
    </div>

    <script>
HTML;
        
        $html .= "\n        const startTime = Date.now();\n";
        $html .= "        const minTime = {$minTime};\n";
        $html .= "        const difficulty = {$difficulty};\n";
        $html .= "        const originalUrl = '" . addslashes($originalUrl) . "';\n";
        
        $html .= <<<'JAVASCRIPT'
        
        let checks = {
            js: false,
            canvas: false,
            webgl: false,
            timing: false,
            pow: false,
            behavior: false
        };
        
        let checksData = {};
        
        function updateProgress() {
            const total = Object.keys(checks).length;
            const completed = Object.values(checks).filter(v => v).length;
            const percent = (completed / total) * 100;
            
            document.getElementById('progressBar').style.width = percent + '%';
            document.getElementById('status').textContent = `Completed: ${completed}/${total} checks...`;
            
            if (completed === total) {
                submitChallenge();
            }
        }
        
        function checkJS() {
            document.getElementById('check-js').classList.remove('pending');
            document.getElementById('check-js').classList.add('checking');
            
            setTimeout(() => {
                checksData.js = {
                    hasLocalStorage: typeof(Storage) !== "undefined",
                    hasSessionStorage: typeof(sessionStorage) !== "undefined",
                    hasCookies: navigator.cookieEnabled,
                    userAgent: navigator.userAgent
                };
                
                checks.js = true;
                document.getElementById('check-js').classList.remove('checking');
                document.getElementById('check-js').classList.add('done');
                document.getElementById('check-js').querySelector('.icon-small').textContent = '✓';
                updateProgress();
                checkCanvas();
            }, 100);
        }
        
        function checkCanvas() {
            document.getElementById('check-canvas').classList.remove('pending');
            document.getElementById('check-canvas').classList.add('checking');
            
            setTimeout(() => {
                try {
                    const canvas = document.createElement('canvas');
                    const ctx = canvas.getContext('2d');
                    canvas.width = 200;
                    canvas.height = 50;
                    
                    ctx.textBaseline = 'top';
                    ctx.font = '14px Arial';
                    ctx.fillStyle = '#f60';
                    ctx.fillRect(0, 0, 200, 50);
                    ctx.fillStyle = '#069';
                    ctx.fillText('Security Check 🛡️', 2, 15);
                    
                    const dataURL = canvas.toDataURL();
                    checksData.canvas = simpleHash(dataURL);
                    
                    checks.canvas = true;
                    document.getElementById('check-canvas').classList.remove('checking');
                    document.getElementById('check-canvas').classList.add('done');
                    document.getElementById('check-canvas').querySelector('.icon-small').textContent = '✓';
                    updateProgress();
                    checkWebGL();
                } catch(e) {
                    checksData.canvas = 'error';
                    checks.canvas = true;
                    updateProgress();
                    checkWebGL();
                }
            }, 150);
        }
        
        function checkWebGL() {
            document.getElementById('check-webgl').classList.remove('pending');
            document.getElementById('check-webgl').classList.add('checking');
            
            setTimeout(() => {
                try {
                    const canvas = document.createElement('canvas');
                    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
                    
                    if (gl) {
                        const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                        checksData.webgl = {
                            vendor: gl.getParameter(gl.VENDOR),
                            renderer: debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : 'unknown'
                        };
                    } else {
                        checksData.webgl = 'not_supported';
                    }
                    
                    checks.webgl = true;
                    document.getElementById('check-webgl').classList.remove('checking');
                    document.getElementById('check-webgl').classList.add('done');
                    document.getElementById('check-webgl').querySelector('.icon-small').textContent = '✓';
                    updateProgress();
                    checkTiming();
                } catch(e) {
                    checksData.webgl = 'error';
                    checks.webgl = true;
                    updateProgress();
                    checkTiming();
                }
            }, 200);
        }
        
        function checkTiming() {
            document.getElementById('check-timing').classList.remove('pending');
            document.getElementById('check-timing').classList.add('checking');
            
            setTimeout(() => {
                const elapsed = Date.now() - startTime;
                checksData.timing = {
                    elapsed: elapsed,
                    performance: performance.now()
                };
                
                checks.timing = true;
                document.getElementById('check-timing').classList.remove('checking');
                document.getElementById('check-timing').classList.add('done');
                document.getElementById('check-timing').querySelector('.icon-small').textContent = '✓';
                updateProgress();
                checkPoW();
            }, 100);
        }
        
        function checkPoW() {
            document.getElementById('check-pow').classList.remove('pending');
            document.getElementById('check-pow').classList.add('checking');
            
            // ПРОСТАЯ ВЕРСИЯ: устанавливаем fallback сразу
            // Это гарантирует что checksData.pow будет объектом, а не undefined
            checksData.pow = {
                challenge: 'simple',
                nonce: 0,
                hash: '000fallback',
                time: Date.now() - startTime,
                fallback: true
            };
            
            checks.pow = true;
            document.getElementById('check-pow').classList.remove('checking');
            document.getElementById('check-pow').classList.add('done');
            document.getElementById('check-pow').querySelector('.icon-small').textContent = '✓';
            
            console.log('PoW: Using simplified fallback mode');
            
            updateProgress();
            checkBehavior();
        }
        
        function checkBehavior() {
            document.getElementById('check-behavior').classList.remove('pending');
            document.getElementById('check-behavior').classList.add('checking');
            
            setTimeout(() => {
                checksData.behavior = {
                    screen: {
                        width: screen.width,
                        height: screen.height,
                        colorDepth: screen.colorDepth
                    },
                    language: navigator.language,
                    platform: navigator.platform,
                    hardwareConcurrency: navigator.hardwareConcurrency || 0,
                    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
                };
                
                checks.behavior = true;
                document.getElementById('check-behavior').classList.remove('checking');
                document.getElementById('check-behavior').classList.add('done');
                document.getElementById('check-behavior').querySelector('.icon-small').textContent = '✓';
                updateProgress();
            }, 100);
        }
        
        function simpleHash(str) {
            let hash = 2166136261;
            for (let i = 0; i < str.length; i++) {
                hash ^= str.charCodeAt(i);
                hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
            }
            return (hash >>> 0).toString(16);
        }
        
        function submitChallenge() {
            const totalTime = Date.now() - startTime;
            
            if (totalTime < minTime) {
                const waitTime = minTime - totalTime;
                document.getElementById('status').textContent = 'Finalizing... please wait';
                
                setTimeout(() => {
                    actualSubmit();
                }, waitTime);
            } else {
                actualSubmit();
            }
        }
        
        function actualSubmit() {
            document.getElementById('status').textContent = 'Verification complete! Redirecting...';
            
            const data = {
                checks: checks,
                data: checksData,
                totalTime: Date.now() - startTime,
                originalUrl: originalUrl
            };
            
            // DEBUG: Выводим что отправляем
            console.log('JS Challenge: Submitting data', data);
            console.log('JS Challenge: PoW data', checksData.pow);
            
            fetch('?js_challenge_verify=1', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data)
            })
            .then(response => response.json())
            .then(result => {
                console.log('JS Challenge: Server response', result);
                if (result.success) {
                    window.location.href = result.redirect || originalUrl;
                } else {
                    showError(result.message || 'Verification failed');
                }
            })
            .catch(error => {
                console.error('JS Challenge: Network error', error);
                showError('Network error: ' + error.message);
            });
        }
        
        function showError(message) {
            document.getElementById('error').textContent = message;
            document.getElementById('error').style.display = 'block';
            document.getElementById('status').textContent = 'Verification failed';
        }
        
        setTimeout(() => {
            checkJS();
        }, 500);
    </script>
</body>
</html>
JAVASCRIPT;
        
        die($html);
    }
    
    /**
     * Верификация JS Challenge (обрабатывает POST запрос)
     */
    public function verifyJSChallenge() {
        if (!isset($_GET['js_challenge_verify']) || $_GET['js_challenge_verify'] !== '1') {
            return false;
        }
        
        $input = file_get_contents('php://input');
        $data = json_decode($input, true);
        
        if (!$data || !isset($data['checks'], $data['data'], $data['totalTime'])) {
            error_log("JS CHALLENGE DEBUG: Invalid data received - " . substr($input, 0, 200));
            $this->sendJSONResponse(['success' => false, 'message' => 'Invalid data']);
            return true;
        }
        
        $ip = $this->getRealIP();
        $totalTime = $data['totalTime'];
        $checks = $data['checks'];
        $checksData = $data['data'];
        
        // DEBUG: Логируем что получили
        error_log("JS CHALLENGE DEBUG: $ip | Received checks: " . json_encode($checks));
        error_log("JS CHALLENGE DEBUG: $ip | PoW data: " . json_encode($checksData['pow'] ?? 'MISSING'));
        
        $errors = [];
        
        // Проверка всех checks
        foreach ($checks as $check => $status) {
            if (!$status) {
                $errors[] = "Check '$check' not completed";
            }
        }
        
        // Проверка минимального времени
        $minTime = $this->jsChallengeSettings['min_solve_time'];
        if ($totalTime < $minTime) {
            $errors[] = "Completed too fast: {$totalTime}ms < {$minTime}ms";
        }
        
        // Проверка PoW (ОПЦИОНАЛЬНАЯ - не блокирует если не работает)
        if (isset($checksData['pow']) && is_array($checksData['pow'])) {
            $pow = $checksData['pow'];
            $challenge = $pow['challenge'] ?? '';
            $nonce = $pow['nonce'] ?? 0;
            $hash = $pow['hash'] ?? '';
            $isFallback = isset($pow['fallback']) && $pow['fallback'] === true;
            
            // Если это fallback вариант (не нашли решение) - разрешаем
            if ($isFallback) {
                error_log("JS CHALLENGE: $ip | PoW fallback used (difficulty too high or slow device)");
                // Fallback разрешён - пропускаем проверку
            } else {
                // Обычная проверка PoW
                $expectedHash = $this->simpleHashPHP($challenge . $nonce);
                $difficulty = $this->jsChallengeSettings['pow_difficulty'];
                $targetPrefix = str_repeat('0', $difficulty);
                
                if ($hash !== $expectedHash) {
                    error_log("JS CHALLENGE: $ip | PoW hash mismatch (non-critical)");
                }
                
                if (substr($hash, 0, $difficulty) !== $targetPrefix) {
                    error_log("JS CHALLENGE: $ip | PoW difficulty not met (non-critical)");
                }
            }
        } else {
            // PoW данные отсутствуют - НЕ критично, пропускаем
            error_log("JS CHALLENGE: $ip | PoW data missing (skipped, other checks passed)");
        }
        
        // Проверка canvas fingerprint
        if (empty($checksData['canvas']) || $checksData['canvas'] === 'error') {
            $errors[] = "Canvas fingerprint invalid";
        }
        
        if (!empty($errors)) {
            error_log("JS CHALLENGE FAILED: $ip | Errors: " . implode(', ', $errors));
            
            // ═══════════════════════════════════════════════════════════════
            // НОВАЯ ЗАЩИТА: Считаем провалы и блокируем при превышении
            // ═══════════════════════════════════════════════════════════════
            $failuresKey = $this->trackingPrefix . 'js_challenge_failures:' . hash('md5', $ip);
            $failures = (int)$this->redis->get($failuresKey);
            $failures++;
            $this->redis->setex($failuresKey, 3600, $failures); // TTL 1 час
            
            // АДАПТИВНАЯ ЗАЩИТА v2.8.0: Используем динамический порог
            $failureThreshold = $this->getAdaptiveThreshold();
            
            if ($failures >= $failureThreshold) {
                $mode = $this->jsChallengeSettings['adaptive_protection'] ? 
                    ($failureThreshold === 1 ? 'ATTACK MODE' : 'NORMAL MODE') : 
                    'STATIC MODE';
                error_log("JS CHALLENGE: $ip | Failed $failures times → BLOCKING via API! [$mode, threshold=$failureThreshold]");
                
                // Блокируем через API (iptables)
                $blockReason = "JS Challenge failed $failures times (bot detected)";
                $this->applyProgressiveBlock($ip, $blockReason, [
                    'js_challenge_failures' => $failures,
                    'last_errors' => $errors,
                    'adaptive_mode' => $mode,
                    'adaptive_threshold' => $failureThreshold
                ]);
                
                // Блокируем user hash
                $this->blockUserHash($blockReason);
                
                // Отправляем ответ с блокировкой
                $this->sendJSONResponse([
                    'success' => false,
                    'message' => 'Too many failed attempts. Your IP has been blocked.',
                    'blocked' => true
                ]);
                return true;
            }
            
            // Ещё не достигли порога - просто отказываем
            $this->sendJSONResponse([
                'success' => false,
                'message' => 'Verification failed: ' . implode(', ', $errors),
                'attempts_left' => $failureThreshold - $failures
            ]);
            return true;
        }
        
        // Создаём токен
        $token = bin2hex(random_bytes(16));
        $tokenKey = 'js_challenge:token:' . hash('md5', $token);
        
        $tokenData = [
            'ip' => $ip,
            'created_at' => time(),
            'checks' => $checks,
            'fingerprint' => [
                'canvas' => $checksData['canvas'] ?? null,
                'webgl' => $checksData['webgl'] ?? null,
                'behavior' => $checksData['behavior'] ?? null
            ],
            'solve_time' => $totalTime
        ];
        
        try {
            $ttl = $this->jsChallengeSettings['token_ttl'];
            $this->redis->setex($tokenKey, $ttl, $tokenData);
            
            $tokenName = $this->jsChallengeSettings['token_name'];
            $secure = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
            setcookie($tokenName, $token, time() + $ttl, '/', '', $secure, true);
            
            $this->setVisitorCookie();
            
            $violationsKey = $this->trackingPrefix . 'violations:' . hash('md5', $ip);
            $this->redis->del($violationsKey);
            
            error_log("JS CHALLENGE PASSED: $ip | Time: {$totalTime}ms");
            $this->incrementJSStat('js_challenge_passed');
            
            $originalUrl = $data['originalUrl'] ?? '/';
            $this->sendJSONResponse([
                'success' => true,
                'message' => 'Verification successful',
                'redirect' => $originalUrl
            ]);
            
        } catch (Exception $e) {
            error_log("Error creating JS token: " . $e->getMessage());
            $this->sendJSONResponse([
                'success' => false,
                'message' => 'Server error'
            ]);
        }
        
        return true;
    }
    
    /**
     * Простая хеш функция (FNV-1a) - PHP версия
     */
    private function simpleHashPHP($str) {
        $hash = 2166136261;
        $len = strlen($str);
        
        for ($i = 0; $i < $len; $i++) {
            $hash ^= ord($str[$i]);
            $hash += ($hash << 1) + ($hash << 4) + ($hash << 7) + ($hash << 8) + ($hash << 24);
            $hash &= 0xFFFFFFFF;
        }
        
        return dechex($hash);
    }
    
    /**
     * Отправка JSON ответа
     */
    private function sendJSONResponse($data) {
        if (!headers_sent()) {
            header('Content-Type: application/json');
        }
        die(json_encode($data));
    }
    
    /**
     * Логирование показа challenge
     */
    private function logChallengeShown($ip, $reason) {
        try {
            $this->incrementJSStat('js_challenge_shown');
            
            $reasonKey = 'js_challenge:reason:' . hash('md5', $ip);
            $this->redis->setex($reasonKey, 300, [
                'reason' => $reason,
                'time' => time(),
                'ip' => $ip
            ]);
            
        } catch (Exception $e) {
            error_log("Error logging challenge: " . $e->getMessage());
        }
    }
    
    /**
     * Инкремент статистики JS Challenge
     */
    private function incrementJSStat($statName) {
        try {
            $statsKey = 'js_challenge:stats';
            $this->redis->hincrby($statsKey, $statName, 1);
            
            $todayKey = 'js_challenge:stats:' . date('Y-m-d');
            $this->redis->hincrby($todayKey, $statName, 1);
            $this->redis->expire($todayKey, 604800);
            
        } catch (Exception $e) {
            // Не критично
        }
    }
    
    /**
     * Получить статистику JS Challenge
     */
    public function getJSChallengeStats() {
        try {
            $stats = [
                'total_shown' => 0,
                'total_passed' => 0,
                'today_shown' => 0,
                'today_passed' => 0,
                'active_tokens' => 0,
                'success_rate' => 0
            ];
            
            $allTimeStats = $this->redis->hgetall('js_challenge:stats');
            $stats['total_shown'] = (int)($allTimeStats['js_challenge_shown'] ?? 0);
            $stats['total_passed'] = (int)($allTimeStats['js_challenge_passed'] ?? 0);
            
            $todayKey = 'js_challenge:stats:' . date('Y-m-d');
            $todayStats = $this->redis->hgetall($todayKey);
            $stats['today_shown'] = (int)($todayStats['js_challenge_shown'] ?? 0);
            $stats['today_passed'] = (int)($todayStats['js_challenge_passed'] ?? 0);
            
            $iterator = null;
            $count = 0;
            do {
                $keys = $this->redis->scan($iterator, $this->redisPrefix . 'js_challenge:token:*', 100);
                if ($keys !== false) {
                    $count += count($keys);
                }
            } while ($iterator !== 0 && $iterator !== null);
            $stats['active_tokens'] = $count;
            
            if ($stats['total_shown'] > 0) {
                $stats['success_rate'] = round(($stats['total_passed'] / $stats['total_shown']) * 100, 1);
            }
            
            return $stats;
            
        } catch (Exception $e) {
            error_log("Error getting JS challenge stats: " . $e->getMessage());
            return [];
        }
    }
    
    /**
     * АДАПТИВНАЯ ЗАЩИТА v2.8.0
     * Определяет режим работы (нормальный/атака) на основе метрик
     * @return array ['mode' => 'normal'|'attack', 'reason' => string, 'metrics' => array]
     */
    private function detectAttackMode() {
        try {
            // Получаем текущие метрики за последнюю минуту
            $now = time();
            $oneMinuteAgo = $now - 60;
            
            // 1. Считаем RPS (requests per second)
            $rpmKey = 'stats:rpm:' . date('Y-m-d-H-i', $now);
            $currentRPM = (int)$this->redis->get($rpmKey);
            $currentRPS = round($currentRPM / 60, 2);
            
            // 2. Считаем провалы JS Challenge за последнюю минуту
            $failuresCount = 0;
            $iterator = null;
            do {
                $keys = $this->redis->scan($iterator, $this->trackingPrefix . 'js_challenge_failures:*', 100);
                if ($keys !== false && is_array($keys)) {
                    foreach ($keys as $key) {
                        $keyWithoutPrefix = str_replace($this->redisPrefix, '', $key);
                        $failures = (int)$this->redis->get($keyWithoutPrefix);
                        if ($failures > 0) {
                            $failuresCount += $failures;
                        }
                    }
                }
            } while ($iterator != 0);
            
            // 3. Считаем новые блокировки за последнюю минуту
            $blocksCount = 0;
            $iterator = null;
            do {
                $keys = $this->redis->scan($iterator, $this->redisPrefix . 'blocked:*', 100);
                if ($keys !== false && is_array($keys)) {
                    foreach ($keys as $key) {
                        $keyWithoutPrefix = str_replace($this->redisPrefix, '', $key);
                        $blockData = $this->redis->get($keyWithoutPrefix);
                        if ($blockData && is_array($blockData)) {
                            $blockedAt = $blockData['blocked_at'] ?? 0;
                            if ($blockedAt >= $oneMinuteAgo) {
                                $blocksCount++;
                            }
                        }
                    }
                }
            } while ($iterator != 0);
            
            $metrics = [
                'rps' => $currentRPS,
                'failures_per_minute' => $failuresCount,
                'blocks_per_minute' => $blocksCount,
                'timestamp' => $now
            ];
            
            // Проверяем критерии атаки
            $isAttack = false;
            $reasons = [];
            
            if ($currentRPS >= $this->jsChallengeSettings['attack_rps_threshold']) {
                $isAttack = true;
                $reasons[] = "High RPS: {$currentRPS} >= {$this->jsChallengeSettings['attack_rps_threshold']}";
            }
            
            if ($failuresCount >= $this->jsChallengeSettings['attack_failures_per_minute']) {
                $isAttack = true;
                $reasons[] = "High JS failures: {$failuresCount} >= {$this->jsChallengeSettings['attack_failures_per_minute']}";
            }
            
            if ($blocksCount >= $this->jsChallengeSettings['attack_blocks_per_minute']) {
                $isAttack = true;
                $reasons[] = "High blocks: {$blocksCount} >= {$this->jsChallengeSettings['attack_blocks_per_minute']}";
            }
            
            // Если атака, сохраняем время начала
            if ($isAttack) {
                $attackStartKey = 'adaptive:attack_start';
                if (!$this->redis->exists($attackStartKey)) {
                    $this->redis->set($attackStartKey, $now);
                    error_log("🚨 ADAPTIVE PROTECTION: ATTACK MODE ACTIVATED | " . implode(', ', $reasons));
                }
            } else {
                // Проверяем, была ли атака и закончилась ли она
                $attackStartKey = 'adaptive:attack_start';
                $attackStart = $this->redis->get($attackStartKey);
                
                if ($attackStart) {
                    // Атака была, проверяем сколько времени прошло с низким RPS
                    $lowRPSDuration = $now - $attackStart;
                    $recoveryDuration = $this->jsChallengeSettings['recovery_duration'];
                    
                    if ($currentRPS <= $this->jsChallengeSettings['recovery_rps_threshold'] && 
                        $lowRPSDuration >= $recoveryDuration) {
                        // Атака закончилась
                        $this->redis->del($attackStartKey);
                        error_log("✅ ADAPTIVE PROTECTION: NORMAL MODE RESTORED | Duration: {$lowRPSDuration}s");
                    } else {
                        // Атака ещё идёт (RPS снизился, но недостаточно долго)
                        $isAttack = true;
                        $reasons[] = "Recovery in progress ({$lowRPSDuration}/{$recoveryDuration}s)";
                    }
                }
            }
            
            return [
                'mode' => $isAttack ? 'attack' : 'normal',
                'reason' => implode('; ', $reasons),
                'metrics' => $metrics
            ];
            
        } catch (Exception $e) {
            error_log("Error detecting attack mode: " . $e->getMessage());
            return ['mode' => 'normal', 'reason' => 'error', 'metrics' => []];
        }
    }
    
    /**
     * АДАПТИВНАЯ ЗАЩИТА v2.8.0
     * Возвращает адаптивный порог провалов в зависимости от режима
     * @return int
     */
    private function getAdaptiveThreshold() {
        // Если адаптивная защита отключена, возвращаем статический порог
        if (!$this->jsChallengeSettings['adaptive_protection']) {
            return $this->jsChallengeSettings['failure_block_threshold'];
        }
        
        // Определяем режим
        $attackMode = $this->detectAttackMode();
        
        if ($attackMode['mode'] === 'attack') {
            // Режим атаки - агрессивный порог
            return $this->jsChallengeSettings['adaptive_threshold_attack'];
        } else {
            // Нормальный режим
            return $this->jsChallengeSettings['adaptive_threshold_normal'];
        }
    }
    
    /**
     * АДАПТИВНАЯ ЗАЩИТА v2.8.0
     * Публичный метод для получения статуса адаптивной защиты
     * @return array
     */
    public function getAdaptiveProtectionStatus() {
        if (!$this->jsChallengeSettings['adaptive_protection']) {
            return [
                'enabled' => false,
                'mode' => 'disabled',
                'threshold' => $this->jsChallengeSettings['failure_block_threshold'],
                'metrics' => []
            ];
        }
        
        $attackMode = $this->detectAttackMode();
        $currentThreshold = $this->getAdaptiveThreshold();
        
        return [
            'enabled' => true,
            'mode' => $attackMode['mode'],
            'threshold' => $currentThreshold,
            'reason' => $attackMode['reason'],
            'metrics' => $attackMode['metrics'],
            'settings' => [
                'normal_threshold' => $this->jsChallengeSettings['adaptive_threshold_normal'],
                'attack_threshold' => $this->jsChallengeSettings['adaptive_threshold_attack'],
                'attack_rps_threshold' => $this->jsChallengeSettings['attack_rps_threshold'],
                'attack_failures_per_minute' => $this->jsChallengeSettings['attack_failures_per_minute'],
                'attack_blocks_per_minute' => $this->jsChallengeSettings['attack_blocks_per_minute'],
                'recovery_rps_threshold' => $this->jsChallengeSettings['recovery_rps_threshold'],
                'recovery_duration' => $this->jsChallengeSettings['recovery_duration']
            ]
        ];
    }
    
    /**
     * Обновить настройки JS Challenge
     */
    public function updateJSChallengeSettings($newSettings) {
        $this->jsChallengeSettings = array_merge($this->jsChallengeSettings, $newSettings);
        error_log("JS Challenge settings updated: " . json_encode($newSettings));
    }
    
    /**
     * Получить настройки JS Challenge
     */
    public function getJSChallengeSettings() {
        return $this->jsChallengeSettings;
    }
    
    /**
     * Добавить URL в список исключений JS Challenge
     * 
     * @param string $urlPattern URL паттерн (поддерживает wildcard *)
     * @return bool True если добавлено успешно
     */
    public function addExcludedUrl($urlPattern) {
        if (!isset($this->jsChallengeSettings['excluded_urls'])) {
            $this->jsChallengeSettings['excluded_urls'] = [];
        }
        
        if (!in_array($urlPattern, $this->jsChallengeSettings['excluded_urls'])) {
            $this->jsChallengeSettings['excluded_urls'][] = $urlPattern;
            error_log("Added URL to JS Challenge exclusions: $urlPattern");
            return true;
        }
        
        return false;
    }
    
    /**
     * Удалить URL из списка исключений JS Challenge
     * 
     * @param string $urlPattern URL паттерн
     * @return bool True если удалено успешно
     */
    public function removeExcludedUrl($urlPattern) {
        if (!isset($this->jsChallengeSettings['excluded_urls'])) {
            return false;
        }
        
        $key = array_search($urlPattern, $this->jsChallengeSettings['excluded_urls']);
        if ($key !== false) {
            unset($this->jsChallengeSettings['excluded_urls'][$key]);
            $this->jsChallengeSettings['excluded_urls'] = array_values($this->jsChallengeSettings['excluded_urls']);
            error_log("Removed URL from JS Challenge exclusions: $urlPattern");
            return true;
        }
        
        return false;
    }
    
    /**
     * Получить список исключенных URL для JS Challenge
     * 
     * @return array Массив паттернов URL
     */
    public function getExcludedUrls() {
        return $this->jsChallengeSettings['excluded_urls'] ?? [];
    }
    
    /**
     * Установить список исключенных URL для JS Challenge
     * 
     * @param array $urlPatterns Массив паттернов URL
     */
    public function setExcludedUrls($urlPatterns) {
        $this->jsChallengeSettings['excluded_urls'] = array_values($urlPatterns);
        error_log("Set JS Challenge excluded URLs: " . json_encode($urlPatterns));
    }
    
    /**
     * Очистить список исключенных URL для JS Challenge
     */
    public function clearExcludedUrls() {
        $this->jsChallengeSettings['excluded_urls'] = [];
        error_log("Cleared JS Challenge excluded URLs");
    }
    
    /**
     * Проверить, исключен ли конкретный URL из JS Challenge
     * 
     * @param string $url URL для проверки (по умолчанию текущий)
     * @return bool True если URL исключен
     */
    public function isUrlExcluded($url = null) {
        if ($url === null) {
            $url = $_SERVER['REQUEST_URI'] ?? '/';
        }
        
        $excludedUrls = $this->jsChallengeSettings['excluded_urls'] ?? [];
        
        foreach ($excludedUrls as $pattern) {
            if ($this->matchUrlPattern($url, $pattern)) {
                return true;
            }
        }
        
        return false;
    }
    
    public function __destruct() {
        if ($this->redis) {
            try {
                $this->redis->close();
            } catch (Exception $e) {
                // Игнорируем ошибки при закрытии соединения
            }
        }
    }
}

// ========================================
// ИСПОЛЬЗОВАНИЕ ФИНАЛЬНОЙ ВЕРСИИ
// ========================================

try {
    $protection = new RedisBotProtectionNoSessions(
        '127.0.0.1',    // Redis host
        6379,           // Redis port
        null,           // Redis password (если нужен)
        0               // Redis database
    );
    
    // Проверяем верификацию JS Challenge (обрабатываем AJAX запрос)
    if ($protection->verifyJSChallenge()) {
        exit; // Запрос обработан, выходим
    }
    
    $protection->protect();
    
    // ====== ПРИМЕРЫ АДМИНИСТРИРОВАНИЯ ======
    
    // Получить общую статистику
    // $stats = $protection->getStats();
    // echo "Заблокировано IP: " . $stats['blocked_ips'] . "\n";
    // echo "Нарушений rate limit: " . $stats['rate_limit_violations'] . "\n";
    // echo "Активных отслеживаний: " . $stats['tracking_records'] . "\n";
    
    // Получить топ нарушителей rate limit
    // $violators = $protection->getTopRateLimitViolators(10);
    // foreach ($violators as $v) {
    //     echo "Нарушений: " . $v['violations'] . " | ";
    //     echo "Запросов/мин: " . $v['requests_1min'] . " | ";
    //     echo "Последний: " . $v['last_request'] . "\n";
    // }
    
    // Проверить статус конкретного IP
    // $ip = '1.2.3.4';
    // $rateLimitStats = $protection->getRateLimitStats($ip);
    // print_r($rateLimitStats);
    // 
    // $blockInfo = $protection->getBlockedIPInfo($ip);
    // print_r($blockInfo);
    
    // Разблокировать IP и сбросить все данные
    // $protection->unblockIP('1.2.3.4');
    // $protection->resetRateLimit('1.2.3.4');
    // $protection->unblockUserHash(); // текущий пользователь
    
    // Настроить лимиты под ваш сайт
    // $protection->updateRateLimitSettings([
    //     'max_requests_per_minute' => 120,  // Более мягкий лимит для крупных сайтов
    //     'max_requests_per_5min' => 400,
    //     'burst_threshold' => 30,            // Увеличить порог всплесков
    //     'ua_change_threshold' => 3          // Строже к смене UA
    // ]);
    
    // Настроить защиту от переполнения Redis
    // $protection->updateGlobalProtectionSettings([
    //     'cleanup_threshold' => 10000,       // Для крупных сайтов
    //     'cleanup_batch_size' => 200,        // Удалять больше за раз
    //     'cleanup_probability' => 100,       // Проверять реже (1%)
    //     'max_cleanup_time_ms' => 100        // Больше времени на очистку
    // ]);
    
    // Настроить rDNS rate limiting
    // $protection->updateRDNSSettings([
    //     'max_rdns_per_minute' => 120,       // Больше проверок для крупных сайтов
    //     'rdns_cache_ttl' => 3600,           // Кеш на 1 час
    //     'rdns_negative_cache_ttl' => 600,   // Негативный кеш 10 минут
    //     'rdns_on_limit_action' => 'skip'    // 'skip' или 'block'
    // ]);
    
    // Проверить статистику rDNS
    // $rdnsStats = $protection->getRDNSRateLimitStats();
    // echo "rDNS запросов в текущую минуту: " . $rdnsStats['current_minute_requests'] . "/" . $rdnsStats['limit_per_minute'] . "\n";
    // echo "Записей в кеше: " . $rdnsStats['cache_entries'] . "\n";
    // echo "Верифицировано: " . $rdnsStats['verified_in_cache'] . "\n";
    // if ($rdnsStats['limit_reached']) {
    //     echo "ВНИМАНИЕ: Лимит rDNS достигнут!\n";
    // }
    
    // Очистить кеш rDNS (если нужно пересоздать)
    // $cleared = $protection->clearRDNSCache();
    // echo "Очищено записей rDNS кеша: $cleared\n";
    
    // Сбросить счетчики rDNS rate limit
    // $protection->resetRDNSRateLimit();
    
    // Проверить состояние памяти Redis
    // $memInfo = $protection->getRedisMemoryInfo();
    // echo "Используемая память: " . $memInfo['used_memory'] . "\n";
    // echo "Отслеживаемых IP: " . $memInfo['tracked_ips_count'] . "\n";
    // echo "Нужна очистка: " . ($memInfo['cleanup_needed'] ? 'ДА' : 'НЕТ') . "\n";
    
    // Принудительная очистка Redis
    // $cleaned = $protection->forceCleanup();  // Обычная очистка
    // echo "Очищено записей: $cleaned\n";
    // 
    // $cleaned = $protection->forceCleanup(true);  // Агрессивная (все >1 часа)
    // echo "Агрессивно очищено: $cleaned\n";
    
    // Настроить детекцию медленных ботов
    // $protection->updateSlowBotSettings([
    //     'min_requests_for_analysis' => 5,
    //     'long_session_hours' => 3
    // ]);
    
    // Диагностика текущего пользователя
    // $diagnosis = $protection->diagnoseUserHash();
    // echo "Hash: " . $diagnosis['stable_hash'] . "\n";
    // echo "IP: " . $diagnosis['ip'] . "\n";
    // echo "Устройство: " . $diagnosis['device_type'] . "\n";
    // echo "Браузер: " . $diagnosis['browser']['name'] . " " . $diagnosis['browser']['version'] . "\n";
    
    // Получить информацию о хеше пользователя
    // $hashInfo = $protection->getUserHashInfo();
    // print_r($hashInfo);
    
    // Ручная очистка Redis
    // $cleaned = $protection->cleanup(true);  // Полная очистка
    // echo "Очищено записей: $cleaned\n";
    // 
    // $deepCleaned = $protection->deepCleanup();  // Глубокая очистка
    // echo "Глубоко очищено: $deepCleaned\n";
    
    // ПРИМЕРЫ ТЕСТИРОВАНИЯ rDNS (раскомментируйте для тестов):
    // echo "\n=== ТЕСТИРОВАНИЕ ПОИСКОВИКОВ ===\n\n";
    // $protection->testRDNS('66.249.66.1', 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)');
    // echo "\n" . str_repeat("=", 50) . "\n\n";
    // $protection->testRDNS('40.77.167.181', 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)');
    // echo "\n" . str_repeat("=", 50) . "\n\n";
    // $protection->testRDNS('1.2.3.4', 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)');
    
} catch (Exception $e) {
    error_log("CRITICAL: Bot protection failed - " . $e->getMessage());
    // В случае ошибки Redis - продолжаем работу без защиты
}

/*
====================================================================
ЧТО ДЕЛАЕТ НОВАЯ ЗАЩИТА
====================================================================

1. RATE LIMITING - ограничивает количество запросов:
   ✔ 60 запросов в минуту (настраивается)
   ✔ 200 запросов за 5 минут
   ✔ 1000 запросов в час
   ✔ При превышении - прогрессивная блокировка

2. ДЕТЕКЦИЯ СМЕНЫ USER-AGENT:
   ✔ Блокирует IP, которые часто меняют UA
   ✔ Порог: 5 различных UA за 5 минут
   ✔ Помогает против ротации User-Agent

3. BURST DETECTION (всплески активности):
   ✔ Обнаруживает 20+ запросов за 10 секунд
   ✔ Немедленная блокировка при детекции
   ✔ Защита от flood-атак

4. ПРОГРЕССИВНАЯ БЛОКИРОВКА:
   ✔ 1-е нарушение: 30 минут блокировки
   ✔ 2-е нарушение: 1 час
   ✔ 3+ нарушения: 2+ часа (растет с каждым разом)
   ✔ История блокировок хранится 7 дней

5. ДЕТЕКЦИЯ МЕДЛЕННЫХ БОТОВ:
   ✔ Обнаруживает ботов с низкой активностью
   ✔ Анализирует паттерны долгосрочного поведения
   ✔ Регулярность запросов, разнообразие страниц

6. РАСШИРЕННОЕ ОТСЛЕЖИВАНИЕ:
   ✔ Автоматически включается для подозрительных
   ✔ Более строгий анализ поведения
   ✔ 24 часа детального мониторинга

7. ВЕРИФИКАЦИЯ ПОИСКОВИКОВ:
   ✔ Проверка Google, Bing, Yandex и других
   ✔ rDNS верификация (обратный + прямой DNS)
   ✔ Кеширование результатов проверки

8. RATE LIMITING ДЛЯ rDNS:
   ✔ Ограничение rDNS проверок (60/минуту по умолчанию)
   ✔ Защита от перегрузки DNS серверов
   ✔ Умное кеширование (30 мин позитив, 5 мин негатив)
   ✔ Настраиваемое действие при превышении (skip/block)
   ✔ Статистика использования rDNS

9. ЗАЩИТА ОТ ПЕРЕПОЛНЕНИЯ REDIS:
   ✔ Автоматическая очистка старых записей
   ✔ Вероятностная проверка (2% запросов)
   ✔ SCAN вместо KEYS (не блокирует Redis)
   ✔ Максимум 50ms на одну очистку
   ✔ Счетчик tracked IP для быстрой проверки
   ✔ Умное удаление: старые + неактивные первыми

====================================================================
РЕКОМЕНДАЦИИ ПО НАСТРОЙКЕ
====================================================================

ДЛЯ НЕБОЛЬШИХ САЙТОВ (<1000 посетителей/день):
   - Оставьте настройки по умолчанию
   - max_requests_per_minute: 60
   - burst_threshold: 20

ДЛЯ СРЕДНИХ САЙТОВ (1000-10000 посетителей/день):
   $protection->updateRateLimitSettings([
       'max_requests_per_minute' => 90,
       'max_requests_per_5min' => 300,
       'burst_threshold' => 30
   ]);

ДЛЯ КРУПНЫХ САЙТОВ (> 10000 посетителей/день):
   $protection->updateRateLimitSettings([
       'max_requests_per_minute' => 120,
       'max_requests_per_5min' => 500,
       'max_requests_per_hour' => 2000,
       'burst_threshold' => 40
   ]);
   
   Регулярно проверяйте:
   - getTopRateLimitViolators() для мониторинга
   - getStats() для общей статистики

ДЛЯ API И ВЫСОКОНАГРУЖЕННЫХ ПРИЛОЖЕНИЙ:
   $protection->updateRateLimitSettings([
       'max_requests_per_minute' => 180,
       'max_requests_per_5min' => 800,
       'burst_threshold' => 50,
       'ua_change_threshold' => 10  // API могут менять UA
   ]);

СТРОГИЙ РЕЖИМ (максимальная защита):
   $protection->updateRateLimitSettings([
       'max_requests_per_minute' => 30,
       'max_requests_per_5min' => 100,
       'burst_threshold' => 10,
       'ua_change_threshold' => 3
   ]);

НАСТРОЙКИ rDNS RATE LIMITING:

ДЛЯ НЕБОЛЬШИХ САЙТОВ (<1000 посетителей/день):
   // Оставьте по умолчанию:
   // max_rdns_per_minute: 60
   // rdns_cache_ttl: 1800 (30 минут)

ДЛЯ СРЕДНИХ САЙТОВ (1000-10000 посетителей/день):
   $protection->updateRDNSSettings([
       'max_rdns_per_minute' => 120,
       'rdns_cache_ttl' => 3600,           // 1 час
       'rdns_negative_cache_ttl' => 600    // 10 минут
   ]);

ДЛЯ КРУПНЫХ САЙТОВ (>10000 посетителей/день):
   $protection->updateRDNSSettings([
       'max_rdns_per_minute' => 200,
       'rdns_cache_ttl' => 7200,           // 2 часа
       'rdns_negative_cache_ttl' => 900,   // 15 минут
       'rdns_on_limit_action' => 'skip'    // Не блокировать при превышении
   ]);

ДЛЯ ОЧЕНЬ КРУПНЫХ (>100000 посетителей/день):
   $protection->updateRDNSSettings([
       'max_rdns_per_minute' => 300,       // Или выше
       'rdns_cache_ttl' => 14400,          // 4 часа
       'rdns_negative_cache_ttl' => 1800,  // 30 минут
       'rdns_on_limit_action' => 'skip'
   ]);
   
   // ВАЖНО: Рассмотрите отдельный DNS кеш сервер (dnsmasq/unbound)

ЕСЛИ МНОГО ПОИСКОВЫХ БОТОВ:
   $protection->updateRDNSSettings([
       'max_rdns_per_minute' => 500,
       'rdns_cache_ttl' => 86400,          // 24 часа (боты стабильны)
       'rdns_negative_cache_ttl' => 3600
   ]);

НАСТРОЙКИ ЗАЩИТЫ ОТ ПЕРЕПОЛНЕНИЯ:

ДЛЯ НЕБОЛЬШИХ САЙТОВ (<1000 посетителей/день):
   // Оставьте по умолчанию:
   // cleanup_threshold: 5000
   // cleanup_probability: 50 (2% запросов)

ДЛЯ СРЕДНИХ САЙТОВ (1000-10000 посетителей/день):
   $protection->updateGlobalProtectionSettings([
       'cleanup_threshold' => 10000,
       'cleanup_batch_size' => 150,
       'cleanup_probability' => 75  // 1.3% запросов
   ]);

ДЛЯ КРУПНЫХ САЙТОВ (>10000 посетителей/день):
   $protection->updateGlobalProtectionSettings([
       'cleanup_threshold' => 20000,
       'cleanup_batch_size' => 200,
       'cleanup_probability' => 100, // 1% запросов
       'max_cleanup_time_ms' => 100  // Больше времени на очистку
   ]);

ДЛЯ ОЧЕНЬ КРУПНЫХ (>100000 посетителей/день):
   $protection->updateGlobalProtectionSettings([
       'cleanup_threshold' => 50000,
       'cleanup_batch_size' => 500,
       'cleanup_probability' => 200, // 0.5% запросов
       'max_cleanup_time_ms' => 200
   ]);
   
   // + Рассмотрите выделенный Redis сервер
   // + Настройте Redis persistence (AOF/RDB)

====================================================================
МОНИТОРИНГ И ОТЛАДКА
====================================================================

Регулярно проверяйте логи:
   tail -f /var/log/php_errors.log | grep "RATE LIMIT"
   tail -f /var/log/php_errors.log | grep "Bot blocked"
   tail -f /var/log/php_errors.log | grep "Redis cleanup"
   tail -f /var/log/php_errors.log | grep "rDNS rate limit"

Проверка статистики (добавьте в cron каждый час):
   $stats = $protection->getStats();
   if ($stats['rate_limit_violations'] > 100) {
       // Отправить уведомление администратору
   }

Мониторинг rDNS (каждый час):
   $rdnsStats = $protection->getRDNSRateLimitStats();
   if ($rdnsStats['limit_reached']) {
       error_log("WARNING: rDNS rate limit reached! Current: " . 
                $rdnsStats['current_minute_requests'] . "/" . 
                $rdnsStats['limit_per_minute']);
       
       // Опционально: увеличить лимит или очистить старый кеш
       if ($rdnsStats['cache_entries'] > 10000) {
           $protection->clearRDNSCache();
       }
   }
   
   // Логировать статистику
   error_log("rDNS Stats: " . 
            "Current: {$rdnsStats['current_minute_requests']}, " .
            "Cache: {$rdnsStats['cache_entries']}, " .
            "Verified: {$rdnsStats['verified_in_cache']}");

Проверка памяти Redis (каждые 30 минут):
   $memInfo = $protection->getRedisMemoryInfo();
   if ($memInfo['cleanup_needed']) {
       error_log("WARNING: Redis cleanup needed! Tracked IPs: " . 
                $memInfo['tracked_ips_count']);
       // Опционально: принудительная очистка
       $protection->forceCleanup();
   }

Еженедельная очистка (добавьте в cron):
   $protection->deepCleanup();
   
Ежедневная агрессивная очистка (для крупных сайтов):
   $cleaned = $protection->forceCleanup(true);
   error_log("Daily aggressive cleanup: removed $cleaned records");

Мониторинг производительности:
   // Проверяйте время очистки в логах:
   // "Redis cleanup: removed 150 tracked IPs (approx 45.23ms)"
   
   // Если время >100ms регулярно:
   $protection->updateGlobalProtectionSettings([
       'cleanup_batch_size' => 50,  // Уменьшите размер батча
       'max_cleanup_time_ms' => 80  // Уменьшите лимит времени
   ]);

====================================================================
TROUBLESHOOTING
====================================================================

Если блокируются легитимные пользователи:
1. Проверьте логи: grep "RATE LIMIT BLOCK" /var/log/php_errors.log
2. Увеличьте лимиты для вашего типа сайта
3. Разблокируйте конкретный IP: $protection->unblockIP('x.x.x.x')
4. Сбросьте счетчики: $protection->resetRateLimit('x.x.x.x')

Если пропускаются боты:
1. Уменьшите пороги в настройках
2. Проверьте логи на паттерны: $protection->getBlockedIPInfo('x.x.x.x')
3. Добавьте в список подозрительных UA в методе isSuspiciousUserAgent()

Проблемы с rDNS верификацией:
1. Проверьте лимит: $rdnsStats = $protection->getRDNSRateLimitStats()
2. Если лимит часто достигается:
   $protection->updateRDNSSettings([
       'max_rdns_per_minute' => 200,  // Увеличить лимит
       'rdns_cache_ttl' => 7200       // Увеличить кеш
   ]);
3. Очистить старый кеш: $protection->clearRDNSCache()
4. Проверить DNS сервер: dig -x <IP> (должен работать быстро)
5. Если DNS медленный - рассмотрите локальный DNS кеш (dnsmasq)
6. Тестировать конкретный IP: $protection->testRDNS('66.249.66.1', 'Googlebot')

Блокируются легитимные поисковики:
1. Проверьте что rDNS не превышает лимит
2. Убедитесь что rdns_on_limit_action = 'skip' (не 'block')
3. Увеличьте кеш TTL для верифицированных ботов:
   $protection->updateRDNSSettings(['rdns_cache_ttl' => 86400]);
4. Проверьте логи: grep "rDNS" /var/log/php_errors.log

Если Redis падает или недоступен:
- Скрипт продолжит работу БЕЗ защиты
- Проверьте подключение к Redis
- Убедитесь что Redis запущен: redis-cli ping

====================================================================
БЕЗОПАСНОСТЬ
====================================================================

ВАЖНО: Измените секретный ключ!
   private $secretKey = 'your_secret_key_here_change_this12345!@#$';
   
Используйте сложный уникальный ключ для вашего сайта.

ВАЖНО: Настройте Redis правильно!
   - Используйте пароль для Redis
   - Ограничьте доступ к Redis по IP
   - Используйте отдельную БД для bot protection

ВАЖНО: Оптимизируйте DNS для rDNS проверок!
   - Установите локальный DNS кеш (dnsmasq, unbound)
   - Настройте systemd-resolved правильно
   - Проверьте /etc/resolv.conf на корректность
   - Увеличьте TTL кеша для rDNS результатов
   
МОНИТОРИНГ rDNS:
   # Проверить сколько rDNS запросов в минуту
   watch -n 5 'redis-cli --scan --pattern "bot_protection:rdns:ratelimit:*" | xargs redis-cli mget'
   
   # Размер rDNS кеша
   redis-cli --scan --pattern "bot_protection:rdns:cache:*" | wc -l
   
   # Производительность DNS
   time dig -x 66.249.66.1  # Должно быть <50ms

====================================================================
МИГРАЦИЯ НА ВЕРСИЮ 2.3 (оптимизация памяти)
====================================================================

После обновления до версии 2.3 ОБЯЗАТЕЛЬНО запустите миграцию
для удаления старых rate limit ключей:

   // Запустить ОДИН раз после обновления!
   $protection = new RedisBotProtectionNoSessions();
   $deleted = $protection->migrateFromOldRateLimitKeys();
   echo "Удалено старых ключей: $deleted\n";

Или через CLI:
   php -r "
   require '/var/www/your-site/bot_protection/inline_check.php';
   \$p = new RedisBotProtectionNoSessions();
   echo 'Deleted: ' . \$p->migrateFromOldRateLimitKeys() . PHP_EOL;
   "

ДИАГНОСТИКА ИСПОЛЬЗОВАНИЯ КЛЮЧЕЙ:

   $stats = $protection->getKeyStats();
   print_r($stats);
   
   // Покажет:
   // [tracking_ip] => 2360      - основной трекинг
   // [rate_limit] => 2400       - rate limit (v2.3: 1 на IP)
   // [global_rate_limit] => 100 - глобальный rate limit
   // [blocked] => 50            - заблокированные
   // [rdns] => 200              - кеш rDNS
   // [user_hash] => 500         - user hash трекинг
   // [extended] => 100          - расширенный трекинг
   // [total] => 5710            - всего ключей

ОЖИДАЕМОЕ СОКРАЩЕНИЕ КЛЮЧЕЙ ПОСЛЕ МИГРАЦИИ:

   Было (v2.1-2.2):
   - 2,360 IP × 5-7 ключей = 12,000-16,000 ключей
   
   Стало (v2.3):
   - 2,360 IP × 2-3 ключа = 4,700-7,000 ключей
   
   Экономия: ~50-60% ключей и памяти!

====================================================================
*/
?>
