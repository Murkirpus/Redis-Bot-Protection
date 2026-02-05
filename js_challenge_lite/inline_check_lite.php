<?php
/**
 * MurKir Security - Redis Bot Protection v3.8.13
 * PoW JS Challenge + Rate Limit + IP Whitelist + Custom UA Logging
 * Security hardened: IP validation, input sanitization, Open Redirect protection
 * 
 * v3.8.13: Додано Admin URL whitelist в inline JS Challenge секцію
 * v3.8.12: Додано підтримку GET/POST методів для API запитів
 */

// ВЛАСНІ USER AGENTS (пропускаються без JS Challenge)
$CUSTOM_USER_AGENTS = array(
    // Додай свої User Agents тут:
	'botprotection',
	'murkir-cleanup',
    
    // Приклади правильних паттернів:
    // 'MyCompany-Monitor/1.0',
    // 'InternalBot',
    // 'API-Client-v2',
);

// БІЛИЙ СПИСОК АДМІНСЬКИХ IP (повністю обходять захист)
$ADMIN_IP_WHITELIST = array(
	'::1',
	'127.0.0.1',
     '185.109.48.79',
	 '2a03:3f40:2:e:0:4:0:2',
	 '2a03:3f40:2:e:0:4:0:3',
);

// БІЛИЙ СПИСОК URL АДМІНКИ (пропускають Rate Limit)
$ADMIN_URL_WHITELIST_ENABLED = true;

$ADMIN_URL_WHITELIST = array(
    '/js_challenge_lite',
	'/redis-bot_protection/api',
	'/admin',
    '/engine/ajax',
    '/engine/admin',
    '/engine/inc/',
);

// НАЛАШТУВАННЯ RATE LIMIT ДЛЯ AJAX
$AJAX_SKIP_RATE_LIMIT = false;
$AJAX_RATE_LIMIT_MULTIPLIER = 3.0;

// БІЛИЙ СПИСОК IP ПОШУКОВИХ СИСТЕМ
$SEARCH_ENGINE_IP_RANGES = array(
	// GOOGLE
	'74.125.0.0/16',
	'172.217.0.0/16',
	'142.250.0.0/15',
	'66.102.0.0/20',
	'66.249.64.0/19',
    '192.178.4.0/27',
    '192.178.4.128/27',
    '192.178.4.160/27',
    '192.178.4.192/27',
    '192.178.4.32/27',
    '192.178.4.64/27',
    '192.178.4.96/27',
    '192.178.5.0/27',
    '192.178.6.0/27',
    '192.178.6.128/27',
    '192.178.6.160/27',
    '192.178.6.192/27',
    '192.178.6.224/27',
    '192.178.6.32/27',
    '192.178.6.64/27',
    '192.178.6.96/27',
    '192.178.7.0/27',
    '192.178.7.128/27',
    '192.178.7.160/27',
    '192.178.7.192/27',
    '192.178.7.224/27',
    '192.178.7.32/27',
    '192.178.7.64/27',
    '192.178.7.96/27',
    '34.100.182.96/28',
    '34.101.50.144/28',
    '34.118.254.0/28',
    '34.118.66.0/28',
    '34.126.178.96/28',
    '34.146.150.144/28',
    '34.147.110.144/28',
    '34.151.74.144/28',
    '34.152.50.64/28',
    '34.154.114.144/28',
    '34.155.98.32/28',
    '34.165.18.176/28',
    '34.175.160.64/28',
    '34.176.130.16/28',
    '34.22.85.0/27',
    '34.64.82.64/28',
    '34.65.242.112/28',
    '34.80.50.80/28',
    '34.88.194.0/28',
    '34.89.10.80/28',
    '34.89.198.80/28',
    '34.96.162.48/28',
    '35.247.243.240/28',
    '66.249.64.0/27',
    '66.249.64.128/27',
    '66.249.64.160/27',
    '66.249.64.192/27',
    '66.249.64.224/27',
    '66.249.64.32/27',
    '66.249.64.64/27',
    '66.249.64.96/27',
    '66.249.65.0/27',
    '66.249.65.128/27',
    '66.249.65.160/27',
    '66.249.65.192/27',
    '66.249.65.224/27',
    '66.249.65.32/27',
    '66.249.65.64/27',
    '66.249.65.96/27',
    '66.249.66.0/27',
    '66.249.66.128/27',
    '66.249.66.160/27',
    '66.249.66.192/27',
    '66.249.66.224/27',
    '66.249.66.32/27',
    '66.249.66.64/27',
    '66.249.66.96/27',
    '66.249.67.0/27',
    '66.249.67.32/27',
    '66.249.67.64/27',
    '66.249.68.0/27',
    '66.249.68.128/27',
    '66.249.68.160/27',
    '66.249.68.192/27',
    '66.249.68.32/27',
    '66.249.68.64/27',
    '66.249.68.96/27',
    '66.249.69.0/27',
    '66.249.69.128/27',
    '66.249.69.160/27',
    '66.249.69.192/27',
    '66.249.69.224/27',
    '66.249.69.32/27',
    '66.249.69.64/27',
    '66.249.69.96/27',
    '66.249.70.0/27',
    '66.249.70.128/27',
    '66.249.70.160/27',
    '66.249.70.192/27',
    '66.249.70.224/27',
    '66.249.70.32/27',
    '66.249.70.64/27',
    '66.249.70.96/27',
    '66.249.71.0/27',
    '66.249.71.128/27',
    '66.249.71.160/27',
    '66.249.71.192/27',
    '66.249.71.224/27',
    '66.249.71.32/27',
    '66.249.71.64/27',
    '66.249.71.96/27',
    '66.249.72.0/27',
    '66.249.72.128/27',
    '66.249.72.160/27',
    '66.249.72.192/27',
    '66.249.72.224/27',
    '66.249.72.32/27',
    '66.249.72.64/27',
    '66.249.73.0/27',
    '66.249.73.128/27',
    '66.249.73.160/27',
    '66.249.73.192/27',
    '66.249.73.224/27',
    '66.249.73.32/27',
    '66.249.73.64/27',
    '66.249.73.96/27',
    '66.249.74.0/27',
    '66.249.74.128/27',
    '66.249.74.160/27',
    '66.249.74.192/27',
    '66.249.74.224/27',
    '66.249.74.32/27',
    '66.249.74.64/27',
    '66.249.74.96/27',
    '66.249.75.0/27',
    '66.249.75.128/27',
    '66.249.75.160/27',
    '66.249.75.192/27',
    '66.249.75.224/27',
    '66.249.75.32/27',
    '66.249.75.64/27',
    '66.249.75.96/27',
    '66.249.76.0/27',
    '66.249.76.128/27',
    '66.249.76.160/27',
    '66.249.76.192/27',
    '66.249.76.224/27',
    '66.249.76.32/27',
    '66.249.76.64/27',
    '66.249.76.96/27',
    '66.249.77.0/27',
    '66.249.77.128/27',
    '66.249.77.160/27',
    '66.249.77.192/27',
    '66.249.77.224/27',
    '66.249.77.32/27',
    '66.249.77.64/27',
    '66.249.77.96/27',
    '66.249.78.0/27',
    '66.249.78.128/27',
    '66.249.78.160/27',
    '66.249.78.32/27',
    '66.249.78.64/27',
    '66.249.78.96/27',
    '66.249.79.0/27',
    '66.249.79.128/27',
    '66.249.79.160/27',
    '66.249.79.192/27',
    '66.249.79.224/27',
    '66.249.79.32/27',
    '66.249.79.64/27',
    
    // GOOGLEBOT IPv6
    '2001:4860:4801:10::/64',
    '2001:4860:4801:12::/64',
    '2001:4860:4801:13::/64',
    '2001:4860:4801:14::/64',
    '2001:4860:4801:15::/64',
    '2001:4860:4801:16::/64',
    '2001:4860:4801:17::/64',
    '2001:4860:4801:18::/64',
    '2001:4860:4801:19::/64',
    '2001:4860:4801:1a::/64',
    '2001:4860:4801:1b::/64',
    '2001:4860:4801:1c::/64',
    '2001:4860:4801:1d::/64',
    '2001:4860:4801:1e::/64',
    '2001:4860:4801:1f::/64',
    '2001:4860:4801:20::/64',
    '2001:4860:4801:21::/64',
    '2001:4860:4801:22::/64',
    '2001:4860:4801:23::/64',
    '2001:4860:4801:24::/64',
    '2001:4860:4801:25::/64',
    '2001:4860:4801:26::/64',
    '2001:4860:4801:27::/64',
    '2001:4860:4801:28::/64',
    '2001:4860:4801:29::/64',
    '2001:4860:4801:2::/64',
    '2001:4860:4801:2a::/64',
    '2001:4860:4801:2b::/64',
    '2001:4860:4801:2c::/64',
    '2001:4860:4801:2d::/64',
    '2001:4860:4801:2e::/64',
    '2001:4860:4801:2f::/64',
    '2001:4860:4801:30::/64',
    '2001:4860:4801:31::/64',
    '2001:4860:4801:32::/64',
    '2001:4860:4801:33::/64',
    '2001:4860:4801:34::/64',
    '2001:4860:4801:35::/64',
    '2001:4860:4801:36::/64',
    '2001:4860:4801:37::/64',
    '2001:4860:4801:38::/64',
    '2001:4860:4801:39::/64',
    '2001:4860:4801:3a::/64',
    '2001:4860:4801:3b::/64',
    '2001:4860:4801:3c::/64',
    '2001:4860:4801:3d::/64',
    '2001:4860:4801:3e::/64',
    '2001:4860:4801:3f::/64',
    '2001:4860:4801:40::/64',
    '2001:4860:4801:41::/64',
    '2001:4860:4801:42::/64',
    '2001:4860:4801:44::/64',
    '2001:4860:4801:45::/64',
    '2001:4860:4801:46::/64',
    '2001:4860:4801:47::/64',
    '2001:4860:4801:48::/64',
    '2001:4860:4801:49::/64',
    '2001:4860:4801:4a::/64',
    '2001:4860:4801:4b::/64',
    '2001:4860:4801:4c::/64',
    '2001:4860:4801:4d::/64',
    '2001:4860:4801:4e::/64',
    '2001:4860:4801:50::/64',
    '2001:4860:4801:51::/64',
    '2001:4860:4801:52::/64',
    '2001:4860:4801:53::/64',
    '2001:4860:4801:54::/64',
    '2001:4860:4801:55::/64',
    '2001:4860:4801:56::/64',
    '2001:4860:4801:57::/64',
    '2001:4860:4801:58::/64',
    '2001:4860:4801:59::/64',
    '2001:4860:4801:60::/64',
    '2001:4860:4801:61::/64',
    '2001:4860:4801:62::/64',
    '2001:4860:4801:63::/64',
    '2001:4860:4801:64::/64',
    '2001:4860:4801:65::/64',
    '2001:4860:4801:66::/64',
    '2001:4860:4801:67::/64',
    '2001:4860:4801:68::/64',
    '2001:4860:4801:69::/64',
    '2001:4860:4801:6a::/64',
    '2001:4860:4801:6b::/64',
    '2001:4860:4801:6c::/64',
    '2001:4860:4801:6d::/64',
    '2001:4860:4801:6e::/64',
    '2001:4860:4801:6f::/64',
    '2001:4860:4801:70::/64',
    '2001:4860:4801:71::/64',
    '2001:4860:4801:72::/64',
    '2001:4860:4801:73::/64',
    '2001:4860:4801:74::/64',
    '2001:4860:4801:75::/64',
    '2001:4860:4801:76::/64',
    '2001:4860:4801:77::/64',
    '2001:4860:4801:78::/64',
    '2001:4860:4801:79::/64',
    '2001:4860:4801:7a::/64',
    '2001:4860:4801:7b::/64',
    '2001:4860:4801:7c::/64',
    '2001:4860:4801:7d::/64',
    '2001:4860:4801:80::/64',
    '2001:4860:4801:81::/64',
    '2001:4860:4801:82::/64',
    '2001:4860:4801:83::/64',
    '2001:4860:4801:84::/64',
    '2001:4860:4801:85::/64',
    '2001:4860:4801:86::/64',
    '2001:4860:4801:87::/64',
    '2001:4860:4801:88::/64',
    '2001:4860:4801:90::/64',
    '2001:4860:4801:91::/64',
    '2001:4860:4801:92::/64',
    '2001:4860:4801:93::/64',
    '2001:4860:4801:94::/64',
    '2001:4860:4801:95::/64',
    '2001:4860:4801:96::/64',
    '2001:4860:4801:97::/64',
    '2001:4860:4801:a0::/64',
    '2001:4860:4801:a1::/64',
    '2001:4860:4801:a2::/64',
    '2001:4860:4801:a3::/64',
    '2001:4860:4801:a4::/64',
    '2001:4860:4801:a5::/64',
    '2001:4860:4801:a6::/64',
    '2001:4860:4801:a7::/64',
    '2001:4860:4801:a8::/64',
    '2001:4860:4801:a9::/64',
    '2001:4860:4801:aa::/64',
    '2001:4860:4801:ab::/64',
    '2001:4860:4801:ac::/64',
    '2001:4860:4801:ad::/64',
    '2001:4860:4801:ae::/64',
    '2001:4860:4801:b0::/64',
    '2001:4860:4801:b1::/64',
    '2001:4860:4801:b2::/64',
    '2001:4860:4801:b3::/64',
    '2001:4860:4801:b4::/64',
    '2001:4860:4801:b5::/64',
    '2001:4860:4801:c::/64',
    '2001:4860:4801:f::/64',
    // YANDEX IPv4
    '5.45.192.0/18',
    '5.255.192.0/18',
    '37.9.64.0/18',
    '37.140.128.0/18',
    '77.88.0.0/18',
    '84.201.128.0/18',
    '87.250.224.0/19',
    '90.156.176.0/22',
    '93.158.128.0/18',
    '95.108.128.0/17',
    '100.43.64.0/19',
    '130.193.32.0/19',
    '141.8.128.0/18',
    '178.154.128.0/17',
    '185.32.187.0/24',
    '199.21.96.0/22',
    '199.36.240.0/22',
    '213.180.192.0/19',
    // YANDEX IPv6
    '2a02:6b8::/32',
    // BINGBOT IPv4 - OFFICIAL (2024-01-03)
	'157.55.39.0/24',
	'207.46.13.0/24',
	'40.77.167.0/24',
	'13.66.139.0/24',
	'13.66.144.0/24',
	'52.167.144.0/24',
	'13.67.10.16/28',
	'13.69.66.240/28',
	'13.71.172.224/28',
	'139.217.52.0/28',
	'191.233.204.224/28',
	'20.36.108.32/28',
	'20.43.120.16/28',
	'40.79.131.208/28',
	'40.79.186.176/28',
	'52.231.148.0/28',
	'20.79.107.240/28',
	'51.105.67.0/28',
	'20.125.163.80/28',
	'40.77.188.0/22',
	'65.55.210.0/24',
	'199.30.24.0/23',
	'40.77.202.0/24',
	'40.77.139.0/25',
	'20.74.197.0/28',
	'20.15.133.160/27',
	'40.77.177.0/24',
	'40.77.178.0/23',
    // BING IPv6
    '2620:1ec:c::0/40',
    '2620:1ec:8f8::/46',
    '2a01:111::/32',
    // BAIDU IPv4
    '116.179.0.0/16',
    '119.63.192.0/21',
    '123.125.71.0/24',
    '180.76.0.0/16',
    '220.181.0.0/16',
    // DUCKDUCKGO IPv4
    '20.191.45.212/32',
    '40.88.21.235/32',
    '52.142.24.149/32',
    '52.142.26.175/32',
    '72.94.249.34/32',
    '72.94.249.35/32',
    // YAHOO IPv4
    '67.195.0.0/16',
    '72.30.0.0/16',
    '74.6.0.0/16',
    '98.136.0.0/14',
    // FACEBOOK IPv4
    '31.13.24.0/21',
    '31.13.64.0/18',
    '66.220.144.0/20',
    '69.63.176.0/20',
    '69.171.224.0/19',
    '157.240.0.0/16',
    '173.252.64.0/18',
    '185.60.216.0/22',
    // FACEBOOK IPv6
    '2a03:2880::/32',
    // APPLE IPv4
    '17.0.0.0/8',
    // APPLE IPv6
    '2620:149::/32',
    '2a01:b740::/32',
    // PETALBOT (HUAWEI) IPv4 - https://aspiegel.com/petalbot
    '114.119.128.0/17',          // Основной диапазон PetalBot
);

// КОНФІГУРАЦІЯ JS CHALLENGE

$_JSC_CONFIG = array(
    'enabled' => true,
    'secret_key' => 'CHANGE_THIS_SECRET_KEY_123!',  // !!! ЗМІНИ НА СВІЙ !!!
    'cookie_name' => 'mk_verified',
    'token_lifetime' => 129600,  // 36 годин (1.5 доби) - v3.8.5
    
    // PROOF OF WORK (PoW) НАЛАШТУВАННЯ - v3.8.0
    'pow_enabled' => true,             // Увімкнути PoW замість простого challenge
    'pow_difficulty' => 3,             // Кількість нулів (4 = ~1-3 сек, 5 = ~10-30 сек)
    'pow_timeout' => 60,               // Максимальний час виконання (секунди)
    'pow_style' => 'cloudflare',       // 'cloudflare' або 'smf' (стиль сторінки)
    
    // v3.8.12: РЕЖИМ РОБОТИ JS CHALLENGE
    // 'always' - завжди показувати (стара поведінка)
    // 'never'  - ніколи не показувати
    // 'auto'   - тільки при аномальній активності (рекомендовано)
    'mode' => 'auto',
);

// v3.8.12: НАЛАШТУВАННЯ АВТОМАТИЧНОГО РЕЖИМУ JS CHALLENGE
// Ці пороги визначають коли показувати Challenge в режимі 'auto'

$_JSC_AUTO_CONFIG = array(
    // Поріг запитів без cookies (новий відвідувач або бот)
    'no_cookie_threshold' => 3,        // Кількість запитів без bot_protection_uid
    'no_cookie_window' => 30,          // За скільки секунд (вікно)
    
    // Поріг швидких запитів (burst detection)
    'burst_threshold' => 5,            // Запитів за короткий період
    'burst_window' => 10,              // Секунд
    
    // Загальний rate limit для показу Challenge
    'rate_threshold' => 15,            // Запитів за хвилину для тригеру
    'rate_window' => 60,               // Секунд
    
    // Підозрілі ознаки (кожна додає "бали підозрілості")
    'check_empty_ua' => true,          // Порожній User-Agent = +2 бали
    'check_suspicious_ua' => true,     // Підозрілий UA (curl, wget, python) = +1 бал
    'check_no_referer' => false,       // Без Referer на внутрішніх сторінках = +1 бал
    'check_no_accept_language' => true, // Без Accept-Language = +1 бал
    
    // Поріг балів для показу Challenge
    'suspicion_threshold' => 2,        // При скількох балах показувати Challenge
    
    // Whitelist перших N запитів (дати шанс новим користувачам)
    'grace_requests' => 3,             // Перші N запитів пропускаємо без Challenge
    
    // Логування
    'log_triggers' => true,            // Логувати причини показу Challenge
);

// v3.8.7: НАЛАШТУВАННЯ ЗАХИСТУ ВІД HAMMER АТАК (долбіння сторінок)

$_HAMMER_PROTECTION = array(
    'enabled' => true,                    // Увімкнути захист
    
    // Challenge page (сторінка проверки)
    // Бот без кінця запитує challenge page без успішного проходження
    'challenge_threshold' => 10,          // Макс. запитів до блокування
    'challenge_window' => 60,             // Часове вікно (секунди)
    
    // 502 page (сторінка блокування)  
    // Вже заблокований бот продовжує долбити сервер
    'blocked_threshold' => 5,             // Макс. запитів до API блоку
    'blocked_window' => 30,               // Часове вікно (секунди)
    
    // API налаштування (використовує основні налаштування API)
    'api_block_enabled' => true,          // Блокувати через API
    
    // Логування
    'log_enabled' => true,                // Логувати події в error_log
    'redis_stats' => true,                // Зберігати статистику в Redis
);

// v3.8.8: ЄДИНІ НАЛАШТУВАННЯ API (використовуються скрізь)
// v3.8.12: Додано підтримку GET/POST методів

$_API_CONFIG = array(
    'enabled' => true,                                                              // Увімкнути API
    'url' => 'https://blog.dj-x.info/redis-bot_protection/API/iptables.php',       // URL API
    'api_key' => 'Asd12345',                                                       // API ключ
    'method' => 'POST',                                                             // Метод запиту: 'GET' або 'POST'
    'timeout' => 5,                                                                 // Таймаут запиту (секунди)
    'retry_on_failure' => 2,                                                        // Кількість повторів при помилці
    'verify_ssl' => true,                                                           // Перевіряти SSL сертифікат
    'user_agent' => 'BotProtection/3.8.12',                                        // User-Agent для API запитів
    'block_on_api' => true,                                                         // Блокувати через API
    'block_on_redis' => true,                                                       // Блокувати в Redis
);

// ШВИДКА ПЕРЕВІРКА ВЛАСНИХ USER AGENTS (ПЕРЕД JS CHALLENGE!)

/**
 * v3.8.12: Перевірка аномальної активності для автоматичного режиму JS Challenge
 * 
 * Повертає true якщо виявлено підозрілу активність і потрібно показати Challenge
 * 
 * @param string $ip IP адреса клієнта
 * @param string $userAgent User-Agent клієнта
 * @return bool|array false якщо все ОК, або масив з причиною
 */
function _jsc_check_anomaly($ip, $userAgent) {
    global $_JSC_AUTO_CONFIG;
    
    static $redis = null;
    static $connected = false;
    
    // Підключення до Redis
    if ($redis === null) {
        try {
            $redis = new Redis();
            $connected = $redis->connect('127.0.0.1', 6379, 0.5);
            if ($connected) {
                $redis->select(1);
                $redis->setOption(Redis::OPT_SERIALIZER, Redis::SERIALIZER_PHP);
            }
        } catch (Exception $e) {
            // Без Redis - показуємо Challenge для безпеки
            return array('reason' => 'redis_unavailable', 'score' => 99);
        }
    }
    
    if (!$connected) {
        return array('reason' => 'redis_unavailable', 'score' => 99);
    }
    
    $prefix = 'bot_protection:';
    $now = time();
    $suspicionScore = 0;
    $triggers = array();
    
    // ========================================
    // ПЕРЕВІРКА 1: Бали підозрілості за ознаками
    // ========================================
    
    // Порожній User-Agent
    if ($_JSC_AUTO_CONFIG['check_empty_ua'] && empty($userAgent)) {
        $suspicionScore += 2;
        $triggers[] = 'empty_ua';
    }
    
    // Підозрілий User-Agent (боти, скрипти)
    if ($_JSC_AUTO_CONFIG['check_suspicious_ua'] && !empty($userAgent)) {
        $suspiciousPatterns = array('curl', 'wget', 'python', 'java/', 'libwww', 'httpclient', 'axios', 'node-fetch', 'go-http', 'scrapy');
        $uaLower = strtolower($userAgent);
        foreach ($suspiciousPatterns as $pattern) {
            if (strpos($uaLower, $pattern) !== false) {
                $suspicionScore += 1;
                $triggers[] = 'suspicious_ua:' . $pattern;
                break;
            }
        }
    }
    
    // Без Accept-Language (браузери завжди надсилають)
    if ($_JSC_AUTO_CONFIG['check_no_accept_language']) {
        if (empty($_SERVER['HTTP_ACCEPT_LANGUAGE'])) {
            $suspicionScore += 1;
            $triggers[] = 'no_accept_language';
        }
    }
    
    // Без Referer на внутрішніх сторінках
    if ($_JSC_AUTO_CONFIG['check_no_referer']) {
        $uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '/';
        // Тільки для не-головних сторінок
        if ($uri !== '/' && empty($_SERVER['HTTP_REFERER'])) {
            $suspicionScore += 1;
            $triggers[] = 'no_referer';
        }
    }
    
    // ========================================
    // ПЕРЕВІРКА 2: Кількість запитів (rate check)
    // ========================================
    
    $requestKey = $prefix . 'jsc_auto:requests:' . $ip;
    
    try {
        // Отримуємо історію запитів
        $requests = $redis->get($requestKey);
        if (!$requests || !is_array($requests)) {
            $requests = array();
        }
        
        // Додаємо поточний запит
        $requests[] = $now;
        
        // Видаляємо старі записи (старше 60 секунд)
        $requests = array_filter($requests, function($t) use ($now) {
            return ($now - $t) < 60;
        });
        $requests = array_values($requests);
        
        // Зберігаємо оновлений список
        $redis->setex($requestKey, 120, $requests);
        
        $totalRequests = count($requests);
        
        // Grace period - перші N запитів пропускаємо
        if ($totalRequests <= $_JSC_AUTO_CONFIG['grace_requests']) {
            // Новий користувач - даємо шанс
            if (!empty($_JSC_AUTO_CONFIG['log_triggers']) && !empty($triggers)) {
                error_log("JSC AUTO: IP=$ip in grace period (request #$totalRequests), triggers: " . implode(', ', $triggers));
            }
            return false;
        }
        
        // Перевірка burst (багато запитів за короткий час)
        $burstWindow = $_JSC_AUTO_CONFIG['burst_window'];
        $burstCount = 0;
        foreach ($requests as $t) {
            if (($now - $t) < $burstWindow) {
                $burstCount++;
            }
        }
        
        if ($burstCount >= $_JSC_AUTO_CONFIG['burst_threshold']) {
            $suspicionScore += 3;
            $triggers[] = "burst:$burstCount/{$burstWindow}s";
        }
        
        // Перевірка загального rate limit
        if ($totalRequests >= $_JSC_AUTO_CONFIG['rate_threshold']) {
            $suspicionScore += 2;
            $triggers[] = "rate:$totalRequests/60s";
        }
        
    } catch (Exception $e) {
        // При помилці Redis - не блокуємо
    }
    
    // ========================================
    // ПЕРЕВІРКА 3: Запити без cookies
    // ========================================
    
    $hasCookie = isset($_COOKIE['bot_protection_uid']) && !empty($_COOKIE['bot_protection_uid']);
    
    if (!$hasCookie) {
        $noCookieKey = $prefix . 'jsc_auto:no_cookie:' . $ip;
        
        try {
            $noCookieRequests = $redis->get($noCookieKey);
            if (!$noCookieRequests || !is_array($noCookieRequests)) {
                $noCookieRequests = array();
            }
            
            // Фільтруємо за вікном
            $window = $_JSC_AUTO_CONFIG['no_cookie_window'];
            $noCookieRequests = array_filter($noCookieRequests, function($t) use ($now, $window) {
                return ($now - $t) < $window;
            });
            $noCookieRequests = array_values($noCookieRequests);
            $noCookieRequests[] = $now;
            
            $redis->setex($noCookieKey, $window * 2, $noCookieRequests);
            
            $noCookieCount = count($noCookieRequests);
            
            if ($noCookieCount >= $_JSC_AUTO_CONFIG['no_cookie_threshold']) {
                $suspicionScore += 2;
                $triggers[] = "no_cookie:$noCookieCount/{$window}s";
            }
            
        } catch (Exception $e) {
            // При помилці - не блокуємо
        }
    }
    
    // ========================================
    // РІШЕННЯ: показувати Challenge чи ні
    // ========================================
    
    if ($suspicionScore >= $_JSC_AUTO_CONFIG['suspicion_threshold']) {
        if (!empty($_JSC_AUTO_CONFIG['log_triggers'])) {
            error_log(sprintf(
                "JSC AUTO TRIGGERED: IP=%s, score=%d (threshold=%d), triggers=[%s], UA=%s",
                $ip,
                $suspicionScore,
                $_JSC_AUTO_CONFIG['suspicion_threshold'],
                implode(', ', $triggers),
                substr($userAgent, 0, 80)
            ));
        }
        
        return array(
            'reason' => 'anomaly_detected',
            'score' => $suspicionScore,
            'triggers' => $triggers
        );
    }
    
    return false;
}

/**
 * Перевірка чи User Agent в whitelist власних UA
 * Викликається ДО JS Challenge для негайного пропуску
 * v3.8.10: Додано логування в Redis як для пошукових систем
 */
function _is_custom_ua($userAgent) {
    global $CUSTOM_USER_AGENTS;
    
    static $redis = null;
    static $connected = false;
    static $logged = array(); // Захист від дублювання логів
    
    if (empty($CUSTOM_USER_AGENTS) || empty($userAgent)) {
        return false;
    }
    
    $userAgentLower = strtolower($userAgent);
    
    foreach ($CUSTOM_USER_AGENTS as $customUA) {
        if (empty($customUA)) {
            continue;
        }
        // Часткове співпадіння (strpos) для гнучкості
        if (stripos($userAgentLower, strtolower($customUA)) !== false) {
            error_log("CUSTOM UA WHITELIST: Allowing - contains: " . $customUA . " | Full UA: " . substr($userAgent, 0, 100));
            
            // v3.8.10: Логування в Redis як для пошукових систем
            $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '0.0.0.0';
            $ip = filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '0.0.0.0';
            
            // Підключення до Redis (один раз)
            if ($redis === null) {
                try {
                    $redis = new Redis();
                    $connected = $redis->connect('127.0.0.1', 6379, 0.5);
                    if ($connected) {
                        $redis->select(1);
                        $redis->setOption(Redis::OPT_SERIALIZER, Redis::SERIALIZER_PHP);
                    }
                } catch (Exception $e) {
                    $connected = false;
                }
            }
            
            // Логуємо в Redis тільки один раз за запит
            if ($connected && !isset($logged[$ip . ':' . $customUA])) {
                $logged[$ip . ':' . $customUA] = true;
                // Engine = CustomUA:назва_паттерна (наприклад: CustomUA:hosttracker)
                _log_search_engine_visit($redis, $ip, 'CustomUA', 'CustomUA:' . $customUA);
            }
            
            return true;
        }
    }
    
    return false;
}

/**
 * Швидка перевірка SEO ботів для раннього пропуску
 */
function _is_seo_bot($userAgent) {
    if (empty($userAgent)) {
        return false;
    }
    
    $userAgentLower = strtolower($userAgent);
    
    // Базовий список для швидкої перевірки
    $seoBots = array(
        'googlebot', 'yandex', 'bingbot', 'duckduckbot',
        'facebookexternalhit', 'twitterbot', 'pinterest',
        'linkedinbot', 'whatsapp', 'telegram', 'viber',
        'petalbot'  // v3.8.4: Huawei Petal Search
    );
    
    foreach ($seoBots as $bot) {
        if (strpos($userAgentLower, $bot) !== false) {
            return true;
        }
    }
    
    return false;
}

// v3.8.7: ФУНКЦІЇ ЗАХИСТУ ВІД HAMMER АТАК

/**
 * v3.8.7: Відстеження та блокування ботів що долбять сторінки
 * 
 * @param string $ip IP адреса
 * @param string $pageType Тип сторінки: 'challenge' або 'blocked'
 * @return bool true якщо IP заблоковано
 */
function _track_page_hammer($ip, $pageType = 'challenge') {
    global $_HAMMER_PROTECTION;
    
    // Перевірка чи увімкнено захист
    if (empty($_HAMMER_PROTECTION['enabled'])) {
        return false;
    }
    
    // Визначаємо пороги для типу сторінки
    if ($pageType === 'blocked') {
        $threshold = $_HAMMER_PROTECTION['blocked_threshold'];
        $window = $_HAMMER_PROTECTION['blocked_window'];
        $keyPrefix = 'hammer:blocked:';
        $blockReason = '502_page_hammer';
    } else {
        $threshold = $_HAMMER_PROTECTION['challenge_threshold'];
        $window = $_HAMMER_PROTECTION['challenge_window'];
        $keyPrefix = 'hammer:challenge:';
        $blockReason = 'challenge_page_hammer';
    }
    
    // Підключення до Redis
    static $redis = null;
    static $connected = false;
    
    if ($redis === null) {
        try {
            $redis = new Redis();
            $connected = $redis->connect('127.0.0.1', 6379, 0.5);
            if ($connected) {
                $redis->select(1);
                $redis->setOption(Redis::OPT_SERIALIZER, Redis::SERIALIZER_PHP);
            }
        } catch (Exception $e) {
            error_log("HAMMER PROTECTION: Redis connection failed - " . $e->getMessage());
            return false;
        }
    }
    
    if (!$connected) {
        return false;
    }
    
    $prefix = 'bot_protection:';
    $key = $prefix . $keyPrefix . $ip;
    $now = time();
    
    try {
        // Отримуємо історію запитів
        $attempts = $redis->get($key);
        if (!$attempts || !is_array($attempts)) {
            $attempts = array();
        }
        
        // Фільтруємо старі записи (поза часовим вікном)
        $filtered = array();
        foreach ($attempts as $timestamp) {
            if (($now - $timestamp) < $window) {
                $filtered[] = $timestamp;
            }
        }
        
        // Додаємо поточний запит
        $filtered[] = $now;
        $attemptCount = count($filtered);
        
        // Зберігаємо в Redis з подвійним TTL
        $redis->setex($key, $window * 2, $filtered);
        
        // Логування статистики в Redis
        if (!empty($_HAMMER_PROTECTION['redis_stats'])) {
            $statsKey = $prefix . 'hammer_stats:' . $pageType . ':' . date('Y-m-d');
            $redis->incr($statsKey);
            $redis->expire($statsKey, 86400 * 7); // 7 днів
        }
        
        // Перевірка порогу - чи потрібно блокувати
        if ($attemptCount >= $threshold) {
            // Логування атаки
            if (!empty($_HAMMER_PROTECTION['log_enabled'])) {
                $ua = isset($_SERVER['HTTP_USER_AGENT']) ? substr($_SERVER['HTTP_USER_AGENT'], 0, 100) : '-';
                error_log(sprintf(
                    "HAMMER ATTACK DETECTED: IP=%s, page=%s, hits=%d in %dsec (threshold=%d), UA=%s",
                    $ip, $pageType, $attemptCount, $window, $threshold, $ua
                ));
            }
            
            // Блокуємо в Redis
            $blockKey = $prefix . 'blocked:hammer:' . $ip;
            $redis->setex($blockKey, 3600, array(
                'ip' => $ip,
                'time' => $now,
                'reason' => $blockReason,
                'page_type' => $pageType,
                'attempts' => $attemptCount,
                'threshold' => $threshold,
                'window' => $window,
                'ua' => isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '-',
            ));
            
            // Статистика блокувань
            if (!empty($_HAMMER_PROTECTION['redis_stats'])) {
                $blockStatsKey = $prefix . 'hammer_blocks:' . $pageType . ':' . date('Y-m-d');
                $redis->incr($blockStatsKey);
                $redis->expire($blockStatsKey, 86400 * 7);
            }
            
            // Блокуємо через API
            if (!empty($_HAMMER_PROTECTION['api_block_enabled'])) {
                $apiResult = _hammer_call_api($ip, $blockReason);
                
                if ($apiResult && isset($apiResult['status'])) {
                    if ($apiResult['status'] === 'success') {
                        error_log("HAMMER API BLOCK SUCCESS: IP=$ip (reason=$blockReason, $attemptCount hits in {$window}sec)");
                    } elseif ($apiResult['status'] !== 'already_blocked') {
                        $msg = isset($apiResult['message']) ? $apiResult['message'] : 'unknown';
                        error_log("HAMMER API BLOCK FAILED: IP=$ip, reason=" . $msg);
                    } else {
                        error_log("HAMMER API: IP=$ip already blocked");
                    }
                }
            }
            
            return true;
        }
        
        // Debug логування проміжних результатів
        if ($attemptCount > 2 && !empty($_HAMMER_PROTECTION['log_enabled'])) {
            error_log(sprintf(
                "HAMMER CHECK: IP=%s, page=%s, hits=%d/%d in %dsec",
                $ip, $pageType, $attemptCount, $threshold, $window
            ));
        }
        
    } catch (Exception $e) {
        error_log("HAMMER PROTECTION ERROR: " . $e->getMessage());
    }
    
    return false;
}

/**
 * v3.8.7: Виклик API для блокування IP
 * v3.8.8: Використовує глобальні налаштування $_API_CONFIG
 * v3.8.12: Підтримка GET/POST методів
 */
function _hammer_call_api($ip, $reason = 'hammer_attack') {
    global $_API_CONFIG;
    
    // Перевіряємо чи API увімкнено
    if (empty($_API_CONFIG['enabled']) || empty($_API_CONFIG['block_on_api'])) {
        return array('status' => 'skipped', 'message' => 'API disabled');
    }
    
    // Визначаємо метод запиту (за замовчуванням POST)
    $method = isset($_API_CONFIG['method']) ? strtoupper($_API_CONFIG['method']) : 'POST';
    
    // Параметри запиту
    $params = array(
        'action' => 'block',
        'ip' => $ip,
        'api' => 1,
        'api_key' => $_API_CONFIG['api_key'],
        'reason' => $reason
    );
    
    try {
        $ch = curl_init();
        if (!$ch) {
            return array('status' => 'error', 'message' => 'cURL init failed');
        }
        
        $curlOptions = array(
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $_API_CONFIG['timeout'],
            CURLOPT_CONNECTTIMEOUT => 3,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_SSL_VERIFYPEER => $_API_CONFIG['verify_ssl'],
            CURLOPT_SSL_VERIFYHOST => $_API_CONFIG['verify_ssl'] ? 2 : 0,
            CURLOPT_USERAGENT => $_API_CONFIG['user_agent'] . '-Hammer',
            CURLOPT_HTTPHEADER => array(
                'Accept: application/json',
                'Cache-Control: no-cache'
            )
        );
        
        if ($method === 'POST') {
            // POST запит - параметри в тілі
            $curlOptions[CURLOPT_URL] = $_API_CONFIG['url'];
            $curlOptions[CURLOPT_POST] = true;
            $curlOptions[CURLOPT_POSTFIELDS] = http_build_query($params);
        } else {
            // GET запит - параметри в URL
            $curlOptions[CURLOPT_URL] = $_API_CONFIG['url'] . '?' . http_build_query($params);
        }
        
        curl_setopt_array($ch, $curlOptions);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);
        
        if (!empty($curlError)) {
            return array('status' => 'error', 'message' => $curlError);
        }
        
        if ($httpCode !== 200) {
            return array('status' => 'error', 'message' => 'HTTP ' . $httpCode);
        }
        
        $result = json_decode($response, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            return array('status' => 'error', 'message' => 'Invalid JSON');
        }
        
        return $result;
        
    } catch (Exception $e) {
        return array('status' => 'error', 'message' => $e->getMessage());
    }
}

/**
 * v3.8.7: Перевірка чи IP вже заблокований за hammer attack
 */
function _is_hammer_blocked($ip) {
    static $redis = null;
    static $connected = false;
    
    if ($redis === null) {
        try {
            $redis = new Redis();
            $connected = $redis->connect('127.0.0.1', 6379, 0.5);
            if ($connected) {
                $redis->select(1);
            }
        } catch (Exception $e) {
            return false;
        }
    }
    
    if (!$connected) {
        return false;
    }
    
    try {
        $blockKey = 'bot_protection:blocked:hammer:' . $ip;
        return $redis->exists($blockKey);
    } catch (Exception $e) {
        return false;
    }
}

// ПЕРЕВІРКА АДМІНСЬКИХ IP (v3.8.1) - НАЙВИЩИЙ ПРІОРИТЕТ!

/**
 * Перевірка IP по білому списку адмінів/власних IP
 * Працює для БУДЬ-ЯКОГО User-Agent!
 * Пропускає ВСІ перевірки (JS Challenge, Rate Limit, і т.д.)
 * 
 * @param string $ip IP адреса
 * @return bool true якщо IP в білому списку адмінів
 */
function _is_admin_ip($ip) {
    global $ADMIN_IP_WHITELIST;
    
    if (empty($ADMIN_IP_WHITELIST) || empty($ip)) {
        return false;
    }
    
    foreach ($ADMIN_IP_WHITELIST as $cidr) {
        if (empty($cidr)) {
            continue;
        }
        
        // Якщо без маски - додаємо /32 для IPv4 або /128 для IPv6
        if (strpos($cidr, '/') === false) {
            $cidr = $cidr . (strpos($cidr, ':') !== false ? '/128' : '/32');
        }
        
        if (_ip_in_cidr_check($ip, $cidr)) {
            error_log("ADMIN IP WHITELIST: Allowing IP $ip (matched $cidr)");
            return true;
        }
    }
    
    return false;
}

/**
 * v3.8.2: УНІВЕРСАЛЬНА перевірка IP по ВСІХ білих списках
 * Перевіряє: $ADMIN_IP_WHITELIST + $SEARCH_ENGINE_IP_RANGES
 * 
 * @param string $ip IP адреса
 * @return bool|string false якщо не в списку, інакше назва списку ('admin' або 'search_engine')
 */
function _is_whitelisted_ip($ip) {
    if (empty($ip)) {
        return false;
    }
    
    // 1. Спочатку перевіряємо адмінські IP (найвищий пріоритет)
    if (_is_admin_ip($ip)) {
        return 'admin';
    }
    
    // 2. Потім перевіряємо IP пошукових систем
    if (_is_search_engine_ip($ip)) {
        return 'search_engine';
    }
    
    return false;
}

// НОВЕ v3.8.4: ФУНКЦІЇ ПЕРЕВІРКИ URL АДМІНКИ ТА AJAX

/**
 * Перевірка чи URL належить до адмінки
 * Повертає true якщо URL збігається з будь-яким шляхом з $ADMIN_URL_WHITELIST
 * 
 * @return bool true якщо URL в білому списку адмінки
 */
function _is_admin_url() {
    global $ADMIN_URL_WHITELIST_ENABLED, $ADMIN_URL_WHITELIST;
    
    if (empty($ADMIN_URL_WHITELIST_ENABLED) || empty($ADMIN_URL_WHITELIST)) {
        return false;
    }
    
    $uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
    if (empty($uri)) {
        return false;
    }
    
    // Перевіряємо і шлях і повний URI (для query string як ?action=admin)
    $path = parse_url($uri, PHP_URL_PATH);
    if ($path === null || $path === false || $path === '') {
        $path = $uri;
    }
    
    $uriLower = strtolower((string)$uri);
    $pathLower = strtolower((string)$path);
    
    foreach ($ADMIN_URL_WHITELIST as $adminPath) {
        if (empty($adminPath)) {
            continue;
        }
        
        $adminPathLower = strtolower($adminPath);
        
        // Перевіряємо і шлях і повний URI
        if (strpos($pathLower, $adminPathLower) !== false || 
            strpos($uriLower, $adminPathLower) !== false) {
            // Debug log (розкоментуй для діагностики)
            // error_log("ADMIN URL WHITELIST: Matched '$adminPath' for URI: $uri");
            return true;
        }
    }
    
    return false;
}

/**
 * Перевірка чи запит є AJAX
 * Перевіряє стандартний заголовок X-Requested-With та Content-Type/Accept для fetch API
 * 
 * @return bool true якщо це AJAX запит
 */
function _is_ajax_request() {
    // 1. Стандартний спосіб: заголовок X-Requested-With (jQuery, axios, etc.)
    if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && 
        strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
        return true;
    }
    
    // 2. Fetch API: Content-Type = application/json
    if (!empty($_SERVER['CONTENT_TYPE'])) {
        $contentType = strtolower($_SERVER['CONTENT_TYPE']);
        if (strpos($contentType, 'application/json') !== false) {
            return true;
        }
    }
    
    // 3. Fetch API: Accept починається з application/json
    if (!empty($_SERVER['HTTP_ACCEPT'])) {
        $accept = strtolower($_SERVER['HTTP_ACCEPT']);
        // Перевіряємо що JSON є першим у списку Accept (пріоритетний формат)
        if (strpos($accept, 'application/json') === 0) {
            return true;
        }
    }
    
    // 4. Перевірка X-JSC-Response (наш власний AJAX для JS Challenge)
    if (!empty($_SERVER['HTTP_X_JSC_RESPONSE'])) {
        return true;
    }
    
    return false;
}

/**
 * v3.8.4: УНІВЕРСАЛЬНА перевірка чи пропускати Rate Limit
 * Централізована функція для перевірки всіх умов пропуску
 * 
 * @param string $ip IP адреса
 * @return bool|string false якщо перевіряти Rate Limit, інакше причина пропуску
 */
function _should_skip_rate_limit($ip) {
    global $AJAX_SKIP_RATE_LIMIT;
    
    // 1. Білі списки IP (найвищий пріоритет - перевіряється першим)
    $whitelistType = _is_whitelisted_ip($ip);
    if ($whitelistType !== false) {
        return 'ip_whitelist:' . $whitelistType;
    }
    
    // 2. URL адмінки (другий пріоритет)
    if (_is_admin_url()) {
        return 'admin_url';
    }
    
    // 3. AJAX запити (тільки якщо увімкнено глобальний пропуск)
    if (!empty($AJAX_SKIP_RATE_LIMIT) && _is_ajax_request()) {
        return 'ajax_request';
    }
    
    return false;
}

/**
 * v3.8.4: Отримати множник Rate Limit для поточного запиту
 * Повертає множник на основі типу запиту (AJAX отримує вищий множник)
 * 
 * @return float множник (1.0 = без змін, >1.0 = збільшені ліміти)
 */
function _get_rate_limit_multiplier() {
    global $AJAX_RATE_LIMIT_MULTIPLIER;
    
    // Якщо це AJAX запит і множник налаштований
    if (_is_ajax_request() && !empty($AJAX_RATE_LIMIT_MULTIPLIER) && $AJAX_RATE_LIMIT_MULTIPLIER > 1.0) {
        return (float)$AJAX_RATE_LIMIT_MULTIPLIER;
    }
    
    return 1.0;
}

/**
 * Універсальна перевірка IP в CIDR (для адмінського whitelist)
 */
function _ip_in_cidr_check($ip, $cidr) {
    if (strpos($cidr, '/') === false) {
        return $ip === $cidr;
    }
    
    list($subnet, $mask) = explode('/', $cidr);
    $mask = (int)$mask;
    
    $ipIsV6 = (strpos($ip, ':') !== false);
    $cidrIsV6 = (strpos($subnet, ':') !== false);
    
    // IPv4 і IPv6 не можуть співпадати
    if ($ipIsV6 !== $cidrIsV6) {
        return false;
    }
    
    if ($ipIsV6) {
        // IPv6
        if ($mask < 0 || $mask > 128) {
            return false;
        }
        return _ipv6_in_cidr_fast($ip, $subnet, $mask);
    }
    
    // IPv4
    if ($mask < 0 || $mask > 32) {
        return false;
    }
    
    $ip_long = ip2long($ip);
    $subnet_long = ip2long($subnet);
    
    if ($ip_long === false || $subnet_long === false) {
        return false;
    }
    
    $mask_long = -1 << (32 - $mask);
    
    return ($ip_long & $mask_long) === ($subnet_long & $mask_long);
}

// ПЕРЕВІРКА IP ПО БІЛОМУ СПИСКУ (v3.7.0)

/**
 * Перевірка IP по білому списку пошукових систем
 * Працює для БУДЬ-ЯКОГО User-Agent!
 * Кешується в Redis для швидкості
 * 
 * @param string $ip IP адреса
 * @return bool true якщо IP в білому списку
 */
function _is_search_engine_ip($ip) {
    global $SEARCH_ENGINE_IP_RANGES;
    
    static $redis = null;
    static $connected = false;
    static $logged = array(); // Захист від дублювання логів
    
    // Підключення до Redis (один раз)
    if ($redis === null) {
        try {
            $redis = new Redis();
            $connected = $redis->connect('127.0.0.1', 6379, 0.5);
            if ($connected) {
                $redis->select(1);
                $redis->setOption(Redis::OPT_SERIALIZER, Redis::SERIALIZER_PHP);
            }
        } catch (Exception $e) {
            $connected = false;
        }
    }
    
    // Перевірка кешу Redis
    if ($connected) {
        $cacheKey = 'bot_protection:ip_whitelist:' . $ip;
        try {
            $cached = $redis->get($cacheKey);
            if ($cached !== false) {
                // Якщо IP вже в кеші і він whitelisted - повертаємо true
                // Логуємо тільки один раз за запит!
                if ($cached === '1' || $cached === 1 || $cached === true) {
                    if (!isset($logged[$ip])) {
                        $logged[$ip] = true;
                        _log_search_engine_visit($redis, $ip, 'IP-cached');
                    }
                    return true;
                }
                return false;
            }
        } catch (Exception $e) {
            // Ігноруємо помилки кешу
        }
    }
    
    // Перевірка IP в діапазонах
    $result = false;
    $matchedEngine = 'unknown';
    $isIPv6 = (strpos($ip, ':') !== false);
    
    foreach ($SEARCH_ENGINE_IP_RANGES as $cidr) {
        $cidrIsIPv6 = (strpos($cidr, ':') !== false);
        if ($isIPv6 !== $cidrIsIPv6) {
            continue;
        }
        
        if (_ip_in_cidr_fast($ip, $cidr)) {
            $result = true;
            // Визначаємо пошукову систему по CIDR
            $matchedEngine = _detect_engine_by_cidr($cidr);
            break;
        }
    }
    
    // Зберігаємо в кеш Redis (24 години)
    if ($connected) {
        try {
            $redis->setex($cacheKey, 86400, $result ? '1' : '0');
        } catch (Exception $e) {
            // Ігноруємо помилки кешу
        }
    }
    
    if ($result) {
        error_log("SEARCH ENGINE IP WHITELIST: Allowing IP=$ip (engine=$matchedEngine)");
        // Логуємо візит в Redis тільки один раз за запит!
        if ($connected && !isset($logged[$ip])) {
            $logged[$ip] = true;
            _log_search_engine_visit($redis, $ip, 'IP', $matchedEngine);
        }
    }
    
    return $result;
}

/**
 * v3.7.0: Визначення пошукової системи по CIDR
 */
function _detect_engine_by_cidr($cidr) {
    // Test IPs
    if (strpos($cidr, '185.6.186.') === 0 || strpos($cidr, '2a00:1e20:11:9108') === 0) {
        return 'Test';
    }
    
    // Google IPv4 - всі діапазони з білого списку
    if (preg_match('/^(66\.249|66\.102|74\.125|142\.250|172\.217|192\.178|34\.|35\.247)/', $cidr)) {
        return 'Google';
    }
    // Google IPv6
    if (strpos($cidr, '2001:4860') === 0) {
        return 'Google';
    }
    
    // Yandex IPv4 - всі діапазони
    if (preg_match('/^(5\.45|5\.255|37\.9|37\.140|77\.88|84\.201|87\.250|90\.156|93\.158|95\.108|100\.43|130\.193|141\.8|178\.154|185\.32\.187|199\.21|199\.36|213\.180)/', $cidr)) {
        return 'Yandex';
    }
    // Yandex IPv6
    if (strpos($cidr, '2a02:6b8') === 0) {
        return 'Yandex';
    }
    
    // Bing/Microsoft IPv4 - всі діапазони
    if (preg_match('/^(13\.|20\.|40\.|51\.105|52\.|65\.55|139\.217|157\.55|191\.233|199\.30|207\.46)/', $cidr)) {
        return 'Bing';
    }
    // Bing IPv6
    if (strpos($cidr, '2620:1ec') === 0 || strpos($cidr, '2a01:111') === 0) {
        return 'Bing';
    }
    
    // Baidu IPv4
    if (preg_match('/^(116\.179|119\.63|123\.125|180\.76|220\.181)/', $cidr)) {
        return 'Baidu';
    }
    
    // Facebook IPv4
    if (preg_match('/^(31\.13|66\.220|69\.63|69\.171|157\.240|173\.252|185\.60)/', $cidr)) {
        return 'Facebook';
    }
    // Facebook IPv6
    if (strpos($cidr, '2a03:2880') === 0) {
        return 'Facebook';
    }
    
    // Apple IPv4
    if (strpos($cidr, '17.') === 0) {
        return 'Apple';
    }
    // Apple IPv6
    if (strpos($cidr, '2620:149') === 0 || strpos($cidr, '2a01:b740') === 0) {
        return 'Apple';
    }
    
    // DuckDuckGo IPv4
    if (preg_match('/^(20\.191|40\.88|52\.142|72\.94)/', $cidr)) {
        return 'DuckDuckGo';
    }
    
    // Yahoo IPv4
    if (preg_match('/^(67\.195|72\.30|74\.6|98\.13[6-9])/', $cidr)) {
        return 'Yahoo';
    }
    
    // PetalBot (Huawei) IPv4
    if (strpos($cidr, '114.119.') === 0) {
        return 'PetalBot';
    }
    
    return 'Other';
}

/**
 * v3.7.0: Логування візиту пошукового бота в Redis
 */
function _log_search_engine_visit($redis, $ip, $method, $engine = null) {
    if (!$redis) {
        return;
    }
    
    try {
        // Визначаємо engine з User-Agent якщо не передано
        if (!$engine) {
            // Спочатку перевіряємо тестові IP (пріоритет!)
            if ($ip === '185.6.186.106' || strpos($ip, '2a00:1e20:11:9108') === 0) {
                $engine = 'Test';
            } else {
                $ua = isset($_SERVER['HTTP_USER_AGENT']) ? strtolower($_SERVER['HTTP_USER_AGENT']) : '';
                if (strpos($ua, 'googlebot') !== false || strpos($ua, 'google-inspectiontool') !== false) {
                    $engine = 'Google';
                } elseif (strpos($ua, 'yandex') !== false) {
                    $engine = 'Yandex';
                } elseif (strpos($ua, 'bingbot') !== false || strpos($ua, 'msnbot') !== false) {
                    $engine = 'Bing';
                } elseif (strpos($ua, 'baiduspider') !== false) {
                    $engine = 'Baidu';
                } elseif (strpos($ua, 'duckduckbot') !== false) {
                    $engine = 'DuckDuckGo';
                } elseif (strpos($ua, 'facebookexternalhit') !== false || strpos($ua, 'facebot') !== false) {
                    $engine = 'Facebook';
                } elseif (strpos($ua, 'applebot') !== false) {
                    $engine = 'Apple';
                } elseif (strpos($ua, 'petalbot') !== false) {
                    $engine = 'PetalBot';
                } else {
                    $engine = 'Other';
                }
            }
        }
        
        $today = date('Y-m-d');
        $host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : 'unknown';
        $url = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '/';
        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '-';
        
        // Скорочуємо UA
        if (strlen($ua) > 100) {
            $ua = substr($ua, 0, 100) . '...';
        }
        
        $prefix = 'bot_protection:';
        
        // 1. Інкрементуємо загальний лічильник бота
        $totalKey = $prefix . 'search_stats:total:' . strtolower($engine);
        $redis->incr($totalKey);
        
        // 2. Інкрементуємо денний лічильник бота
        $todayKey = $prefix . 'search_stats:today:' . $today . ':' . strtolower($engine);
        $redis->incr($todayKey);
        $redis->expire($todayKey, 86400 * 7);
        
        // 3. Інкрементуємо лічильник по хосту
        $hostKey = $prefix . 'search_stats:hosts:' . $host;
        $redis->incr($hostKey);
        $redis->expire($hostKey, 86400 * 30);
        
        // 4. Інкрементуємо лічильник по методу
        $methodKey = $prefix . 'search_stats:methods:' . strtolower($method);
        $redis->incr($methodKey);
        
        // 5. Додаємо запис в лог
        $logEntry = array(
            'time' => date('Y-m-d H:i:s'),
            'engine' => $engine,
            'ip' => $ip,
            'method' => $method,
            'host' => $host,
            'url' => $url,
            'ua' => $ua,
        );
        
        $logKey = $prefix . 'search_log';
        $redis->lpush($logKey, $logEntry);
        $redis->ltrim($logKey, 0, 499);
        
    } catch (Exception $e) {
        // Ігноруємо помилки
    }
}

/**
 * Швидка перевірка IP в CIDR діапазоні (IPv4 та IPv6)
 */
function _ip_in_cidr_fast($ip, $cidr) {
    if (strpos($cidr, '/') === false) {
        return $ip === $cidr;
    }
    
    list($subnet, $bits) = explode('/', $cidr, 2);
    $bits = (int)$bits;
    
    // IPv6
    if (strpos($ip, ':') !== false) {
        return _ipv6_in_cidr_fast($ip, $subnet, $bits);
    }
    
    // IPv4
    if ($bits < 0 || $bits > 32) {
        return false;
    }
    
    $ip_long = ip2long($ip);
    $subnet_long = ip2long($subnet);
    
    if ($ip_long === false || $subnet_long === false) {
        return false;
    }
    
    if ($bits === 0) {
        return true;
    }
    
    $mask = -1 << (32 - $bits);
    return ($ip_long & $mask) === ($subnet_long & $mask);
}

/**
 * Перевірка IPv6 в CIDR діапазоні
 */
function _ipv6_in_cidr_fast($ip, $subnet, $bits) {
    if ($bits < 0 || $bits > 128) {
        return false;
    }
    
    $ip_bin = @inet_pton($ip);
    $subnet_bin = @inet_pton($subnet);
    
    if ($ip_bin === false || $subnet_bin === false) {
        return false;
    }
    
    if ($bits === 0) {
        return true;
    }
    
    $full_bytes = (int)floor($bits / 8);
    $remaining_bits = $bits % 8;
    
    for ($i = 0; $i < $full_bytes; $i++) {
        if ($ip_bin[$i] !== $subnet_bin[$i]) {
            return false;
        }
    }
    
    if ($remaining_bits > 0 && $full_bytes < 16) {
        $mask = 0xFF << (8 - $remaining_bits);
        if ((ord($ip_bin[$full_bytes]) & $mask) !== (ord($subnet_bin[$full_bytes]) & $mask)) {
            return false;
        }
    }
    
    return true;
}

// JS CHALLENGE ФУНКЦІЇ

function _jsc_getClientIP() {
    $ip = '0.0.0.0';
    
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        $ip = $_SERVER['HTTP_CF_CONNECTING_IP'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        $ip = trim($ips[0]);
    } elseif (!empty($_SERVER['HTTP_X_REAL_IP'])) {
        $ip = $_SERVER['HTTP_X_REAL_IP'];
    } elseif (isset($_SERVER['REMOTE_ADDR'])) {
        $ip = $_SERVER['REMOTE_ADDR'];
    }
    
    // Валідація IP
    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '0.0.0.0';
}

function _jsc_isVerified($secret_key, $cookie_name) {
    if (!isset($_COOKIE[$cookie_name])) {
        return false;
    }
    $cookie = $_COOKIE[$cookie_name];
    
    // Валідація: має бути sha256 hex (64 символи a-f0-9)
    if (!preg_match('/^[a-f0-9]{64}$/', $cookie)) {
        _jsc_logStats('failed', _jsc_getClientIP());
        return false;
    }
    
    $ip = _jsc_getClientIP();
    
    // v3.8.5: Перевіряємо токен за останні 3 дні (для 1.5 доби валідності)
    $daysToCheck = array(
        date('Y-m-d'),
        date('Y-m-d', strtotime('-1 day')),
        date('Y-m-d', strtotime('-2 days')),
    );
    
    $verified = false;
    foreach ($daysToCheck as $day) {
        $expected = hash('sha256', $ip . $day . $secret_key);
        if (hash_equals($expected, $cookie)) {
            $verified = true;
            break;
        }
    }
    
    if (!$verified) {
        _jsc_logStats('expired', $ip);
    }
    
    return $verified;
}

/**
 * v3.7.0: Логування статистики JS Challenge в Redis
 * @param string $type - 'shown', 'passed', 'failed', 'expired'
 * @param string $ip - IP адреса клієнта
 */
function _jsc_logStats($type, $ip = null) {
    static $redis = null;
    static $connected = false;
    static $logged = array(); // Запобігаємо дублюванню в одному запиті
    
    // Логуємо кожен тип тільки один раз за запит
    if (isset($logged[$type])) {
        return;
    }
    $logged[$type] = true;
    
    if ($ip === null) {
        $ip = _jsc_getClientIP();
    }
    
    // Підключення до Redis
    if ($redis === null) {
        try {
            $redis = new Redis();
            $connected = $redis->connect('127.0.0.1', 6379, 0.5);
            if ($connected) {
                $redis->select(1);
                $redis->setOption(Redis::OPT_SERIALIZER, Redis::SERIALIZER_PHP);
            }
        } catch (Exception $e) {
            $connected = false;
            return;
        }
    }
    
    if (!$connected) {
        return;
    }
    
    try {
        $prefix = 'bot_protection:jsc_stats:';
        $today = date('Y-m-d');
        $hour = date('Y-m-d:H');
        
        // 1. Інкрементуємо загальний лічильник
        $redis->incr($prefix . 'total:' . $type);
        
        // 2. Інкрементуємо денний лічильник
        $dailyKey = $prefix . 'daily:' . $today . ':' . $type;
        $redis->incr($dailyKey);
        $redis->expire($dailyKey, 86400 * 7); // 7 днів
        
        // 3. Інкрементуємо погодинний лічильник
        $hourlyKey = $prefix . 'hourly:' . $hour . ':' . $type;
        $redis->incr($hourlyKey);
        $redis->expire($hourlyKey, 86400 * 2); // 2 дні
        
        // 4. Додаємо запис в лог (останні 100 записів)
        $logEntry = array(
            'date' => date('Y-m-d H:i:s'),
            'ip' => $ip,
            'ua' => isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '-',
        );
        
        $logKey = $prefix . 'log:' . $type;
        $redis->lPush($logKey, $logEntry);
        $redis->lTrim($logKey, 0, 99); // Зберігаємо останні 100
        
    } catch (Exception $e) {
        // Ігноруємо помилки
    }
}

function _jsc_generateChallenge($secret_key) {
    global $_JSC_CONFIG;
    
    // v3.8.9: Генеруємо дані для обох типів challenge (PoW + fallback sum)
    $id = bin2hex(random_bytes(16));
    $timestamp = time();
    
    // Дані для fallback challenge (сума чисел)
    $numbers = array();
    for ($i = 0; $i < 5; $i++) {
        $numbers[] = mt_rand(10, 99);
    }
    $answer = array_sum($numbers);
    $sumTarget = hash('sha256', $id . $timestamp . $answer . $secret_key);
    
    // v3.8.0: Proof of Work challenge (з fallback)
    if (!empty($_JSC_CONFIG['pow_enabled'])) {
        $difficulty = isset($_JSC_CONFIG['pow_difficulty']) ? (int)$_JSC_CONFIG['pow_difficulty'] : 4;
        $timeout = isset($_JSC_CONFIG['pow_timeout']) ? (int)$_JSC_CONFIG['pow_timeout'] : 60;
        $style = isset($_JSC_CONFIG['pow_style']) ? $_JSC_CONFIG['pow_style'] : 'cloudflare';
        
        return array(
            'type' => 'pow',
            'id' => $id,
            'timestamp' => $timestamp,
            'difficulty' => $difficulty,
            'timeout' => $timeout,
            'style' => $style,
            'target' => str_repeat('0', $difficulty),
            // v3.8.9: Fallback дані для браузерів без crypto.subtle
            'fallback' => array(
                'numbers' => $numbers,
                'target' => $sumTarget
            )
        );
    }
    
    // Стандартний challenge (сума чисел)
    return array(
        'type' => 'sum',
        'id' => $id,
        'timestamp' => $timestamp,
        'numbers' => $numbers,
        'target' => $sumTarget,
        'difficulty' => 3
    );
}

function _jsc_showChallengePage($challenge, $redirect_url) {
    // v3.8.7: Відстеження hammer атак на challenge page
    $ip = _jsc_getClientIP();
    if (_track_page_hammer($ip, 'challenge')) {
        // IP заблоковано за hammer - показуємо 502
        _show_502_error();
        return;
    }
    
    // v3.8.0: Логуємо показ challenge
    _jsc_logStats('shown');
    
    $challengeJson = json_encode($challenge);
    $redirectJson = json_encode($redirect_url);
    $isPow = isset($challenge['type']) && $challenge['type'] === 'pow';
    $style = isset($challenge['style']) ? $challenge['style'] : 'cloudflare';
    
    http_response_code(200);
    header('Content-Type: text/html; charset=UTF-8');
    header('Cache-Control: no-cache, no-store, must-revalidate');
    header('X-Robots-Tag: noindex, nofollow');
    
    // v3.8.0: Вибір стилю сторінки
    if ($isPow && $style === 'cloudflare') {
        _jsc_showCloudflarePoWPage($challengeJson, $redirectJson);
    } else {
        _jsc_showSMFChallengePage($challengeJson, $redirectJson, $isPow);
    }
    exit;
}

/**
 * v3.8.6: Cloudflare-style Proof of Work сторінка
 */
function _jsc_showCloudflarePoWPage($challengeJson, $redirectJson) {
    echo '<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title>Проверка... Подождите</title>
    <style>
        html, body { width: 100%; height: 100%; margin: 0; padding: 0; background: #ffffff; color: #000; font-family: -apple-system, system-ui, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; font-size: 17px; display: flex; align-items: center; justify-content: center; text-align: center; }
        .container { max-width: 540px; padding: 40px 24px; }
        .cf-logo { width: 360px; max-width: 90vw; margin-bottom: 48px; }
        h1 { font-size: 34px; font-weight: 500; margin: 0 0 16px; color: #000; }
        .subtitle { font-size: 20px; color: #222; margin: 0 0 40px; }
        .cf-spinner { position: relative; width: 80px; height: 80px; margin: 0 auto 32px; }
        .cf-spinner::before, .cf-spinner::after { content: ""; position: absolute; top: 0; left: 0; width: 100%; height: 100%; border-radius: 50%; border: 6px solid transparent; }
        .cf-spinner::before { border-top-color: #f38020; animation: spin 1.2s linear infinite; }
        .cf-spinner::after { border-top-color: #e04e2a; animation: spin 1.5s linear infinite reverse; }
        @keyframes spin { to { transform: rotate(360deg); } }
        .progress-container { margin: 24px 0; }
        .progress-bar { width: 100%; height: 8px; background: #e5e5e5; border-radius: 4px; overflow: hidden; }
        .progress-fill { height: 100%; background: linear-gradient(90deg, #f38020, #e04e2a); width: 0%; transition: width 0.3s ease; }
        .status { font-size: 18px; color: #444; margin-top: 16px; min-height: 24px; }
        .status.success { color: #2e7d32; font-weight: 600; }
        .stats { font-size: 14px; color: #888; margin-top: 12px; font-family: monospace; }
        .error { margin-top: 30px; padding: 20px; background: #fff5f5; border: 1px solid #ffcccc; border-radius: 8px; color: #c00; display: none; text-align: left; font-size: 15px; line-height: 1.5; }
        .error strong { display: block; margin-bottom: 8px; }
        .small { margin-top: 60px; font-size: 13px; color: #999; }
        .small a { color: #f38020; text-decoration: none; }
        .checkmark { display: none; width: 80px; height: 80px; margin: 0 auto 32px; }
        .checkmark.show { display: block; animation: scaleIn 0.3s ease; }
        @keyframes scaleIn { from { transform: scale(0); } to { transform: scale(1); } }
        .checkmark circle { fill: #2e7d32; }
        .checkmark path { stroke: #fff; stroke-width: 3; stroke-linecap: round; stroke-linejoin: round; stroke-dasharray: 24; stroke-dashoffset: 24; animation: draw 0.4s ease 0.2s forwards; }
        @keyframes draw { to { stroke-dashoffset: 0; } }
    </style>
</head>
<body>

<div class="container">
    <img src="https://www.cloudflare.com/img/logo-cloudflare-dark.svg" alt="Security Check" class="cf-logo" onerror="this.style.display=\'none\'">
    <h1 id="title">Проверка...</h1>
    <p class="subtitle" id="subtitle">Проверяем ваш браузер перед входом на сайт</p>
    
    <div class="cf-spinner" id="spinner"></div>
    <svg class="checkmark" id="checkmark" viewBox="0 0 80 80">
        <circle cx="40" cy="40" r="38"/>
        <path d="M24 42 L35 53 L56 28" fill="none"/>
    </svg>
    
    <div class="progress-container">
        <div class="progress-bar">
            <div class="progress-fill" id="progress"></div>
        </div>
    </div>
    <div class="status" id="status">Инициализация защиты...</div>
    <div class="stats" id="stats"></div>
    
    <div class="error" id="error"></div>
    <div class="small">Powered by <a href="#">MurKir Security</a> | Proof-of-Work Protection</div>
</div>

<script>
    var challengeData = ' . $challengeJson . ';
    var redirectUrl = ' . $redirectJson . ';
    
    var progressBar = document.getElementById("progress");
    var statusEl = document.getElementById("status");
    var statsEl = document.getElementById("stats");
    var errorEl = document.getElementById("error");
    var spinnerEl = document.getElementById("spinner");
    var checkmarkEl = document.getElementById("checkmark");
    var titleEl = document.getElementById("title");
    var subtitleEl = document.getElementById("subtitle");
    
    // v3.8.6: Флаг завершення перевірки
    var challengeComplete = false;
    var challengeStarted = false;

    function updateProgress(percent, message) {
        progressBar.style.width = percent + "%";
        statusEl.textContent = message;
    }

    function showError(msg) {
        // v3.8.8: Автоматичне оновлення сторінки при "Challenge expired"
        if (msg && msg.toLowerCase().indexOf("expired") !== -1) {
            errorEl.innerHTML = "<strong>⏰ Время проверки истекло</strong><br>Страница автоматически обновится через 3 секунды...";
            errorEl.style.display = "block";
            spinnerEl.style.display = "none";
            statusEl.textContent = "Обновление страницы...";
            statsEl.textContent = "";
            setTimeout(function() {
                location.reload();
            }, 3000);
            return;
        }
        errorEl.innerHTML = "<strong>⚠️ Ошибка проверки</strong>" + msg;
        errorEl.style.display = "block";
        spinnerEl.style.display = "none";
        statusEl.textContent = "Проверка не пройдена";
        statsEl.textContent = "";
    }
    
    function showSuccess() {
        spinnerEl.style.display = "none";
        checkmarkEl.classList.add("show");
        titleEl.textContent = "Проверка пройдена!";
        subtitleEl.textContent = "Перенаправление на сайт...";
        statusEl.className = "status success";
    }

    // SHA-256 hash function
    async function sha256(str) {
        var buf = new TextEncoder().encode(str);
        var hash = await crypto.subtle.digest("SHA-256", buf);
        return Array.from(new Uint8Array(hash)).map(function(b) {
            return b.toString(16).padStart(2, "0");
        }).join("");
    }
    
    // Перевірка cookies
    function areCookiesEnabled() {
        try {
            document.cookie = "cookietest=1; SameSite=Lax";
            var result = document.cookie.indexOf("cookietest=") !== -1;
            document.cookie = "cookietest=1; expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=Lax";
            return result;
        } catch (e) {
            return false;
        }
    }
    
    // Перевірка захисту від циклу
    function checkLoopProtection() {
        try {
            var key = "pow_attempts_" + challengeData.id.substr(0, 8);
            var attempts = parseInt(sessionStorage.getItem(key) || "0", 10);
            if (attempts >= 5) return false;
            sessionStorage.setItem(key, (attempts + 1).toString());
            return true;
        } catch (e) {
            return true;
        }
    }

    // v3.8.9: Перевірка підтримки crypto.subtle (потребує HTTPS!)
    function isCryptoSupported() {
        try {
            return !!(window.crypto && window.crypto.subtle && window.crypto.subtle.digest);
        } catch (e) {
            return false;
        }
    }

    async function performChallenge() {
        // Запобігаємо повторному запуску
        if (challengeStarted || challengeComplete) return;
        challengeStarted = true;
        
        try {
            updateProgress(5, "Анализ окружения...");
            await new Promise(function(r) { setTimeout(r, 400); });
            
            // Перевірка циклу
            if (!checkLoopProtection()) {
                showError("<br>Обнаружен цикл проверки. Пожалуйста, очистите cookies браузера и обновите страницу.");
                return;
            }
            
            // Перевірка cookies
            updateProgress(10, "Проверка cookies...");
            await new Promise(function(r) { setTimeout(r, 300); });
            
            if (!areCookiesEnabled()) {
                showError("<br>Для прохождения проверки необходимо включить cookies в вашем браузере.");
                return;
            }
            
            // v3.8.9: Вибір методу challenge (PoW або fallback sum)
            var usePow = isCryptoSupported();
            
            if (usePow) {
                updateProgress(15, "Вычисление токена безопасности...");
                
                var nonce = 0;
                var hash = "";
                var target = challengeData.target || "0".repeat(challengeData.difficulty || 4);
                var startTime = Date.now();
                var timeout = (challengeData.timeout || 60) * 1000;
                var hashesPerUpdate = 1000;
                
                while (true) {
                    // v3.8.6: Перевірка чи вкладка активна
                    if (document.hidden) {
                        await new Promise(function(r) { setTimeout(r, 100); });
                        startTime += 100;
                        continue;
                    }
                    
                    hash = await sha256(challengeData.id + nonce);
                    
                    if (hash.startsWith(target)) {
                        break;
                    }
                    
                    nonce++;
                    
                    if (nonce % hashesPerUpdate === 0) {
                        var elapsed = Date.now() - startTime;
                        var hashRate = Math.round(nonce / (elapsed / 1000));
                        var progress = Math.min(85, 15 + (elapsed / timeout) * 70);
                        updateProgress(progress, "Вычисление токена безопасности...");
                        statsEl.textContent = nonce.toLocaleString() + " хешей | " + hashRate.toLocaleString() + " H/s";
                        
                        if (elapsed > timeout) {
                            showError("<br>Время проверки истекло. Пожалуйста, обновите страницу и попробуйте снова.");
                            return;
                        }
                        
                        await new Promise(function(r) { setTimeout(r, 0); });
                    }
                }
                
                var totalTime = ((Date.now() - startTime) / 1000).toFixed(2);
                statsEl.textContent = nonce.toLocaleString() + " хешей за " + totalTime + " сек";
                
                updateProgress(90, "Верификация результата...");
                
                // Відправка PoW на сервер
                sendResult({
                    challenge_id: challengeData.id,
                    nonce: nonce,
                    hash: hash,
                    timestamp: challengeData.timestamp,
                    type: "pow"
                });
                
            } else {
                updateProgress(15, "Вычисление результата...");
                statsEl.textContent = "Режим совместимости (без PoW)";
                
                // Отримуємо fallback дані
                var fb = challengeData.fallback;
                if (!fb || !fb.numbers) {
                    showError("<br>Ошибка: данные проверки недоступны");
                    return;
                }
                
                await new Promise(function(r) { setTimeout(r, 500); });
                updateProgress(50, "Обработка данных...");
                
                // Обчислюємо суму
                var sum = 0;
                for (var i = 0; i < fb.numbers.length; i++) {
                    sum += fb.numbers[i];
                }
                
                await new Promise(function(r) { setTimeout(r, 500); });
                updateProgress(90, "Верификация результата...");
                
                // Відправка суми на сервер
                sendResult({
                    challenge_id: challengeData.id,
                    answer: sum,
                    timestamp: challengeData.timestamp,
                    type: "sum"
                });
            }
            
        } catch (error) {
            showError("<br>Не удалось пройти проверку: " + error.message);
        }
    }
    
    // v3.8.9: Універсальна функція відправки результату
    function sendResult(data) {
        var xhr = new XMLHttpRequest();
        xhr.open("POST", window.location.href, true);
        xhr.setRequestHeader("Content-Type", "application/json");
        xhr.setRequestHeader("X-JSC-Response", "1");
        
        xhr.onload = function() {
            if (xhr.status === 200) {
                try {
                    var result = JSON.parse(xhr.responseText);
                    if (result.success) {
                        challengeComplete = true;
                        updateProgress(100, "Проверка завершена!");
                        showSuccess();
                        
                        try {
                            sessionStorage.removeItem("pow_attempts_" + challengeData.id.substr(0, 8));
                        } catch (e) {}
                        
                        setTimeout(function() {
                            window.location.href = redirectUrl;
                        }, 800);
                    } else {
                        showError("<br>" + (result.error || "Ошибка верификации"));
                    }
                } catch (e) {
                    showError("<br>Некорректный ответ сервера");
                }
            } else {
                showError("<br>HTTP ошибка: " + xhr.status);
            }
        };
        
        xhr.onerror = function() {
            showError("<br>Сетевая ошибка. Проверьте подключение к интернету.");
        };
        
        xhr.send(JSON.stringify(data));
    }

    // v3.8.6: Перезавантаження сторінки при активації вкладки
    document.addEventListener("visibilitychange", function() {
        if (document.visibilityState === "visible" && !challengeComplete && !challengeStarted) {
            // Вкладка стала активною і перевірка ще не почалась - запускаємо
            setTimeout(performChallenge, 300);
        } else if (document.visibilityState === "visible" && !challengeComplete && challengeStarted) {
            // Перевірка вже почалась але не завершена - перезавантажуємо
            // (можливо timeout вже спрацював або щось пішло не так)
            setTimeout(function() {
                if (!challengeComplete) {
                    location.reload();
                }
            }, 1000);
        }
    });

    window.addEventListener("load", function() {
        // Запускаємо тільки якщо вкладка активна
        if (!document.hidden) {
            setTimeout(performChallenge, 500);
        }
        // Якщо вкладка неактивна - visibilitychange handler запустить пізніше
    });
</script>
</body>
</html>';
}

/**
 * v3.8.6: SMF-style Challenge сторінка (оригінальний стиль з PoW підтримкою)
 */
function _jsc_showSMFChallengePage($challengeJson, $redirectJson, $isPow = false) {
    echo '<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title>Проверка безопасности</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: Verdana, Arial, sans-serif;
            font-size: 13px;
            background: #e5e5e8;
            color: #000;
            padding: 20px;
        }
        #wrapper {
            max-width: 900px;
            margin: 0 auto;
            background: #fff;
            border: 1px solid #bbb;
        }
        #header {
            background: linear-gradient(to bottom, #315d7d 0%, #1e5380 100%);
            padding: 20px;
            border-bottom: 1px solid #144063;
        }
        #header h1 {
            color: #fff;
            font-size: 22px;
            font-weight: normal;
            text-shadow: 1px 1px 2px rgba(0,0,0,0.3);
            margin: 0;
        }
        #content {
            padding: 30px;
            background: #fff;
        }
        .catbg {
            background: linear-gradient(to bottom, #ffffff 0%, #e0e0e0 100%);
            border: 1px solid #ccc;
            border-bottom: 1px solid #aaa;
            padding: 10px;
            font-weight: bold;
            color: #444;
            margin-bottom: 15px;
        }
        .windowbg {
            background: #f0f0f0;
            border: 1px solid #ccc;
            padding: 25px;
            margin-bottom: 15px;
        }
        .spinner {
            width: 40px;
            height: 40px;
            border: 4px solid #e5e5e8;
            border-top: 4px solid #1e5380;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .info-text {
            text-align: center;
            color: #444;
            line-height: 1.6;
            margin: 15px 0;
        }
        .progress-bar {
            width: 100%;
            height: 24px;
            background: #fff;
            border: 1px solid #bbb;
            border-radius: 3px;
            overflow: hidden;
            margin: 20px 0;
            box-shadow: inset 0 1px 3px rgba(0,0,0,0.1);
        }
        .progress-fill {
            height: 100%;
            background: linear-gradient(to bottom, #7db8e5 0%, #4e9bd6 100%);
            width: 0%;
            transition: width 0.3s ease;
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.4);
        }
        .status {
            text-align: center;
            color: #666;
            font-size: 12px;
            margin-top: 15px;
            font-style: italic;
        }
        .stats {
            text-align: center;
            color: #888;
            font-size: 11px;
            margin-top: 10px;
            font-family: monospace;
        }
        .error {
            background: #fff0f0;
            border: 1px solid #cc3300;
            color: #cc3300;
            padding: 15px;
            border-radius: 3px;
            margin-top: 15px;
            display: none;
        }
        .success { color: #080; }
        .smalltext {
            font-size: 11px;
            color: #777;
            text-align: center;
            margin-top: 20px;
            padding-top: 15px;
            border-top: 1px solid #ddd;
        }
        #footer {
            background: #e5e5e8;
            padding: 15px;
            text-align: center;
            font-size: 11px;
            color: #666;
            border-top: 1px solid #bbb;
        }
    </style>
</head>
<body>
    <div id="wrapper">
        <div id="header">
            <h1>🛡️ Система безопасности</h1>
        </div>
        <div id="content">
            <div class="catbg">
                Проверка безопасности' . ($isPow ? ' (Proof-of-Work)' : '') . '
            </div>
            <div class="windowbg">
                <div class="spinner" id="spinner"></div>
                <div class="info-text">
                    <strong>Пожалуйста, подождите...</strong><br>
                    Выполняется автоматическая проверка вашего браузера для защиты от автоматизированных запросов.
                </div>
                <div class="progress-bar">
                    <div class="progress-fill" id="progress"></div>
                </div>
                <div class="status" id="status">Инициализация проверки...</div>
                <div class="stats" id="stats"></div>
                <div class="error" id="error"></div>
                <div class="smalltext">
                    Эта проверка обычно занимает несколько секунд.<br>
                    Не закрывайте это окно до завершения проверки.
                </div>
            </div>
        </div>
        <div id="footer">
            Powered by MurKir Security | SMF-Style Interface
        </div>
    </div>
    <script>
        var challengeData = ' . $challengeJson . ';
        var redirectUrl = ' . $redirectJson . ';
        var progressBar = document.getElementById("progress");
        var statusEl = document.getElementById("status");
        var statsEl = document.getElementById("stats");
        var errorEl = document.getElementById("error");
        
        // v3.8.6: Флаги стану
        var challengeComplete = false;
        var challengeStarted = false;
        
        function updateProgress(percent, message) {
            progressBar.style.width = percent + "%";
            statusEl.textContent = message;
        }
        
        function showError(message) {
            // v3.8.8: Автоматичне оновлення сторінки при "Challenge expired"
            if (message && message.toLowerCase().indexOf("expired") !== -1) {
                errorEl.innerHTML = "⏰ Время проверки истекло<br>Страница автоматически обновится через 3 секунды...";
                errorEl.style.display = "block";
                statusEl.textContent = "Обновление страницы...";
                document.getElementById("spinner").style.display = "none";
                setTimeout(function() {
                    location.reload();
                }, 3000);
                return;
            }
            errorEl.innerHTML = message;
            errorEl.style.display = "block";
            statusEl.textContent = "Ошибка проверки";
            document.getElementById("spinner").style.display = "none";
        }
        
        function sleep(ms) {
            return new Promise(function(resolve) { setTimeout(resolve, ms); });
        }
        
        function areCookiesEnabled() {
            try {
                document.cookie = "cookietest=1; SameSite=Lax";
                var result = document.cookie.indexOf("cookietest=") !== -1;
                document.cookie = "cookietest=1; expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=Lax";
                return result;
            } catch (e) {
                return false;
            }
        }
        
        function checkLoopProtection() {
            try {
                var key = "jsc_attempts_" + challengeData.id.substr(0, 8);
                var attempts = parseInt(sessionStorage.getItem(key) || "0", 10);
                if (attempts >= 5) return false;
                sessionStorage.setItem(key, (attempts + 1).toString());
                return true;
            } catch (e) {
                var url = new URL(window.location.href);
                var attempts = parseInt(url.searchParams.get("_jsc_retry") || "0", 10);
                return attempts < 5;
            }
        }
        
        // SHA-256 for PoW
        async function sha256(str) {
            var buf = new TextEncoder().encode(str);
            var hash = await crypto.subtle.digest("SHA-256", buf);
            return Array.from(new Uint8Array(hash)).map(function(b) {
                return b.toString(16).padStart(2, "0");
            }).join("");
        }
        
        // v3.8.9: Перевірка підтримки crypto.subtle
        function isCryptoSupported() {
            try {
                return !!(window.crypto && window.crypto.subtle && window.crypto.subtle.digest);
            } catch (e) {
                return false;
            }
        }
        
        async function performChallenge() {
            // v3.8.6: Запобігаємо повторному запуску
            if (challengeStarted || challengeComplete) return;
            challengeStarted = true;
            
            try {
                updateProgress(10, "Проверка браузера...");
                await sleep(300);
                
                if (!checkLoopProtection()) {
                    showError("<strong>🔄 Обнаружен цикл проверки</strong><br><br>" +
                        "Пожалуйста, очистите cookies браузера и обновите страницу (F5)");
                    return;
                }
                
                updateProgress(20, "Проверка JavaScript...");
                await sleep(300);
                
                updateProgress(30, "Проверка cookies...");
                await sleep(300);
                
                if (!areCookiesEnabled()) {
                    showError("<strong>⚠️ Cookies отключены</strong><br><br>" +
                        "Для прохождения проверки необходимо включить cookies в вашем браузере.");
                    return;
                }
                
                var answer, nonce, hash;
                var wantsPow = challengeData.type === "pow";
                // v3.8.9: Перевіряємо чи браузер підтримує PoW
                var canDoPow = wantsPow && isCryptoSupported();
                var isPow = canDoPow;
                
                if (canDoPow) {
                    // Proof of Work
                    updateProgress(40, "Вычисление токена безопасности...");
                    
                    nonce = 0;
                    var target = challengeData.target || "0".repeat(challengeData.difficulty || 4);
                    var startTime = Date.now();
                    var timeout = (challengeData.timeout || 60) * 1000;
                    
                    while (true) {
                        // v3.8.6: Перевірка чи вкладка активна
                        if (document.hidden) {
                            await sleep(100);
                            startTime += 100; // Не рахуємо час коли вкладка неактивна
                            continue;
                        }
                        
                        hash = await sha256(challengeData.id + nonce);
                        if (hash.startsWith(target)) break;
                        nonce++;
                        
                        if (nonce % 500 === 0) {
                            var elapsed = Date.now() - startTime;
                            var hashRate = Math.round(nonce / (elapsed / 1000));
                            var progress = Math.min(85, 40 + (elapsed / timeout) * 45);
                            updateProgress(progress, "Вычисление токена безопасности...");
                            statsEl.textContent = nonce.toLocaleString() + " хешей | " + hashRate.toLocaleString() + " H/s";
                            
                            if (elapsed > timeout) {
                                showError("<strong>⏱️ Время истекло</strong><br><br>Пожалуйста, обновите страницу.");
                                return;
                            }
                            await sleep(0);
                        }
                    }
                    
                    var totalTime = ((Date.now() - startTime) / 1000).toFixed(2);
                    statsEl.textContent = nonce.toLocaleString() + " хешей за " + totalTime + " сек";
                } else if (wantsPow && challengeData.fallback) {
                    // v3.8.9: Fallback - використовуємо sum challenge замість PoW
                    updateProgress(60, "Режим совместимости...");
                    statsEl.textContent = "Ваш браузер не поддерживает PoW";
                    var fb = challengeData.fallback;
                    answer = fb.numbers.reduce(function(sum, num) { return sum + num; }, 0);
                    isPow = false;
                } else {
                    // Sum challenge (legacy)
                    updateProgress(60, "Вычисление задачи...");
                    answer = challengeData.numbers.reduce(function(sum, num) { return sum + num; }, 0);
                }
                
                updateProgress(90, "Отправка решения...");
                
                var xhr = new XMLHttpRequest();
                xhr.open("POST", window.location.href, true);
                xhr.setRequestHeader("Content-Type", "application/json");
                xhr.setRequestHeader("X-JSC-Response", "1");
                
                xhr.onload = function() {
                    if (xhr.status === 200) {
                        try {
                            var result = JSON.parse(xhr.responseText);
                            if (result.success) {
                                // v3.8.6: Позначаємо що перевірка завершена
                                challengeComplete = true;
                                
                                updateProgress(100, "Проверка завершена!");
                                statusEl.className = "status success";
                                document.getElementById("spinner").style.display = "none";
                                
                                try {
                                    var key = (isPow ? "pow_attempts_" : "jsc_attempts_") + challengeData.id.substr(0, 8);
                                    sessionStorage.removeItem(key);
                                } catch (e) {}
                                
                                setTimeout(function() {
                                    window.location.href = redirectUrl;
                                }, 500);
                            } else {
                                showError(result.error || "Verification failed");
                            }
                        } catch (e) {
                            showError("Invalid response");
                        }
                    } else {
                        showError("HTTP " + xhr.status);
                    }
                };
                
                xhr.onerror = function() {
                    showError("Network error");
                };
                
                var payload = {
                    challenge_id: challengeData.id,
                    timestamp: challengeData.timestamp,
                    type: isPow ? "pow" : "sum"
                };
                
                if (isPow) {
                    payload.nonce = nonce;
                    payload.hash = hash;
                } else {
                    payload.answer = answer;
                }
                
                xhr.send(JSON.stringify(payload));
                
            } catch (error) {
                showError("Не удалось пройти проверку. Обновите страницу.");
            }
        }
        
        // v3.8.6: Перезавантаження сторінки при активації вкладки
        document.addEventListener("visibilitychange", function() {
            if (document.visibilityState === "visible" && !challengeComplete && !challengeStarted) {
                // Вкладка стала активною і перевірка ще не почалась
                setTimeout(performChallenge, 300);
            } else if (document.visibilityState === "visible" && !challengeComplete && challengeStarted) {
                // Перевірка вже почалась але не завершена - перезавантажуємо
                setTimeout(function() {
                    if (!challengeComplete) {
                        location.reload();
                    }
                }, 1000);
            }
        });
        
        window.addEventListener("load", function() {
            // Запускаємо тільки якщо вкладка активна
            if (!document.hidden) {
                setTimeout(performChallenge, 1000);
            }
        });
    </script>
</body>
</html>';
}

// ОБРОБКА POST ЗАПИТУ JS CHALLENGE
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_SERVER['HTTP_X_JSC_RESPONSE'])) {
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-cache, no-store');
    
    // Обмеження розміру вхідних даних (макс 4KB)
    $rawInput = file_get_contents('php://input');
    if (strlen($rawInput) > 4096) {
        echo json_encode(array('success' => false, 'error' => 'Request too large'));
        exit;
    }
    
    $input = json_decode($rawInput, true);
    
    if (!$input || !is_array($input) || !isset($input['challenge_id']) || !isset($input['timestamp'])) {
        echo json_encode(array('success' => false, 'error' => 'Invalid request'));
        exit;
    }
    
    // Валідація challenge_id (має бути hex рядок 32 символи)
    $challengeId = isset($input['challenge_id']) ? $input['challenge_id'] : '';
    if (!preg_match('/^[a-f0-9]{32}$/', $challengeId)) {
        echo json_encode(array('success' => false, 'error' => 'Invalid challenge ID'));
        exit;
    }
    
    $timestamp = (int)$input['timestamp'];
    
    // Валідація timestamp (не в майбутньому, не занадто старий)
    $now = time();
    if ($timestamp > $now + 60 || $timestamp < $now - 600) {
        echo json_encode(array('success' => false, 'error' => 'Invalid timestamp'));
        exit;
    }
    
    // Валідація type
    $challengeType = isset($input['type']) ? $input['type'] : 'sum';
    if (!in_array($challengeType, array('pow', 'sum'), true)) {
        $challengeType = 'sum';
    }
    
    // v3.8.0: Різний timeout для PoW та звичайного challenge
    $maxAge = ($challengeType === 'pow') ? 120 : 300;
    
    if ($now - $timestamp > $maxAge) {
        echo json_encode(array('success' => false, 'error' => 'Challenge expired'));
        exit;
    }
    
    // v3.8.0: Proof of Work верифікація
    if ($challengeType === 'pow') {
        if (!isset($input['nonce']) || !isset($input['hash'])) {
            echo json_encode(array('success' => false, 'error' => 'Missing PoW data'));
            exit;
        }
        
        // Валідація nonce (має бути число в розумних межах)
        $nonce = $input['nonce'];
        if (!is_numeric($nonce) || $nonce < 0 || $nonce > 4294967295) {
            echo json_encode(array('success' => false, 'error' => 'Invalid nonce'));
            exit;
        }
        $nonce = (int)$nonce;
        
        // Валідація hash (має бути sha256 hex - 64 символи)
        $clientHash = isset($input['hash']) ? $input['hash'] : '';
        if (!preg_match('/^[a-f0-9]{64}$/', $clientHash)) {
            echo json_encode(array('success' => false, 'error' => 'Invalid hash format'));
            exit;
        }
        
        $difficulty = isset($_JSC_CONFIG['pow_difficulty']) ? (int)$_JSC_CONFIG['pow_difficulty'] : 4;
        
        // Серверна верифікація PoW
        $serverHash = hash('sha256', $challengeId . $nonce);
        $target = str_repeat('0', $difficulty);
        
        if (!hash_equals($serverHash, $clientHash)) {
            _jsc_logStats('failed', _jsc_getClientIP());
            echo json_encode(array('success' => false, 'error' => 'Hash mismatch'));
            exit;
        }
        
        if (strpos($serverHash, $target) !== 0) {
            _jsc_logStats('failed', _jsc_getClientIP());
            echo json_encode(array('success' => false, 'error' => 'Invalid PoW solution'));
            exit;
        }
    } else {
        // Legacy: перевірка суми (для зворотної сумісності)
        if (!isset($input['answer'])) {
            _jsc_logStats('failed', _jsc_getClientIP());
            echo json_encode(array('success' => false, 'error' => 'Missing answer'));
            exit;
        }
    }
    
    // v3.8.1: Логуємо успішне проходження challenge (для ВСІХ типів)
    _jsc_logStats('passed', _jsc_getClientIP());
    
    $ip = _jsc_getClientIP();
    $token = hash('sha256', $ip . date('Y-m-d') . $_JSC_CONFIG['secret_key']);
    
    $secure = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
    $lifetime = $_JSC_CONFIG['token_lifetime'];
    $cookie_name = $_JSC_CONFIG['cookie_name'];
    
    if (PHP_VERSION_ID >= 70300) {
        setcookie($cookie_name, $token, [
            'expires' => time() + $lifetime,
            'path' => '/',
            'secure' => $secure,
            'httponly' => true,
            'samesite' => 'Lax'
        ]);
    } else {
        setcookie($cookie_name, $token, time() + $lifetime, '/', '', $secure, true);
    }
    
    echo json_encode(array('success' => true, 'token' => $token));
    exit;
}

// ШВИДКА ПЕРЕВІРКА БЛОКУВАННЯ

function _quick_block_check() {
    try {
        $redis = new Redis();
        $redis->connect('127.0.0.1', 6379, 1);
        $redis->select(1);
        
        $ip = _jsc_getClientIP();
        $prefix = 'bot_protection:';
        
        // v3.8.7: Перевірка hammer block
        if ($redis->exists($prefix . 'blocked:hammer:' . $ip)) {
            return true;
        }
        
        if ($redis->exists($prefix . 'ua_blocked:' . $ip)) {
            return true;
        }
        
        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
        $lang = isset($_SERVER['HTTP_ACCEPT_LANGUAGE']) ? $_SERVER['HTTP_ACCEPT_LANGUAGE'] : '';
        $browserHash = hash('sha256', $ua . '|' . $lang);
        
        $cookieName = 'bot_protection_uid';
        $cookieId = isset($_COOKIE[$cookieName]) ? $_COOKIE[$cookieName] : '';
        
        if (!empty($cookieId)) {
            $userId = $cookieId . '_' . substr($browserHash, 0, 16);
        } else {
            $userId = $ip . '_' . substr($browserHash, 0, 16);
        }
        
        if ($redis->exists($prefix . 'blocked:' . hash('md5', $userId))) {
            return true;
        }
        
        $redis->close();
        return false;
        
    } catch (Exception $e) {
        return false;
    }
}

function _show_502_error() {
    // v3.8.7: Відстеження hammer атак на 502 page
    $ip = _jsc_getClientIP();
    _track_page_hammer($ip, 'blocked');
    
    http_response_code(502);
    header('Content-Type: text/html; charset=UTF-8');
    header('Cache-Control: no-cache, no-store');
    
    echo '<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title>502 Bad Gateway</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: Verdana, Arial, sans-serif;
            font-size: 13px;
            background: #e5e5e8;
            color: #000;
            padding: 20px;
        }
        #wrapper {
            max-width: 900px;
            margin: 0 auto;
            background: #fff;
            border: 1px solid #bbb;
        }
        #header {
            background: linear-gradient(to bottom, #7d3131 0%, #803e1e 100%);
            padding: 20px;
            border-bottom: 1px solid #631414;
        }
        #header h1 {
            color: #fff;
            font-size: 22px;
            font-weight: normal;
            text-shadow: 1px 1px 2px rgba(0,0,0,0.3);
            margin: 0;
        }
        #content {
            padding: 30px;
            background: #fff;
        }
        .catbg {
            background: linear-gradient(to bottom, #ffffff 0%, #ffe0e0 100%);
            border: 1px solid #cc9999;
            border-bottom: 1px solid #aa7777;
            padding: 10px;
            font-weight: bold;
            color: #880000;
            margin-bottom: 15px;
        }
        .windowbg {
            background: #fff5f5;
            border: 1px solid #cc9999;
            padding: 25px;
            margin-bottom: 15px;
        }
        .error-icon {
            text-align: center;
            font-size: 48px;
            margin-bottom: 20px;
            color: #cc3300;
        }
        .error-code {
            text-align: center;
            font-size: 18px;
            font-weight: bold;
            color: #cc3300;
            margin-bottom: 15px;
        }
        .info-text {
            color: #444;
            line-height: 1.8;
            margin: 15px 0;
        }
        .info-box {
            background: #f0f0f0;
            border: 1px solid #ccc;
            padding: 15px;
            margin: 20px 0;
            border-left: 4px solid #cc3300;
        }
        .info-box strong {
            display: block;
            margin-bottom: 10px;
            color: #880000;
        }
        .info-box ul {
            margin-left: 20px;
            color: #666;
        }
        .info-box li {
            margin: 5px 0;
        }
        .button {
            display: inline-block;
            background: linear-gradient(to bottom, #7db8e5 0%, #4e9bd6 100%);
            border: 1px solid #3a7ba8;
            color: #fff;
            padding: 8px 20px;
            text-decoration: none;
            border-radius: 3px;
            font-weight: bold;
            text-shadow: 1px 1px 1px rgba(0,0,0,0.2);
            cursor: pointer;
            margin-top: 15px;
        }
        .button:hover {
            background: linear-gradient(to bottom, #8dc5f0 0%, #5ea8e0 100%);
        }
        .center {
            text-align: center;
        }
        .smalltext {
            font-size: 11px;
            color: #777;
            text-align: center;
            margin-top: 20px;
            padding-top: 15px;
            border-top: 1px solid #ddd;
        }
        #footer {
            background: #e5e5e8;
            padding: 15px;
            text-align: center;
            font-size: 11px;
            color: #666;
            border-top: 1px solid #bbb;
        }
        #countdown {
            font-weight: bold;
            color: #1e5380;
        }
    </style>
</head>
<body>
    <div id="wrapper">
        <div id="header">
            <h1>⚠️ Ошибка сервера</h1>
        </div>
        <div id="content">
            <div class="catbg">
                Ошибка 502 - Bad Gateway
            </div>
            <div class="windowbg">
                <div class="error-icon">⚠</div>
                <div class="error-code">HTTP 502 Bad Gateway</div>
                
                <div class="info-text center">
                    <strong>Сервер временно недоступен</strong><br>
                    К сожалению, в данный момент невозможно обработать ваш запрос.<br>
                    Пожалуйста, попробуйте позже.
                </div>
                
                <div class="info-box">
                    <strong>Возможные причины:</strong>
                    <ul>
                        <li>Сервер перегружен большим количеством запросов</li>
                        <li>Проводятся технические работы</li>
                        <li>Временные проблемы с соединением</li>
                        <li>Перезапуск серверных служб</li>
                    </ul>
                </div>
                
                <div class="center">
                    <a href="javascript:location.reload()" class="button">
                        🔄 Обновить страницу
                    </a>
                </div>
                
                <div class="smalltext">
                    Автоматическое обновление через <span id="countdown">10</span> секунд...<br>
                    Если проблема сохраняется, обратитесь к администратору сайта.
                </div>
            </div>
        </div>
        <div id="footer">
            SMF 2.0.15 | SMF © 2017, Simple Machines | Powered by MurKir Security
        </div>
    </div>
    
    <script>
        var counter = 10;
        var countdownEl = document.getElementById("countdown");
        
        var interval = setInterval(function() {
            counter--;
            if (countdownEl) {
                countdownEl.textContent = counter;
            }
            if (counter <= 0) {
                clearInterval(interval);
                location.reload();
            }
        }, 1000);
    </script>
</body>
</html>';
    exit;
}

if (_quick_block_check()) {
    _show_502_error();
}

// ПЕРЕВІРКА JS CHALLENGE (З ПРІОРИТЕТОМ IP WHITELIST v3.7.0)
if ($_JSC_CONFIG['enabled']) {
    $clientIP = _jsc_getClientIP();  // Додано v3.7.0
    $userAgent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
    $_jsc_skip = false;
    
    // ПРІОРИТЕТ 0: ВСІ БІЛІ СПИСКИ IP (АБСОЛЮТНИЙ ПРІОРИТЕТ!) - v3.8.2
    // Перевіряє: $ADMIN_IP_WHITELIST + $SEARCH_ENGINE_IP_RANGES
    // Ці IP пропускаються БЕЗ БУДЬ-ЯКИХ перевірок!
    $whitelistType = _is_whitelisted_ip($clientIP);
    if ($whitelistType !== false) {
        $_jsc_skip = true;
        // Логування вже зроблено в _is_admin_ip() або _is_search_engine_ip()
    }
    
    // ПРІОРИТЕТ 0.5: ADMIN URL WHITELIST (v3.8.13)
    // URL адмінки та API пропускаються без JS Challenge
    if (!$_jsc_skip && _is_admin_url()) {
        $_jsc_skip = true;
    }
    
    // ПРІОРИТЕТ 1: ВЛАСНІ USER AGENTS
    if (!$_jsc_skip && _is_custom_ua($userAgent)) {
        $_jsc_skip = true;
        // error_log вже зроблено в _is_custom_ua()
    }
    
    // ПРІОРИТЕТ 2: SEO БОТИ (по User-Agent)
    if (!$_jsc_skip && _is_seo_bot($userAgent)) {
        $_jsc_skip = true;
    }
    
    // ПРІОРИТЕТ 3: СТАТИЧНІ ФАЙЛИ ТА AJAX
    if (!$_jsc_skip) {
        $uri = isset($_SERVER['REQUEST_URI']) ? strtolower($_SERVER['REQUEST_URI']) : '';
        $skipExt = array('.js', '.css', '.json', '.xml', '.txt', '.ico', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.woff', '.woff2', '.ttf', '.mp4', '.mp3', '.pdf', '.zip', '.rar');
        
        foreach ($skipExt as $ext) {
            if (strpos($uri, $ext) !== false) {
                $_jsc_skip = true;
                break;
            }
        }
        
        if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
            $_jsc_skip = true;
        }
        
        // v3.8.13: Запити з параметром api=1 (API виклики) теж пропускаємо
        if (!$_jsc_skip && (isset($_GET['api']) && $_GET['api'] == '1')) {
            // Додаткова перевірка: тільки якщо URL в admin whitelist
            if (_is_admin_url()) {
                $_jsc_skip = true;
            }
        }
    }
    
    // ПОКАЗ JS CHALLENGE (тільки для звичайних користувачів)
    // v3.8.12: Підтримка режимів 'always', 'auto', 'never'
    if (!$_jsc_skip && !_jsc_isVerified($_JSC_CONFIG['secret_key'], $_JSC_CONFIG['cookie_name'])) {
        
        $mode = isset($_JSC_CONFIG['mode']) ? $_JSC_CONFIG['mode'] : 'always';
        $showChallenge = false;
        
        switch ($mode) {
            case 'never':
                // Ніколи не показувати Challenge
                $showChallenge = false;
                break;
                
            case 'auto':
                // Показувати тільки при аномальній активності
                $anomaly = _jsc_check_anomaly($clientIP, $userAgent);
                if ($anomaly !== false) {
                    $showChallenge = true;
                }
                break;
                
            case 'always':
            default:
                // Завжди показувати (стара поведінка)
                $showChallenge = true;
                break;
        }
        
        if ($showChallenge) {
            $challenge = _jsc_generateChallenge($_JSC_CONFIG['secret_key']);
            $currentUrl = _jsc_getSafeCurrentUrl();
            _jsc_showChallengePage($challenge, $currentUrl);
        }
    }
}

/**
 * Безпечне отримання поточного URL з валідацією хоста
 */
function _jsc_getSafeCurrentUrl() {
    // Отримуємо хост
    $host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '';
    
    // Видаляємо порт якщо є
    $host = preg_replace('/:\d+$/', '', $host);
    
    // Валідація хоста - тільки дозволені символи (букви, цифри, крапки, дефіси)
    if (!preg_match('/^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$/', $host)) {
        $host = 'localhost';
    }
    
    // Обмеження довжини хоста
    if (strlen($host) > 253) {
        $host = 'localhost';
    }
    
    // Отримуємо URI і очищуємо
    $uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '/';
    
    // Обмеження довжини URI
    if (strlen($uri) > 2048) {
        $uri = substr($uri, 0, 2048);
    }
    
    // Видаляємо небезпечні символи з URI
    $uri = preg_replace('/[\x00-\x1F\x7F]/', '', $uri);
    
    $scheme = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    
    return $scheme . '://' . $host . $uri;
}

// КЛАСС ЗАХИСТУ

class SimpleBotProtection {
    
    private $redis = null;
    private $redisHost = '127.0.0.1';
    private $redisPort = 6379;
    private $redisDB = 1;
    private $redisPassword = '';
    private $redisPrefix = 'bot_protection:';
    private $debugMode = false;
    
    // Налаштування rate limit
    private $rateLimitSettings = array(
        'max_requests_per_minute' => 30,
        'max_requests_per_5min' => 100,
        'max_requests_per_hour' => 500,
        'burst_threshold' => 10,
        'block_duration' => 900,
        'cookie_multiplier' => 2.0,
        'js_verified_multiplier' => 3.0,
    );
    
    // Налаштування UA Rotation
    private $uaRotationSettings = array(
        'enabled' => true,
        'max_unique_ua_per_5min' => 10,
        'max_unique_ua_per_hour' => 20,
        'block_duration' => 7200,
        'tracking_window' => 3600,
    );
    
    // Налаштування API (ініціалізуються з глобального $_API_CONFIG в конструкторі)
    private $apiSettings = array();
    
    // ЗАХИСТ ВІД БОТІВ БЕЗ COOKIES v1.0 (2026-01-15)
    
    /**
     * Налаштування захисту від ботів без cookies
     * 
     * Боти часто НЕ зберігають cookies (bot_protection_uid), навіть якщо
     * пройшли JS Challenge (mk_verified). Це дозволяє виявити їх швидше.
     * 
     * РЕКОМЕНДОВАНІ ЗНАЧЕННЯ:
     * - Малий сайт (легкий трафік): threshold=5, window=60
     * - Середній сайт (рекомендовано): threshold=3, window=30
     * - Під атакою (жорстко): threshold=2, window=20
     */
    
    // Скільки запитів без bot_protection_uid перед блокуванням
    private $noCookieThreshold = 10;
    
    // За який період часу рахувати (секунди)
    private $noCookieTimeWindow = 60;
    
    /**
     * Жорсткі rate limits для користувачів БЕЗ bot_protection_uid cookie
     * 
     * Ці ліміти застосовуються ТІЛЬКИ до користувачів без cookie.
     * Звичайні користувачі з cookie використовують rateLimitSettings.
     */
    private $noCookieRateLimits = array(
        'minute' => 10,      // Замість 20 (звичайний)
        '5min' => 30,        // Замість 100
        'hour' => 200,       // Замість 1000
        'day' => 1000,       // Замість 5000
        'burst' => 5,        // Замість 20 (10 секунд)
    );
    
    /**
     * Перевірка кількості запитів без bot_protection_uid cookie
     * 
     * Виявляє боти які пройшли JS Challenge (мають mk_verified),
     * але НЕ зберігають bot_protection_uid cookie.
     * 
     * @param string $ip IP адреса
     * @return bool true якщо треба блокувати
     */
    private function checkNoCookieAttempts($ip) {
        $key = $this->redisPrefix . 'no_cookie_attempts:' . $ip;
        
        // Отримуємо історію спроб
        $attempts = $this->redis->get($key);
        if (!$attempts || !is_array($attempts)) {
            $attempts = array();
        }
        
        $now = time();
        
        // Фільтруємо старі записи (за межами time window)
        $filtered = array();
        foreach ($attempts as $timestamp) {
            if (($now - $timestamp) < $this->noCookieTimeWindow) {
                $filtered[] = $timestamp;
            }
        }
        
        // Додаємо поточну спробу
        $filtered[] = $now;
        
        // Зберігаємо в Redis з подвійним TTL (щоб не втратити дані)
        $this->redis->setex($key, $this->noCookieTimeWindow * 2, $filtered);
        
        // Перевірка порогу
        $attemptCount = count($filtered);
        
        if ($attemptCount >= $this->noCookieThreshold) {
            error_log(sprintf(
                "NO COOKIE ATTACK DETECTED: IP=%s, attempts=%d in %dsec (threshold=%d)",
                $ip, 
                $attemptCount, 
                $this->noCookieTimeWindow,
                $this->noCookieThreshold
            ));
            
            // Блокуємо в Redis
            $blockKey = $this->redisPrefix . 'blocked:no_cookie:' . $ip;
            $this->redis->setex($blockKey, 3600, array(
                'ip' => $ip,  // Додано для адмінки
                'time' => $now,
                'reason' => 'no_cookie_attack',
                'attempts' => $attemptCount,
                'threshold' => $this->noCookieThreshold,
                'window' => $this->noCookieTimeWindow
            ));
            
            // Блокуємо через API
            if ($this->apiSettings['enabled'] && $this->apiSettings['block_on_api']) {
                $apiResult = $this->callBlockingAPI($ip, 'block');
                
                if ($apiResult['status'] === 'success') {
                    error_log("API BLOCK SUCCESS: IP=$ip (no cookie attack, $attemptCount attempts in {$this->noCookieTimeWindow}sec)");
                } elseif ($apiResult['status'] !== 'already_blocked') {
                    $msg = isset($apiResult['message']) ? $apiResult['message'] : 'unknown';
                    error_log("API BLOCK FAILED: IP=$ip, reason=" . $msg);
                }
            }
            
            return true;
        }
        
        // Логування якщо включено debug режим
        if ($this->debugMode && $attemptCount > 1) {
            error_log(sprintf(
                "NO COOKIE CHECK: IP=%s, attempts=%d/%d in %dsec",
                $ip, 
                $attemptCount, 
                $this->noCookieThreshold,
                $this->noCookieTimeWindow
            ));
        }
        
        return false;
    }
    
    /**
     * Оновити налаштування захисту від ботів без cookies
     * 
     * @param array $settings Нові налаштування
     *                        - threshold: int - кількість спроб
     *                        - time_window: int - період часу в секундах
     *                        - rate_limits: array - власні ліміти
     */
    public function updateNoCookieSettings($settings) {
        if (isset($settings['threshold'])) {
            $this->noCookieThreshold = max(1, (int)$settings['threshold']);
        }
        if (isset($settings['time_window'])) {
            $this->noCookieTimeWindow = max(10, (int)$settings['time_window']);
        }
        if (isset($settings['rate_limits']) && is_array($settings['rate_limits'])) {
            $this->noCookieRateLimits = array_merge(
                $this->noCookieRateLimits, 
                $settings['rate_limits']
            );
        }
    }
    
    // Налаштування rDNS
    private $rdnsSettings = array(
        'enabled' => true,
        'cache_ttl' => 3600,
        'rate_limit_per_minute' => 10,
        'rdns_on_limit_action' => 'skip',
    );
    
    private $rdnsPrefix = 'rdns:';
    
    // Налаштування логування SEO ботів
    private $searchLogSettings = array(
        'enabled' => true,
        'file' => '/var/log/search_engines.log',
        'max_size' => 1048576,
        'keep_backups' => 3,
        'log_host' => true,
        'log_url' => true,
        'log_ua' => true,
        'ua_max_length' => 100,
        // v3.7.0: Redis статистика
        'redis_stats' => true,           // Зберігати статистику в Redis
        'redis_log_max' => 500,          // Максимум записів в логу Redis
        'redis_stats_ttl' => 86400 * 30, // TTL для статистики (30 днів)
    );
    
    // РОЗШИРЕНИЙ WHITELIST ПОШУКОВИХ СИСТЕМ (SEO v3.6.0)
    
    private $searchEngines = array(
        // GOOGLE
        'google' => array(
            'user_agent_patterns' => array(
                'google-read-aloud', 'googlebot', 'google-inspectiontool', 'adsbot-google', 
                'apis-google', 'mediapartners-google', 'googleother',
                'google-site-verification', 'googlebot-image', 'googlebot-news',
                'googlebot-video', 'google-structured-data'
            ),
            'rdns_patterns' => array('.googlebot.com', '.google.com'),
            'skip_forward_verification' => false,
            'ip_ranges' => array(
                '66.249.64.0/19', '64.233.160.0/19', '72.14.192.0/18',
                '203.208.32.0/19', '74.125.0.0/16', '216.239.32.0/19',
                '2001:4860::/32',
            )
        ),
        
        // YANDEX
        'yandex' => array(
            'user_agent_patterns' => array(
                'yandex', 'yandexbot', 'yandexmetrika', 'yandexwebmaster',
                'yandexdirect', 'yandexmobilebot', 'yandeximages'
            ),
            'rdns_patterns' => array('.yandex.ru', '.yandex.net', '.yandex.com'),
            'skip_forward_verification' => false,
            'ip_ranges' => array(
                '5.45.192.0/18', '5.255.192.0/18', '37.9.64.0/18',
                '37.140.128.0/18', '77.88.0.0/16', '87.250.224.0/19',
                '93.158.128.0/18', '95.108.128.0/17', '100.43.64.0/19',
                '141.8.128.0/18', '178.154.128.0/17', '213.180.192.0/19',
                '2a02:6b8::/32',
            )
        ),
        
        // BING/MICROSOFT
        'bing' => array(
            'user_agent_patterns' => array('bingbot', 'bingpreview', 'msnbot', 'adidxbot'),
            'rdns_patterns' => array('.search.msn.com'),
            'skip_forward_verification' => false,
            'ip_ranges' => array(
                '13.66.0.0/16', '13.67.0.0/16', '13.68.0.0/16',
                '40.76.0.0/14', '157.55.0.0/16', '199.30.16.0/20',
                '207.46.0.0/16', '2620:1ec:c::0/40',
            )
        ),
        
        // BAIDU
        'baidu' => array(
            'user_agent_patterns' => array('baiduspider', 'baidu'),
            'rdns_patterns' => array('.crawl.baidu.com', '.baidu.com'),
            'skip_forward_verification' => false,
            'ip_ranges' => array(
                '116.179.0.0/16', '119.63.192.0/21', '123.125.71.0/24', 
                '180.76.0.0/16', '220.181.0.0/16',
            )
        ),
        
        // DUCKDUCKGO
        'duckduckgo' => array(
            'user_agent_patterns' => array('duckduckbot', 'duckduckgo'),
            'rdns_patterns' => array('.duckduckgo.com'),
            'skip_forward_verification' => true,
            'ip_ranges' => array(
                '20.191.45.212/32', '40.88.21.235/32', '52.142.26.175/32',
                '52.142.24.149/32', '72.94.249.34/32', '72.94.249.35/32',
            )
        ),
        
        // YAHOO
        'yahoo' => array(
            'user_agent_patterns' => array('slurp', 'yahoo'),
            'rdns_patterns' => array('.crawl.yahoo.net'),
            'skip_forward_verification' => false,
            'ip_ranges' => array(
                '67.195.0.0/16', '74.6.0.0/16', '98.136.0.0/14',
                '202.160.176.0/20', '209.191.64.0/18',
            )
        ),
        
        // SEZNAM (Czech)
        'seznam' => array(
            'user_agent_patterns' => array('seznambot', 'seznam'),
            'rdns_patterns' => array('.seznam.cz'),
            'skip_forward_verification' => true,
            'ip_ranges' => array()
        ),
        
        // SOGOU (China)
        'sogou' => array(
            'user_agent_patterns' => array('sogou'),
            'rdns_patterns' => array('.sogou.com'),
            'skip_forward_verification' => true,
            'ip_ranges' => array()
        ),
        
        // EXABOT
        'exabot' => array(
            'user_agent_patterns' => array('exabot'),
            'rdns_patterns' => array('.exabot.com'),
            'skip_forward_verification' => true,
            'ip_ranges' => array()
        ),
        
        // APPLE
        'applebot' => array(
            'user_agent_patterns' => array('applebot'),
            'rdns_patterns' => array('.applebot.apple.com'),
            'skip_forward_verification' => false,
            'ip_ranges' => array(
                '17.0.0.0/8',
                '2a01:b740::/32',
            )
        ),
        
        // FACEBOOK
        'facebook' => array(
            'user_agent_patterns' => array('facebookexternalhit', 'facebookcatalog'),
            'rdns_patterns' => array('.facebook.com', '.fbsv.net'),
            'skip_forward_verification' => true,
            'ip_ranges' => array(
                '31.13.24.0/21', '31.13.64.0/18', '66.220.144.0/20',
                '69.63.176.0/20', '173.252.64.0/18', '2a03:2880::/32',
            )
        ),
        
        // TWITTER/X
        'twitter' => array(
            'user_agent_patterns' => array('twitterbot'),
            'rdns_patterns' => array('.twitter.com'),
            'skip_forward_verification' => true,
            'ip_ranges' => array()
        ),
        
        // INSTAGRAM
        'instagram' => array(
            'user_agent_patterns' => array('instagram'),
            'rdns_patterns' => array('.instagram.com'),
            'skip_forward_verification' => true,
            'ip_ranges' => array()
        ),
        
        // PINTEREST
        'pinterest' => array(
            'user_agent_patterns' => array('pinterest'),
            'rdns_patterns' => array('.pinterest.com'),
            'skip_forward_verification' => true,
            'ip_ranges' => array(
                '54.236.1.0/24',
            )
        ),
        
        // LINKEDIN
        'linkedin' => array(
            'user_agent_patterns' => array('linkedinbot'),
            'rdns_patterns' => array('.linkedin.com'),
            'skip_forward_verification' => true,
            'ip_ranges' => array()
        ),
        
        // TIKTOK/BYTEDANCE
        'tiktok' => array(
            'user_agent_patterns' => array('tiktok', 'bytespider', 'bytedance'),
            'rdns_patterns' => array('.bytedance.com', '.tiktok.com'),
            'skip_forward_verification' => true,
            'ip_ranges' => array()
        ),
        
        // WHATSAPP
        'whatsapp' => array(
            'user_agent_patterns' => array('whatsapp'),
            'rdns_patterns' => array('.whatsapp.net'),
            'skip_forward_verification' => true,
            'ip_ranges' => array()
        ),
        
        // TELEGRAM
        'telegram' => array(
            'user_agent_patterns' => array('telegrambot', 'telegram'),
            'rdns_patterns' => array('.telegram.org'),
            'skip_forward_verification' => true,
            'ip_ranges' => array()
        ),
        
        // VIBER
        'viber' => array(
            'user_agent_patterns' => array('viber'),
            'rdns_patterns' => array('.viber.com'),
            'skip_forward_verification' => true,
            'ip_ranges' => array()
        ),
        
        // DISCORD
        'discord' => array(
            'user_agent_patterns' => array('discordbot', 'discord'),
            'rdns_patterns' => array('.discord.com'),
            'skip_forward_verification' => true,
            'ip_ranges' => array()
        ),
        
        // SLACK
        'slack' => array(
            'user_agent_patterns' => array('slackbot', 'slack'),
            'rdns_patterns' => array('.slack.com'),
            'skip_forward_verification' => true,
            'ip_ranges' => array()
        ),
        
        // SEO TOOLS
        'semrush' => array(
            'user_agent_patterns' => array('semrushbot'),
            'rdns_patterns' => array('.semrush.com'),
            'skip_forward_verification' => true,
            'ip_ranges' => array()
        ),
        
        'ahrefs' => array(
            'user_agent_patterns' => array('ahrefsbot'),
            'rdns_patterns' => array('.ahrefs.com'),
            'skip_forward_verification' => true,
            'ip_ranges' => array()
        ),
        
        'majestic' => array(
            'user_agent_patterns' => array('majestic', 'mj12bot'),
            'rdns_patterns' => array('.majestic12.co.uk'),
            'skip_forward_verification' => true,
            'ip_ranges' => array()
        ),
        
        'screaming_frog' => array(
            'user_agent_patterns' => array('screaming frog'),
            'rdns_patterns' => array(),
            'skip_forward_verification' => true,
            'ip_ranges' => array()
        ),
        
        'sitebulb' => array(
            'user_agent_patterns' => array('sitebulb'),
            'rdns_patterns' => array(),
            'skip_forward_verification' => true,
            'ip_ranges' => array()
        ),
        
        // MONITORING
        'pingdom' => array(
            'user_agent_patterns' => array('pingdom'),
            'rdns_patterns' => array('.pingdom.com'),
            'skip_forward_verification' => true,
            'ip_ranges' => array()
        ),
        
        'uptimerobot' => array(
            'user_agent_patterns' => array('uptimerobot'),
            'rdns_patterns' => array('.uptimerobot.com'),
            'skip_forward_verification' => true,
            'ip_ranges' => array()
        ),
        
        'statuscake' => array(
            'user_agent_patterns' => array('statuscake'),
            'rdns_patterns' => array('.statuscake.com'),
            'skip_forward_verification' => true,
            'ip_ranges' => array()
        ),
        
        'gtmetrix' => array(
            'user_agent_patterns' => array('gtmetrix'),
            'rdns_patterns' => array('.gtmetrix.com'),
            'skip_forward_verification' => true,
            'ip_ranges' => array()
        ),
        
        'webpagetest' => array(
            'user_agent_patterns' => array('webpagetest'),
            'rdns_patterns' => array('.webpagetest.org'),
            'skip_forward_verification' => true,
            'ip_ranges' => array()
        ),
        
        'lighthouse' => array(
            'user_agent_patterns' => array('lighthouse', 'chrome-lighthouse'),
            'rdns_patterns' => array(),
            'skip_forward_verification' => true,
            'ip_ranges' => array()
        ),
        
        // v3.8.4: PETALBOT (HUAWEI PETAL SEARCH)
        'petalbot' => array(
            'user_agent_patterns' => array('petalbot'),
            'rdns_patterns' => array('.petalsearch.com', '.aspiegel.com'),
            'skip_forward_verification' => true,
            'ip_ranges' => array(
                '114.119.128.0/17',
            )
        ),
    );
    
    // ВЛАСНІ USER AGENTS (v3.6.0)
    
    private $customUserAgents = array();
    
    public function __construct() {
        global $CUSTOM_USER_AGENTS, $_API_CONFIG;
        
        // Завантажуємо власні UA з глобальної конфігурації
        $this->customUserAgents = $CUSTOM_USER_AGENTS;
        
        // v3.8.8: Завантажуємо налаштування API з глобальної конфігурації
        $this->apiSettings = $_API_CONFIG;
        
        $this->connectRedis();
    }
    
    /**
     * Підключення до Redis
     */
    private function connectRedis() {
        try {
            $this->redis = new Redis();
            $this->redis->connect($this->redisHost, $this->redisPort, 1);
            
            if ($this->redisPassword) {
                $this->redis->auth($this->redisPassword);
            }
            
            $this->redis->select($this->redisDB);
            $this->redis->setOption(Redis::OPT_SERIALIZER, Redis::SERIALIZER_PHP);
            
        } catch (Exception $e) {
            error_log("Redis connection failed: " . $e->getMessage());
            $this->redis = null;
        }
    }
    
    /**
     * ========================================================================
     * ГОЛОВНИЙ МЕТОД ЗАХИСТУ (v3.8.4 - Admin URL + AJAX Support)
     * ========================================================================
     */
    public function protect() {
        try {
            $ip = $this->getClientIP();
            $userAgent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
            
            // КРОК 0: ПЕРЕВІРКА ПРОПУСКУ RATE LIMIT (v3.8.4)
            // Перевіряє: IP whitelist, Admin URL whitelist, AJAX (якщо увімкнено)
            $skipReason = _should_skip_rate_limit($ip);
            if ($skipReason !== false) {
                if ($this->debugMode) {
                    error_log("BOT PROTECTION: Skipping all checks - reason: $skipReason, IP: $ip");
                }
                return; // Пропускаємо ВСІ перевірки
            }
            
            // КРОК 1: ШВИДКА ПЕРЕВІРКА ВЛАСНИХ USER AGENTS
            if ($this->isCustomUserAgent($userAgent)) {
                if ($this->debugMode) {
                    error_log("BOT PROTECTION: Custom User Agent detected, allowing: " . substr($userAgent, 0, 50));
                }
                return; // Пропускаємо власні UA
            }
            
            // КРОК 2: ПЕРЕВІРКА ПОШУКОВИХ СИСТЕМ (rDNS)
            // rDNS верифікація для ботів які не в IP whitelist
            if ($this->verifySearchEngineRDNS($ip, $userAgent)) {
                if ($this->debugMode) {
                    error_log("BOT PROTECTION: Search engine verified by rDNS, allowing");
                }
                return; // Верифікований пошуковий бот
            }
            
            // КРОК 3: ПЕРЕВІРКА REDIS (якщо доступний)
            if (!$this->redis) {
                if ($this->debugMode) {
                    error_log("BOT PROTECTION: Redis not available, protection disabled");
                }
                return; // Якщо Redis недоступний - пропускаємо
            }
            
            // Debug logging
            if ($this->debugMode) {
                error_log("BOT PROTECTION: Checking IP=$ip, UA=" . substr($userAgent, 0, 50) . ", AJAX=" . (_is_ajax_request() ? 'yes' : 'no'));
            }
            
            // КРОК 4: ПЕРЕВІРКИ ЗАХИСТУ (для звичайних користувачів)
            
            // v3.8.4: Отримуємо множник для AJAX запитів
            $rateMultiplier = _get_rate_limit_multiplier();
            
            if ($this->debugMode && $rateMultiplier > 1.0) {
                error_log("BOT PROTECTION: AJAX rate limit multiplier applied: x" . $rateMultiplier);
            }
            
            // Перевірка UA Rotation (не застосовується множник - це інший тип атаки)
            if ($this->checkUserAgentRotation($ip)) {
                error_log("BOT PROTECTION: UA rotation detected, blocking IP=$ip");
                $this->show502Error();
            }
            
            // Перевірка Rate Limit і Burst (з множником для AJAX)
            if ($this->checkRateLimit($ip, $rateMultiplier)) {
                error_log("BOT PROTECTION: Rate limit exceeded, blocking IP=$ip");
                $this->show502Error();
            }
            
            if ($this->debugMode) {
                error_log("BOT PROTECTION: Request allowed for IP=$ip");
            }
            
        } catch (Exception $e) {
            error_log("BOT PROTECTION ERROR: " . $e->getMessage() . " at line " . $e->getLine());
            return; // При помилці - пропускаємо
        }
    }
    
    /**
     * ========================================================================
     * ПЕРЕВІРКА ВЛАСНИХ USER AGENTS (v3.6.0)
     * ========================================================================
     */
    private function isCustomUserAgent($userAgent) {
        if (empty($this->customUserAgents)) {
            return false;
        }
        
        $userAgentLower = strtolower($userAgent);
        
        foreach ($this->customUserAgents as $customUA) {
            if (stripos($userAgentLower, strtolower($customUA)) !== false) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Додати власний User Agent до whitelist
     */
    public function addCustomUserAgent($userAgent) {
        global $CUSTOM_USER_AGENTS;
        if (!in_array($userAgent, $CUSTOM_USER_AGENTS)) {
            $CUSTOM_USER_AGENTS[] = $userAgent;
        }
        $this->customUserAgents = $CUSTOM_USER_AGENTS;
    }
    
    /**
     * Встановити масив власних User Agents
     */
    public function setCustomUserAgents($userAgents) {
        global $CUSTOM_USER_AGENTS;
        if (is_array($userAgents)) {
            $CUSTOM_USER_AGENTS = $userAgents;
            $this->customUserAgents = $userAgents;
        }
    }
    
    /**
     * Отримати список власних User Agents
     */
    public function getCustomUserAgents() {
        return $this->customUserAgents;
    }
    
    /**
     * Очистити список власних User Agents
     */
    public function clearCustomUserAgents() {
        global $CUSTOM_USER_AGENTS;
        $CUSTOM_USER_AGENTS = array();
        $this->customUserAgents = array();
    }
    
    /**
     * Перевірка чи IP належить пошуковій системі
     */
    private function isSearchEngineByIP($ip, $userAgent = '') {
        $detectedEngine = null;
        $engineConfig = null;
        
        if (!empty($userAgent)) {
            foreach ($this->searchEngines as $engine => $config) {
                foreach ($config['user_agent_patterns'] as $pattern) {
                    if (stripos($userAgent, $pattern) !== false) {
                        $detectedEngine = $engine;
                        $engineConfig = $config;
                        break 2;
                    }
                }
            }
        }
        
        if ($detectedEngine && $engineConfig && !empty($engineConfig['ip_ranges'])) {
            foreach ($engineConfig['ip_ranges'] as $cidr) {
                if ($this->ipInRange($ip, $cidr)) {
                    error_log("Search engine verified by IP: $detectedEngine ($ip)");
                    $this->logSearchEngine($detectedEngine, $ip, 'IP');
                    return true;
                }
            }
        }
        
        foreach ($this->searchEngines as $engine => $config) {
            if (!empty($config['ip_ranges'])) {
                foreach ($config['ip_ranges'] as $cidr) {
                    if ($this->ipInRange($ip, $cidr)) {
                        error_log("Search engine verified by IP (fallback): $engine ($ip)");
                        $this->logSearchEngine($engine, $ip, 'IP-fallback');
                        return true;
                    }
                }
            }
        }
        
        return false;
    }
    
    /**
     * rDNS верифікація пошукових ботів
     */
    private function verifySearchEngineRDNS($ip, $userAgent = '') {
        $engineConfig = null;
        $engineName = null;
        
        if (!empty($userAgent)) {
            foreach ($this->searchEngines as $engine => $config) {
                foreach ($config['user_agent_patterns'] as $pattern) {
                    if (stripos($userAgent, $pattern) !== false) {
                        $engineConfig = $config;
                        $engineName = $engine;
                        break 2;
                    }
                }
            }
        }
        
        if (!$engineConfig || empty($engineConfig['rdns_patterns'])) {
            return false;
        }
        
        $verified = $this->performRDNSVerification($ip, $engineConfig);
        
        if ($verified && $engineName) {
            $this->logSearchEngine($engineName, $ip, 'rDNS');
        }
        
        return $verified;
    }
    
    /**
     * Виконання rDNS верифікації
     */
    private function performRDNSVerification($ip, $engineConfig) {
        try {
            $cacheKey = $this->redisPrefix . $this->rdnsPrefix . 'cache:' . hash('md5', $ip);
            
            $cached = $this->redis->get($cacheKey);
            if ($cached !== false) {
                return $cached === '1';
            }
            
            if (!$this->checkRDNSRateLimit()) {
                if ($this->rdnsSettings['rdns_on_limit_action'] === 'block') {
                    error_log("rDNS rate limit exceeded, blocking IP: $ip");
                    return false;
                }
                error_log("rDNS rate limit exceeded, skipping verification for: $ip");
                return false;
            }
            
            $verified = false;
            $allowedPatterns = $engineConfig['rdns_patterns'];
            $skipForward = isset($engineConfig['skip_forward_verification']) ? $engineConfig['skip_forward_verification'] : false;
            
            $hostname = $this->getHostnameWithTimeout($ip, 2);
            
            if ($hostname && $hostname !== $ip) {
                $hostnameMatches = false;
                foreach ($allowedPatterns as $pattern) {
                    if ($this->matchesDomainPattern($hostname, $pattern)) {
                        $hostnameMatches = true;
                        break;
                    }
                }
                
                if ($hostnameMatches) {
                    if ($skipForward) {
                        $verified = true;
                    } else {
                        $forwardIPs = gethostbynamel($hostname);
                        if ($forwardIPs && in_array($ip, $forwardIPs)) {
                            $verified = true;
                        }
                    }
                }
            }
            
            $this->redis->setex($cacheKey, $this->rdnsSettings['cache_ttl'], $verified ? '1' : '0');
            
            return $verified;
            
        } catch (Exception $e) {
            error_log("rDNS verification error for IP $ip: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Перевірка rDNS rate limit
     */
    private function checkRDNSRateLimit() {
        $key = $this->redisPrefix . $this->rdnsPrefix . 'ratelimit';
        $count = $this->redis->incr($key);
        
        if ($count === 1) {
            $this->redis->expire($key, 60);
        }
        
        return $count <= $this->rdnsSettings['rate_limit_per_minute'];
    }
    
    /**
     * Отримання hostname з timeout
     */
    private function getHostnameWithTimeout($ip, $timeout = 2) {
        $hostname = null;
        $start = microtime(true);
        
        $hostname = @gethostbyaddr($ip);
        
        $elapsed = microtime(true) - $start;
        
        if ($elapsed > $timeout) {
            error_log("rDNS lookup timeout for $ip (took {$elapsed}s)");
            return null;
        }
        
        return $hostname !== $ip ? $hostname : null;
    }
    
    /**
     * Перевірка відповідності домену паттерну
     */
    private function matchesDomainPattern($hostname, $pattern) {
        if (substr($pattern, 0, 1) === '.') {
            return substr($hostname, -strlen($pattern)) === $pattern;
        }
        return $hostname === $pattern;
    }
    
    /**
     * Перевірка User Agent Rotation
     */
    private function checkUserAgentRotation($ip) {
        if (!$this->uaRotationSettings['enabled']) {
            return false;
        }
        
        $userAgent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
        if (empty($userAgent)) {
            return false;
        }
        
        $now = time();
        $uaKey = $this->redisPrefix . 'ua:' . $ip;
        $blockKey = $this->redisPrefix . 'ua_blocked:' . $ip;
        
        if ($this->redis->exists($blockKey)) {
            return true;
        }
        
        $uaData = $this->redis->get($uaKey);
        if (!$uaData || !is_array($uaData)) {
            $uaData = array();
        }
        
        $filtered = array();
        foreach ($uaData as $timestamp => $ua) {
            if (($now - $timestamp) < $this->uaRotationSettings['tracking_window']) {
                $filtered[$timestamp] = $ua;
            }
        }
        
        $filtered[$now] = $userAgent;
        
        $uniqueUA5min = array();
        $uniqueUAHour = array();
        
        foreach ($filtered as $timestamp => $ua) {
            if (($now - $timestamp) < 300) {
                $uniqueUA5min[$ua] = true;
            }
            if (($now - $timestamp) < 3600) {
                $uniqueUAHour[$ua] = true;
            }
        }
        
        $count5min = count($uniqueUA5min);
        $countHour = count($uniqueUAHour);
        
        if ($this->debugMode) {
            error_log(sprintf(
                "UA ROTATION CHECK: IP=%s, unique_5min=%d/%d, unique_hour=%d/%d",
                $ip,
                $count5min, $this->uaRotationSettings['max_unique_ua_per_5min'],
                $countHour, $this->uaRotationSettings['max_unique_ua_per_hour']
            ));
        }
        
        $this->redis->setex($uaKey, $this->uaRotationSettings['tracking_window'], $filtered);
        
        if ($count5min > $this->uaRotationSettings['max_unique_ua_per_5min'] ||
            $countHour > $this->uaRotationSettings['max_unique_ua_per_hour']) {
            
            $this->redis->setex(
                $blockKey,
                $this->uaRotationSettings['block_duration'],
                array('time' => $now, 'count_5min' => $count5min, 'count_hour' => $countHour)
            );
            
            error_log("UA ROTATION BLOCK: IP=$ip, 5min=$count5min, hour=$countHour");
            
            if ($this->apiSettings['enabled'] && $this->apiSettings['block_on_api']) {
                $this->callBlockingAPI($ip, 'block');
            }
            
            return true;
        }
        
        return false;
    }
    
    /**
     * Отримати IP клієнта
     */
    private function getClientIP() {
        $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '0.0.0.0';
        
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            $ip = $_SERVER['HTTP_CF_CONNECTING_IP'];
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            $ip = trim($ips[0]);
        } elseif (!empty($_SERVER['HTTP_X_REAL_IP'])) {
            $ip = $_SERVER['HTTP_X_REAL_IP'];
        }
        
        return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '0.0.0.0';
    }
    
    /**
     * Перевірка чи IP в CIDR діапазоні
     */
    private function ipInRange($ip, $cidr) {
        if (strpos($cidr, '/') === false) {
            return $ip === $cidr;
        }
        
        list($subnet, $mask) = explode('/', $cidr);
        $mask = (int)$mask;
        
        $ipIsV6 = (strpos($ip, ':') !== false);
        $cidrIsV6 = (strpos($subnet, ':') !== false);
        
        if ($ipIsV6 !== $cidrIsV6) {
            return false;
        }
        
        if ($ipIsV6) {
            if ($mask < 0 || $mask > 128) {
                error_log("Invalid IPv6 CIDR mask: $cidr");
                return false;
            }
            return $this->ipv6InRange($ip, $subnet, $mask);
        }
        
        if ($mask < 0 || $mask > 32) {
            error_log("Invalid IPv4 CIDR mask: $cidr (IP: $ip)");
            return false;
        }
        
        $ip_long = ip2long($ip);
        $subnet_long = ip2long($subnet);
        
        if ($ip_long === false || $subnet_long === false) {
            return false;
        }
        
        $mask_long = -1 << (32 - $mask);
        
        return ($ip_long & $mask_long) === ($subnet_long & $mask_long);
    }
    
    /**
     * Перевірка IPv6 в діапазоні
     */
    private function ipv6InRange($ip, $subnet, $mask) {
        $ip_bin = inet_pton($ip);
        $subnet_bin = inet_pton($subnet);
        
        if ($ip_bin === false || $subnet_bin === false) {
            return false;
        }
        
        $mask = (int)$mask;
        
        if ($mask < 0 || $mask > 128) {
            error_log("Invalid IPv6 mask in ipv6InRange: $mask");
            return false;
        }
        
        $full_bytes = (int)floor($mask / 8);
        $remaining_bits = $mask % 8;
        
        for ($i = 0; $i < $full_bytes; $i++) {
            if ($ip_bin[$i] !== $subnet_bin[$i]) {
                return false;
            }
        }
        
        if ($remaining_bits > 0) {
            $mask_byte = (0xFF << (8 - $remaining_bits)) & 0xFF;
            if ((ord($ip_bin[$full_bytes]) & $mask_byte) !== (ord($subnet_bin[$full_bytes]) & $mask_byte)) {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Генерація user identifier
     */
    private function generateUserIdentifier() {
        $ip = $this->getClientIP();
        $userAgent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
        $acceptLang = isset($_SERVER['HTTP_ACCEPT_LANGUAGE']) ? $_SERVER['HTTP_ACCEPT_LANGUAGE'] : '';
        
        $browserHash = hash('sha256', $userAgent . '|' . $acceptLang);
        
        $cookieName = 'bot_protection_uid';
        $cookieId = isset($_COOKIE[$cookieName]) ? $_COOKIE[$cookieName] : '';
        
        if (empty($cookieId)) {
            $cookieId = bin2hex(random_bytes(16));
            $secure = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
            
            if (PHP_VERSION_ID >= 70300) {
                setcookie($cookieName, $cookieId, [
                    'expires' => time() + 86400 * 30,
                    'path' => '/',
                    'secure' => $secure,
                    'httponly' => true,
                    'samesite' => 'Lax'
                ]);
            } else {
                setcookie($cookieName, $cookieId, time() + 86400 * 30, '/', '', $secure, true);
            }
        }
        
        return $cookieId . '_' . substr($browserHash, 0, 16);
    }
    
    /**
     * Перевірка наявності cookie
     */
    private function hasValidCookie() {
        $cookieName = 'bot_protection_uid';
        return isset($_COOKIE[$cookieName]) && !empty($_COOKIE[$cookieName]);
    }
    
    /**
     * Перевірка JS verification
     */
    private function isJSVerified() {
        global $_JSC_CONFIG;
        return _jsc_isVerified($_JSC_CONFIG['secret_key'], $_JSC_CONFIG['cookie_name']);
    }
    
    /**
     * Отримати інформацію про користувача
     */
    private function getUserInfo() {
        $userAgent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
        $acceptLang = isset($_SERVER['HTTP_ACCEPT_LANGUAGE']) ? $_SERVER['HTTP_ACCEPT_LANGUAGE'] : '';
        $browserHash = hash('sha256', $userAgent . '|' . $acceptLang);
        
        $cookieName = 'bot_protection_uid';
        $cookieId = isset($_COOKIE[$cookieName]) ? $_COOKIE[$cookieName] : '';
        
        return array(
            'browser_hash' => $browserHash,
            'cookie_id' => $cookieId,
            'user_agent' => $userAgent,
            'accept_lang' => $acceptLang
        );
    }
    
    /**
     * Перевірка Rate Limit
     */
    /**
     * Перевірка Rate Limit (v3.8.4 - з підтримкою AJAX множника)
     * 
     * @param string $ip IP адреса користувача
     * @param float $ajaxMultiplier Множник для AJAX запитів (за замовчуванням 1.0)
     * @return bool true якщо ліміт перевищено
     */
    private function checkRateLimit($ip, $ajaxMultiplier = 1.0) {
        $now = time();
        $userId = $this->generateUserIdentifier();
        $hasCookie = $this->hasValidCookie();
        
        // Ініціалізація змінної для уникнення помилок
        $useStrictLimits = false;
        
        // ЗАХИСТ ВІД БОТІВ БЕЗ COOKIES - Перевірка та жорсткі ліміти
        if (!$hasCookie) {
            // Перевірка чи це атака без cookies
            if ($this->checkNoCookieAttempts($ip)) {
                // Вже заблоковано і залоговано в checkNoCookieAttempts()
                return true;
            }
            
            // Використовуємо жорсткі ліміти для користувачів без cookies
            $useStrictLimits = true;
            
            if ($this->debugMode) {
                error_log(sprintf(
                    "RATE LIMIT: Using STRICT limits for no-cookie user, IP=%s, limits: burst=%d, 5min=%d, hour=%d",
                    $ip,
                    $this->noCookieRateLimits['burst'],
                    $this->noCookieRateLimits['5min'],
                    $this->noCookieRateLimits['hour']
                ));
            }
        } else {
            // Cookie є - скидаємо лічильник спроб без cookie для цього IP
            // Це дозволяє кільком користувачам з одного IP заходити на сайт
            $attemptsKey = $this->redisPrefix . 'no_cookie_attempts:' . $ip;
            if ($this->redis->exists($attemptsKey)) {
                $this->redis->del($attemptsKey);
                if ($this->debugMode) {
                    error_log("NO COOKIE ATTEMPTS RESET: IP=$ip (cookie obtained successfully)");
                }
            }
        }
        
        $key = $this->redisPrefix . 'rate:' . hash('md5', $userId);
        $blockKey = $this->redisPrefix . 'blocked:' . hash('md5', $userId);
        
        if ($this->redis->exists($blockKey)) {
            return true;
        }
        
        $data = $this->redis->get($key);
        
        $defaultRequests = array(
            'minute' => array(),
            '5min' => array(),
            'hour' => array(),
            'last_10sec' => array()
        );
        
        if ($data && is_array($data)) {
            $requests = $data;
            foreach (array('minute', '5min', 'hour', 'last_10sec') as $key_name) {
                if (!isset($requests[$key_name]) || !is_array($requests[$key_name])) {
                    $requests[$key_name] = array();
                }
            }
        } else {
            $requests = $defaultRequests;
        }
        
        $filteredMinute = array();
        foreach ($requests['minute'] as $t) {
            if (($now - $t) < 60) {
                $filteredMinute[] = $t;
            }
        }
        $requests['minute'] = $filteredMinute;
        
        $filtered5min = array();
        foreach ($requests['5min'] as $t) {
            if (($now - $t) < 300) {
                $filtered5min[] = $t;
            }
        }
        $requests['5min'] = $filtered5min;
        
        $filteredHour = array();
        foreach ($requests['hour'] as $t) {
            if (($now - $t) < 3600) {
                $filteredHour[] = $t;
            }
        }
        $requests['hour'] = $filteredHour;
        
        $filtered10sec = array();
        foreach ($requests['last_10sec'] as $t) {
            if (($now - $t) < 10) {
                $filtered10sec[] = $t;
            }
        }
        $requests['last_10sec'] = $filtered10sec;
        
        $requests['minute'][] = $now;
        $requests['5min'][] = $now;
        $requests['hour'][] = $now;
        $requests['last_10sec'][] = $now;
        
        // Встановлення лімітів залежно від наявності cookie (v3.8.4 + AJAX multiplier)
        if ($useStrictLimits) {
            // Жорсткі ліміти для користувачів БЕЗ bot_protection_uid cookie
            // AJAX множник НЕ застосовується для strict limits (це можливі боти)
            $limits = array(
                'minute' => $this->noCookieRateLimits['minute'],
                '5min' => $this->noCookieRateLimits['5min'],
                'hour' => $this->noCookieRateLimits['hour'],
                'burst' => $this->noCookieRateLimits['burst']
            );
        } else {
            // Звичайні ліміти з multiplier для користувачів З cookie
            $multiplier = 1.0;
            if ($hasCookie) {
                $multiplier = $this->rateLimitSettings['cookie_multiplier'];
            }
            if ($this->isJSVerified()) {
                $multiplier = $this->rateLimitSettings['js_verified_multiplier'];
            }
            
            // v3.8.4: Застосовуємо AJAX множник додатково
            // Ліміти = базові * cookie/JS multiplier * AJAX multiplier
            $totalMultiplier = $multiplier * $ajaxMultiplier;
            
            $limits = array(
                'minute' => (int)($this->rateLimitSettings['max_requests_per_minute'] * $totalMultiplier),
                '5min' => (int)($this->rateLimitSettings['max_requests_per_5min'] * $totalMultiplier),
                'hour' => (int)($this->rateLimitSettings['max_requests_per_hour'] * $totalMultiplier),
                'burst' => (int)($this->rateLimitSettings['burst_threshold'] * $totalMultiplier)
            );
            
            if ($this->debugMode && $ajaxMultiplier > 1.0) {
                error_log(sprintf(
                    "RATE LIMIT: AJAX multiplier applied: base_mult=%.1f, ajax_mult=%.1f, total=%.1f",
                    $multiplier, $ajaxMultiplier, $totalMultiplier
                ));
            }
        }
        
        $violations = array();
        
        if ($this->debugMode) {
            error_log(sprintf(
                "RATE LIMIT CHECK: user_id=%s, cookie=%s, counts=[min:%d/%d, 5min:%d/%d, hour:%d/%d, burst:%d/%d]",
                substr($userId, 0, 30),
                $hasCookie ? 'YES' : 'NO',
                count($requests['minute']), $limits['minute'],
                count($requests['5min']), $limits['5min'],
                count($requests['hour']), $limits['hour'],
                count($requests['last_10sec']), $limits['burst']
            ));
        }
        
        if (count($requests['minute']) > $limits['minute']) {
            $violations[] = 'minute';
        }
        
        if (count($requests['5min']) > $limits['5min']) {
            $violations[] = '5min';
        }
        
        if (count($requests['hour']) > $limits['hour']) {
            $violations[] = 'hour';
        }
        
        if (count($requests['last_10sec']) > $limits['burst']) {
            $violations[] = 'burst';
        }
        
        $this->redis->setex($key, 3600, $requests);
        
        if (!empty($violations)) {
            $this->blockUser($userId, $ip, $violations, $hasCookie, $limits);
            return true;
        }
        
        return false;
    }
    
    /**
     * Блокування користувача
     */
    private function blockUser($userId, $ip, $violations, $hasCookie, $limits) {
        $blockKey = $this->redisPrefix . 'blocked:' . hash('md5', $userId);
        $userInfo = $this->getUserInfo();
        
        $blockData = array(
            'time' => time(),
            'violations' => $violations,
            'user_id' => $userId,
            'ip' => $ip,
            'browser_hash' => $userInfo['browser_hash'],
            'cookie_id' => $userInfo['cookie_id'],
            'has_cookie' => $hasCookie,
            'limits' => $limits
        );
        
        if ($this->apiSettings['block_on_redis']) {
            $this->redis->setex(
                $blockKey,
                $this->rateLimitSettings['block_duration'],
                $blockData
            );
        }
        
        error_log("RATE LIMIT BLOCK USER: " .
                  "user_id=" . substr($userId, 0, 20) .
                  ", ip=$ip" .
                  ", cookie=" . ($hasCookie ? 'YES' : 'NO') .
                  ", violations=" . implode(',', $violations));
        
        if (!$hasCookie && $this->apiSettings['enabled'] && $this->apiSettings['block_on_api']) {
            $apiResult = $this->callBlockingAPI($ip, 'block');
            if ($apiResult['status'] === 'success') {
                error_log("API BLOCK SUCCESS: IP=$ip (user without cookie)");
            } elseif ($apiResult['status'] !== 'already_blocked') {
                $msg = isset($apiResult['message']) ? $apiResult['message'] : 'unknown';
                error_log("API BLOCK FAILED: IP=$ip, reason=" . $msg);
            }
        }
    }
    
    /**
     * Виклик API для блокування
     * v3.8.12: Підтримка GET/POST методів
     */
    private function callBlockingAPI($ip, $action = 'block') {
        if (!$this->apiSettings['enabled']) {
            return array('status' => 'disabled', 'message' => 'API disabled');
        }
        
        if (!$this->apiSettings['block_on_api']) {
            return array('status' => 'skipped', 'message' => 'API blocking disabled');
        }
        
        // Визначаємо метод запиту (за замовчуванням POST)
        $method = isset($this->apiSettings['method']) ? strtoupper($this->apiSettings['method']) : 'POST';
        
        // Параметри запиту
        $params = array(
            'action' => $action,
            'ip' => $ip,
            'api' => 1,
            'api_key' => $this->apiSettings['api_key']
        );
        
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
                
                $curlOptions = array(
                    CURLOPT_RETURNTRANSFER => true,
                    CURLOPT_TIMEOUT => $this->apiSettings['timeout'],
                    CURLOPT_CONNECTTIMEOUT => 3,
                    CURLOPT_FOLLOWLOCATION => false,
                    CURLOPT_SSL_VERIFYPEER => $this->apiSettings['verify_ssl'],
                    CURLOPT_SSL_VERIFYHOST => $this->apiSettings['verify_ssl'] ? 2 : 0,
                    CURLOPT_USERAGENT => $this->apiSettings['user_agent'],
                    CURLOPT_HTTPHEADER => array(
                        'Accept: application/json',
                        'Cache-Control: no-cache'
                    )
                );
                
                if ($method === 'POST') {
                    // POST запит - параметри в тілі
                    $curlOptions[CURLOPT_URL] = $this->apiSettings['url'];
                    $curlOptions[CURLOPT_POST] = true;
                    $curlOptions[CURLOPT_POSTFIELDS] = http_build_query($params);
                } else {
                    // GET запит - параметри в URL
                    $curlOptions[CURLOPT_URL] = $this->apiSettings['url'] . '?' . http_build_query($params);
                }
                
                curl_setopt_array($ch, $curlOptions);
                
                $response = curl_exec($ch);
                $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                $curlError = curl_error($ch);
                $curlErrno = curl_errno($ch);
                curl_close($ch);
                
                if ($curlErrno !== 0) {
                    throw new Exception("cURL error #" . $curlErrno . ": " . $curlError);
                }
                
                if ($httpCode !== 200) {
                    throw new Exception("HTTP error code: " . $httpCode);
                }
                
                $result = json_decode($response, true);
                if (json_last_error() !== JSON_ERROR_NONE) {
                    throw new Exception("Invalid JSON response");
                }
                
                return $result;
                
            } catch (Exception $e) {
                $lastError = $e->getMessage();
                if ($attempt < $maxRetries) {
                    usleep(500000);
                }
            }
        }
        
        return array('status' => 'error', 'message' => $lastError);
    }
    
    /**
     * Показ 502 помилки
     */
    private function show502Error() {
        _show_502_error();
    }
    
    /**
     * Логування пошукової системи
     */
    private function logSearchEngine($engine, $ip, $method = 'IP') {
        if (!$this->searchLogSettings['enabled']) {
            return;
        }
        
        // v3.7.0: Збереження статистики в Redis
        if ($this->searchLogSettings['redis_stats']) {
            $this->logSearchEngineToRedis($engine, $ip, $method);
        }
        
        $logFile = $this->searchLogSettings['file'];
        
        if (file_exists($logFile) && filesize($logFile) >= $this->searchLogSettings['max_size']) {
            $this->rotateSearchLog();
        }
        
        $timestamp = date('Y-m-d H:i:s');
        $logParts = array($timestamp, $engine, $ip, $method);
        
        if ($this->searchLogSettings['log_host']) {
            $host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '-';
            $logParts[] = $host;
        }
        
        if ($this->searchLogSettings['log_url']) {
            $url = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '-';
            $logParts[] = $url;
        }
        
        if ($this->searchLogSettings['log_ua']) {
            $ua = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '-';
            $maxLen = $this->searchLogSettings['ua_max_length'];
            if (strlen($ua) > $maxLen) {
                $ua = substr($ua, 0, $maxLen) . '...';
            }
            $logParts[] = $ua;
        }
        
        $logLine = implode(' | ', $logParts) . "\n";
        
        @file_put_contents($logFile, $logLine, FILE_APPEND | LOCK_EX);
    }
    
    /**
     * v3.7.0: Збереження статистики пошукових ботів в Redis
     */
    private function logSearchEngineToRedis($engine, $ip, $method) {
        if (!$this->redis) {
            return;
        }
        
        try {
            $today = date('Y-m-d');
            $host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : 'unknown';
            $url = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '/';
            $ua = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '-';
            
            // Скорочуємо UA
            $maxLen = $this->searchLogSettings['ua_max_length'];
            if (strlen($ua) > $maxLen) {
                $ua = substr($ua, 0, $maxLen) . '...';
            }
            
            // 1. Інкрементуємо загальний лічильник бота
            $totalKey = $this->redisPrefix . 'search_stats:total:' . strtolower($engine);
            $this->redis->incr($totalKey);
            
            // 2. Інкрементуємо денний лічильник бота
            $todayKey = $this->redisPrefix . 'search_stats:today:' . $today . ':' . strtolower($engine);
            $this->redis->incr($todayKey);
            $this->redis->expire($todayKey, 86400 * 7); // Зберігаємо 7 днів
            
            // 3. Інкрементуємо лічильник по хосту
            $hostKey = $this->redisPrefix . 'search_stats:hosts:' . $host;
            $this->redis->incr($hostKey);
            $this->redis->expire($hostKey, $this->searchLogSettings['redis_stats_ttl']);
            
            // 4. Інкрементуємо лічильник по методу верифікації
            $methodKey = $this->redisPrefix . 'search_stats:methods:' . strtolower($method);
            $this->redis->incr($methodKey);
            
            // 5. Додаємо запис в лог (Redis List)
            $logEntry = array(
                'time' => date('Y-m-d H:i:s'),
                'engine' => $engine,
                'ip' => $ip,
                'method' => $method,
                'host' => $host,
                'url' => $url,
                'ua' => $ua,
            );
            
            $logKey = $this->redisPrefix . 'search_log';
            $this->redis->lpush($logKey, $logEntry);
            $this->redis->ltrim($logKey, 0, $this->searchLogSettings['redis_log_max'] - 1);
            
        } catch (Exception $e) {
            // Ігноруємо помилки Redis для статистики
            if ($this->debugMode) {
                error_log("Search stats Redis error: " . $e->getMessage());
            }
        }
    }
    
    /**
     * Ротація логу
     */
    private function rotateSearchLog() {
        $logFile = $this->searchLogSettings['file'];
        $keepBackups = $this->searchLogSettings['keep_backups'];
        
        $oldestBackup = $logFile . '.' . $keepBackups;
        if (file_exists($oldestBackup)) {
            @unlink($oldestBackup);
        }
        
        for ($i = $keepBackups - 1; $i >= 1; $i--) {
            $from = $logFile . '.' . $i;
            $to = $logFile . '.' . ($i + 1);
            if (file_exists($from)) {
                @rename($from, $to);
            }
        }
        
        if (file_exists($logFile)) {
            @rename($logFile, $logFile . '.1');
        }
    }
    
    /**
     * Увімкнути/вимкнути debug
     */
    public function setDebugMode($enabled) {
        $this->debugMode = (bool)$enabled;
    }
    
    /**
     * Оновити налаштування rate limit
     */
    public function updateRateLimitSettings($settings) {
        $this->rateLimitSettings = array_merge($this->rateLimitSettings, $settings);
    }
    
    /**
     * Оновити налаштування UA Rotation
     */
    public function updateUARotationSettings($settings) {
        $this->uaRotationSettings = array_merge($this->uaRotationSettings, $settings);
    }
    
    /**
     * Оновити налаштування API
     */
    public function updateAPISettings($settings) {
        $this->apiSettings = array_merge($this->apiSettings, $settings);
    }
    
    /**
     * Додати пошукову систему
     */
    public function addSearchEngine($name, $config) {
        $this->searchEngines[$name] = $config;
    }
    
    /**
     * Додати IP діапазон до пошукової системи
     */
    public function addSearchEngineIP($engine, $cidr) {
        if (isset($this->searchEngines[$engine])) {
            $this->searchEngines[$engine]['ip_ranges'][] = $cidr;
        }
    }
    
    /**
     * Отримати статистику
     */
    public function getSearchLogStats() {
        $logFile = $this->searchLogSettings['file'];
        
        $stats = array(
            'enabled' => $this->searchLogSettings['enabled'],
            'file' => $logFile,
            'exists' => file_exists($logFile),
            'size' => file_exists($logFile) ? filesize($logFile) : 0,
            'max_size' => $this->searchLogSettings['max_size'],
            'bots' => array()
        );
        
        if ($stats['exists']) {
            $content = @file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            $stats['total_lines'] = $content ? count($content) : 0;
            
            if ($content) {
                foreach ($content as $line) {
                    $parts = explode(' | ', $line);
                    if (isset($parts[1])) {
                        $bot = trim($parts[1]);
                        if (!isset($stats['bots'][$bot])) {
                            $stats['bots'][$bot] = 0;
                        }
                        $stats['bots'][$bot]++;
                    }
                }
            }
        }
        
        return $stats;
    }
    
    /**
     * Деструктор - закриваємо з'єднання Redis
     */
    public function __destruct() {
        if ($this->redis !== null) {
            try {
                $this->redis->close();
            } catch (Exception $e) {
                // Ігноруємо помилки закриття
            }
            $this->redis = null;
        }
    }
}

// АВТОМАТИЧНИЙ ЗАХИСТ
$protection = new SimpleBotProtection();
$protection->protect();
