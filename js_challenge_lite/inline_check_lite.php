<?php
/**
 * ============================================================================
 * Redis Bot Protection - SEO ОПТИМІЗОВАНА ВЕРСІЯ v3.6.4
 * ============================================================================
 * 
 * ВЕРСІЯ 3.6.4 - SMF STYLE (2026-01-14)
 * 
 * НОВЕ v3.6.4:
 * 🎨 Дизайн в стилі SMF 2.0.15 (Simple Machines Forum)
 * 🎨 Класична тема форуму: синій заголовок, білий фон
 * 🎨 JS Challenge виглядає як сторінка форуму
 * 🎨 502 помилка з червоним заголовком (помилка)
 * 🎨 Градієнти та стилі як в SMF
 * 🎨 Футер з копірайтом SMF
 * 
 * НОВЕ v3.6.3:
 * 🎨 Збалансований дизайн JS Challenge (видніше, особливо по центру)
 * 🎨 Радіальне світіння по центру екрану
 * 🎨 502 помилка в такому ж темному стилі
 * 🎨 Автоматичне оновлення 502 через 10 секунд
 * 🎨 Краща видимість але все ще непомітно
 * 
 * НОВЕ v3.6.2:
 * 🎨 Темний дизайн JS Challenge (майже непомітний на чорному фоні)
 * 🎨 Мінімалістичний інтерфейс
 * 🎨 Знижена яскравість всіх елементів
 * 🎨 Коротший текст повідомлень
 * 
 * ВИПРАВЛЕННЯ v3.6.1:
 * 🔧 Розширений список Google ботів в _is_seo_bot()
 * 🔧 Додано Google-InspectionTool (для GSC)
 * 🔧 Додано всі варіанти Google ботів (AdsBot, APIs-Google, тощо)
 * 🔧 Синхронізовано з searchEngines в класі SimpleBotProtection
 * 🔧 Виправлено 503 помилку в Google Search Console
 * 
 * ВЕРСІЯ 3.6.0 - SEO OPTIMIZATION + CUSTOM USER AGENTS (2026-01-14)
 * 
 * НОВЕ v3.6.0:
 * ✅ Розширений whitelist пошукових систем (40+ ботів)
 * ✅ Соціальні мережі (Instagram, Pinterest, LinkedIn, TikTok та ін.)
 * ✅ Моніторинг та аналітика (Pingdom, UptimeRobot, GTmetrix та ін.)
 * ✅ Власні User Agents - whitelist для ваших сервісів
 * ✅ Раннє виявлення ботів (перевірка ПЕРЕД Rate Limit)
 * ✅ Окремі ліміти для верифікованих ботів
 * ✅ Автоматичне логування SEO ботів
 * ✅ Швидка перевірка без Redis overhead для ботів
 * 
 * SEO БОТИ (автоматично пропускаються):
 * - Google (Googlebot, Google-InspectionTool, AdsBot, APIs-Google)
 * - Yandex (YandexBot, YandexImages, YandexMetrika)
 * - Bing (Bingbot, BingPreview, msnbot)
 * - Baidu (Baiduspider)
 * - DuckDuckGo (DuckDuckBot)
 * - Yahoo (Slurp)
 * - Seznam (SeznamBot)
 * - Sogou (Sogou Spider)
 * - Exabot
 * - Applebot (Apple)
 * - Screaming Frog SEO Spider
 * - Semrush, Ahrefs, Majestic
 * 
 * СОЦІАЛЬНІ МЕРЕЖІ:
 * - Facebook (facebookexternalhit, facebookcatalog)
 * - Twitter/X (Twitterbot)
 * - Instagram (Instagram)
 * - Pinterest (Pinterest)
 * - LinkedIn (LinkedInBot)
 * - TikTok (TikTok, Bytespider)
 * - WhatsApp, Telegram, Viber
 * - Discord, Slack
 * 
 * МОНІТОРИНГ:
 * - Pingdom, UptimeRobot, StatusCake
 * - GTmetrix, WebPageTest
 * - Lighthouse
 * 
 * НАЛАШТУВАННЯ ВЛАСНИХ USER AGENTS:
 * $protection->addCustomUserAgent('MyApp/1.0');
 * $protection->addCustomUserAgent('MyBot');
 * $protection->setCustomUserAgents(['MyApp/1.0', 'MyBot', 'MyCrawler']);
 * 
 * ============================================================================
 */

// ============================================================================
// КОНФІГУРАЦІЯ ВЛАСНИХ USER AGENTS (НАЙВИЩИЙ ПРІОРИТЕТ)
// ============================================================================

/**
 * ВАЖЛИВО! Власні User Agents перевіряються ПЕРЕД JS Challenge!
 * 
 * Додай сюди унікальні User Agents своїх сервісів/ботів:
 * - Моніторинг (Pingdom, UptimeRobot, StatusCake)
 * - Власні краулери та скрейпери
 * - Внутрішні сервіси компанії
 * - API клієнти
 * 
 * ⚠️ УВАГА: НЕ використовуй занадто загальні паттерни!
 * ❌ ПОГАНО: 'Android', 'Windows', 'Mozilla', 'Chrome'
 * ✅ ДОБРЕ: 'MyCompany-Monitor', 'MyBot/1.0', 'InternalService'
 */
$CUSTOM_USER_AGENTS = array(
    // Додай свої User Agents тут:
    'hosttracker',           // ✅ OK - моніторинг
    //'nexus',                 // ⚠️ Може збігатися з Nexus телефонами
    // 'Android',            // ❌ НЕ ДОДАВАЙ! Це заблокує всі Android пристрої!
    
    // Приклади правильних паттернів:
    // 'MyCompany-Monitor/1.0',
    // 'InternalBot',
    // 'API-Client-v2',
);

// ============================================================================
// КОНФІГУРАЦІЯ JS CHALLENGE
// ============================================================================

$_JSC_CONFIG = array(
    'enabled' => true,
    'secret_key' => 'CHANGE_THIS_SECRET_KEY_123!',  // !!! ЗМІНИ НА СВІЙ !!!
    'cookie_name' => 'mk_verified',
    'token_lifetime' => 86400,  // 24 години
);

// ============================================================================
// ШВИДКА ПЕРЕВІРКА ВЛАСНИХ USER AGENTS (ПЕРЕД JS CHALLENGE!)
// ============================================================================

/**
 * Перевірка чи User Agent в whitelist власних UA
 * Викликається ДО JS Challenge для негайного пропуску
 */
function _is_custom_ua($userAgent) {
    global $CUSTOM_USER_AGENTS;
    
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
            return true;
        }
    }
    
    return false;
}

/**
 * Швидка перевірка SEO ботів для раннього пропуску
 * ВАЖЛИВО! Цей список має співпадати з searchEngines в класі SimpleBotProtection
 */
function _is_seo_bot($userAgent) {
    if (empty($userAgent)) {
        return false;
    }
    
    $userAgentLower = strtolower($userAgent);
    
    // ========================================================================
    // РОЗШИРЕНИЙ СПИСОК ПОШУКОВИХ СИСТЕМ (v3.6.1)
    // ========================================================================
    
    $seoBots = array(
        // GOOGLE (всі варіанти)
        'googlebot',                    // Основний краулер
        'google-inspectiontool',        // ⭐ Google Search Console!
        'adsbot-google',                // Реклама
        'apis-google',                  // API Google
        'mediapartners-google',         // AdSense
        'googleother',                  // Інші сервіси
        'google-site-verification',     // Верифікація сайту
        'googlebot-image',              // Зображення
        'googlebot-news',               // Новини
        'googlebot-video',              // Відео
        'google-structured-data',       // Structured data
        
        // YANDEX (всі варіанти)
        'yandexbot',
        'yandex',
        'yandexmetrika',
        'yandexwebmaster',
        'yandexdirect',
        'yandexmobilebot',
        'yandeximages',
        
        // BING/MICROSOFT
        'bingbot',
        'bingpreview',
        'msnbot',
        'adidxbot',
        
        // ІНШІ ПОШУКОВІ СИСТЕМИ
        'duckduckbot',          // DuckDuckGo
        'baiduspider',          // Baidu
        'slurp',                // Yahoo
        'seznambot',            // Seznam
        'sogou',                // Sogou
        'exabot',               // Exalead
        'applebot',             // Apple
        
        // SEO TOOLS
        'screaming frog',       // Screaming Frog SEO Spider
        'semrushbot',           // Semrush
        'ahrefsbot',            // Ahrefs
        'mj12bot',              // Majestic
        'sitebulb',             // Sitebulb
        
        // СОЦІАЛЬНІ МЕРЕЖІ
        'facebookexternalhit',  // Facebook
        'facebookcatalog',      // Facebook Catalog
        'twitterbot',           // Twitter/X
        'pinterest',            // Pinterest
        'linkedinbot',          // LinkedIn
        'instagram',            // Instagram
        'tiktok',               // TikTok
        'bytespider',           // ByteDance/TikTok
        'whatsapp',             // WhatsApp
        'telegram',             // Telegram
        'viber',                // Viber
        'discordbot',           // Discord
        'slackbot',             // Slack
        
        // МОНІТОРИНГ
        'pingdom',              // Pingdom
        'uptimerobot',          // UptimeRobot
        'statuscake',           // StatusCake
        'gtmetrix',             // GTmetrix
        'webpagetest',          // WebPageTest
        'lighthouse',           // Google Lighthouse
        'chrome-lighthouse',    // Chrome Lighthouse
    );
    
    foreach ($seoBots as $bot) {
        if (strpos($userAgentLower, $bot) !== false) {
            return true;
        }
    }
    
    return false;
}

// ============================================================================
// JS CHALLENGE ФУНКЦІЇ
// ============================================================================

function _jsc_getClientIP() {
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        return $_SERVER['HTTP_CF_CONNECTING_IP'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        return trim($ips[0]);
    } elseif (!empty($_SERVER['HTTP_X_REAL_IP'])) {
        return $_SERVER['HTTP_X_REAL_IP'];
    }
    return isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '0.0.0.0';
}

function _jsc_isVerified($secret_key, $cookie_name) {
    if (!isset($_COOKIE[$cookie_name])) {
        return false;
    }
    $cookie = $_COOKIE[$cookie_name];
    if (strlen($cookie) !== 64) {
        return false;
    }
    $ip = _jsc_getClientIP();
    $expected = hash('sha256', $ip . date('Y-m-d') . $secret_key);
    return hash_equals($expected, $cookie);
}

function _jsc_generateChallenge($secret_key) {
    $id = md5(uniqid(mt_rand(), true));
    $timestamp = time();
    $numbers = array();
    for ($i = 0; $i < 5; $i++) {
        $numbers[] = mt_rand(10, 99);
    }
    $answer = array_sum($numbers);
    $target = hash('sha256', $id . $timestamp . $answer . $secret_key);
    return array(
        'id' => $id,
        'timestamp' => $timestamp,
        'numbers' => $numbers,
        'target' => $target,
        'difficulty' => 3
    );
}

function _jsc_showChallengePage($challenge, $redirect_url) {
    $challengeJson = json_encode($challenge);
    $redirectJson = json_encode($redirect_url);
    
    http_response_code(503);
    header('Content-Type: text/html; charset=UTF-8');
    header('Cache-Control: no-cache, no-store, must-revalidate');
    header('Retry-After: 5');
    
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
                Проверка безопасности
            </div>
            <div class="windowbg">
                <div class="spinner"></div>
                <div class="info-text">
                    <strong>Пожалуйста, подождите...</strong><br>
                    Выполняется автоматическая проверка вашего браузера для защиты от автоматизированных запросов.
                </div>
                <div class="progress-bar">
                    <div class="progress-fill" id="progress"></div>
                </div>
                <div class="status" id="status">Инициализация проверки...</div>
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
        var errorEl = document.getElementById("error");
        
        function updateProgress(percent, message) {
            progressBar.style.width = percent + "%";
            statusEl.textContent = message;
        }
        
        function showError(message) {
            errorEl.textContent = message;
            errorEl.style.display = "block";
            statusEl.textContent = "Ошибка проверки";
        }
        
        function sleep(ms) {
            return new Promise(function(resolve) { setTimeout(resolve, ms); });
        }
        
        async function performChallenge() {
            try {
                updateProgress(20, "Проверка JavaScript...");
                await sleep(500);
                
                updateProgress(40, "Проверка cookies...");
                await sleep(300);
                
                updateProgress(60, "Вычисление задачи...");
                var answer = challengeData.numbers.reduce(function(sum, num) { return sum + num; }, 0);
                
                updateProgress(80, "Отправка решения...");
                
                var xhr = new XMLHttpRequest();
                xhr.open("POST", window.location.href, true);
                xhr.setRequestHeader("Content-Type", "application/json");
                xhr.setRequestHeader("X-JSC-Response", "1");
                
                xhr.onload = function() {
                    if (xhr.status === 200) {
                        try {
                            var result = JSON.parse(xhr.responseText);
                            if (result.success) {
                                updateProgress(100, "Проверка завершена!");
                                statusEl.className = "status success";
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
                
                xhr.send(JSON.stringify({
                    challenge_id: challengeData.id,
                    answer: answer,
                    timestamp: challengeData.timestamp
                }));
                
            } catch (error) {
                showError("Не удалось пройти проверку. Обновите страницу.");
            }
        }
        
        window.addEventListener("load", function() {
            setTimeout(performChallenge, 1000);
        });
    </script>
</body>
</html>';
    exit;
}

// ============================================================================
// ФУНКЦІЯ ЛОГУВАННЯ JS CHALLENGE СТАТИСТИКИ
// ============================================================================
function _jsc_logStats($event, $ip = null) {
    try {
        $redis = new Redis();
        $redis->connect('127.0.0.1', 6379, 1);
        $redis->select(1);
        $redis->setOption(Redis::OPT_SERIALIZER, Redis::SERIALIZER_PHP);
        
        $prefix = 'bot_protection:jsc_stats:';
        $today = date('Y-m-d');
        $hour = date('Y-m-d:H');
        
        // Загальна статистика
        $redis->incr($prefix . 'total:' . $event);
        $redis->incr($prefix . 'daily:' . $today . ':' . $event);
        $redis->expire($prefix . 'daily:' . $today . ':' . $event, 86400 * 7); // Зберігаємо 7 днів
        
        // Погодинна статистика
        $redis->incr($prefix . 'hourly:' . $hour . ':' . $event);
        $redis->expire($prefix . 'hourly:' . $hour . ':' . $event, 86400 * 2); // Зберігаємо 2 дні
        
        // Логування IP (для показу в адмінці)
        if ($ip && in_array($event, array('shown', 'passed', 'failed'))) {
            $logKey = $prefix . 'log:' . $event;
            $logEntry = array(
                'ip' => $ip,
                'time' => time(),
                'date' => date('Y-m-d H:i:s'),
                'ua' => isset($_SERVER['HTTP_USER_AGENT']) ? substr($_SERVER['HTTP_USER_AGENT'], 0, 200) : '-'
            );
            
            // Зберігаємо останні 100 записів
            $redis->lPush($logKey, $logEntry);
            $redis->lTrim($logKey, 0, 99);
            $redis->expire($logKey, 86400 * 7);
        }
        
        $redis->close();
    } catch (Exception $e) {
        error_log("JSC Stats logging error: " . $e->getMessage());
    }
}

// ============================================================================
// ОБРОБКА POST ЗАПИТУ JS CHALLENGE
// ============================================================================
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_SERVER['HTTP_X_JSC_RESPONSE'])) {
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-cache, no-store');
    
    $input = json_decode(file_get_contents('php://input'), true);
    $ip = _jsc_getClientIP();
    
    if (!$input || !isset($input['challenge_id']) || !isset($input['answer']) || !isset($input['timestamp'])) {
        _jsc_logStats('failed', $ip);
        echo json_encode(array('success' => false, 'error' => 'Invalid request'));
        exit;
    }
    
    $timestamp = (int)$input['timestamp'];
    
    if (time() - $timestamp > 300) {
        _jsc_logStats('expired', $ip);
        echo json_encode(array('success' => false, 'error' => 'Challenge expired'));
        exit;
    }
    
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
    
    // Логуємо успішне проходження
    _jsc_logStats('passed', $ip);
    
    echo json_encode(array('success' => true, 'token' => $token));
    exit;
}

// ============================================================================
// ШВИДКА ПЕРЕВІРКА БЛОКУВАННЯ
// ============================================================================

function _quick_block_check() {
    try {
        $redis = new Redis();
        $redis->connect('127.0.0.1', 6379, 1);
        $redis->select(1);
        
        $ip = _jsc_getClientIP();
        $prefix = 'bot_protection:';
        
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

// ============================================================================
// ПЕРЕВІРКА JS CHALLENGE (З ПРІОРИТЕТОМ WHITELIST)
// ============================================================================
if ($_JSC_CONFIG['enabled']) {
    $userAgent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
    $_jsc_skip = false;
    
    // ========================================================================
    // ПРІОРИТЕТ 1: ВЛАСНІ USER AGENTS (найвищий пріоритет!)
    // ========================================================================
    if (_is_custom_ua($userAgent)) {
        $_jsc_skip = true;
        // error_log вже зроблено в _is_custom_ua()
    }
    
    // ========================================================================
    // ПРІОРИТЕТ 2: SEO БОТИ
    // ========================================================================
    if (!$_jsc_skip && _is_seo_bot($userAgent)) {
        $_jsc_skip = true;
    }
    
    // ========================================================================
    // ПРІОРИТЕТ 3: СТАТИЧНІ ФАЙЛИ ТА AJAX
    // ========================================================================
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
    }
    
    // ========================================================================
    // ПОКАЗ JS CHALLENGE (тільки для звичайних користувачів)
    // ========================================================================
    if (!$_jsc_skip && !_jsc_isVerified($_JSC_CONFIG['secret_key'], $_JSC_CONFIG['cookie_name'])) {
        $challenge = _jsc_generateChallenge($_JSC_CONFIG['secret_key']);
        $currentUrl = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' ? 'https' : 'http') . 
                      '://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
        
        // Логуємо показ challenge
        _jsc_logStats('shown', _jsc_getClientIP());
        
        _jsc_showChallengePage($challenge, $currentUrl);
    }
}

// ============================================================================
// КЛАСС ЗАХИСТУ
// ============================================================================

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
        'cookie_multiplier' => 1.5,
        'js_verified_multiplier' => 2.0,
    );
    
    // Налаштування UA Rotation
    private $uaRotationSettings = array(
        'enabled' => true,
        'max_unique_ua_per_5min' => 10,
        'max_unique_ua_per_hour' => 20,
        'block_duration' => 7200,
        'tracking_window' => 3600,
    );
    
    // Налаштування API
    private $apiSettings = array(
        'enabled' => false,
        'url' => 'https://murkir.pp.ua/bot_blocker_api.php',
        'api_key' => 'your_api_key_here',
        'timeout' => 5,
        'retry_on_failure' => 2,
        'verify_ssl' => true,
        'user_agent' => 'BotProtection/3.6',
        'block_on_api' => true,
        'block_on_redis' => true,
    );
    
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
        'file' => '/tmp/search_bots.log',  // ⚠️ Повинен співпадати з redis-bot_admin.php!
        'max_size' => 1048576,
        'keep_backups' => 3,
        'log_host' => true,
        'log_url' => true,
        'log_ua' => true,
        'ua_max_length' => 100,
    );
    
    // ========================================================================
    // РОЗШИРЕНИЙ WHITELIST ПОШУКОВИХ СИСТЕМ (SEO v3.6.0)
    // ========================================================================
    
    private $searchEngines = array(
        // GOOGLE
        'google' => array(
            'user_agent_patterns' => array(
                'googlebot', 'google-inspectiontool', 'adsbot-google', 
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
                '119.63.192.0/21', '123.125.71.0/24', '180.76.0.0/16',
                '220.181.0.0/16',
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
    );
    
    // ========================================================================
    // ВЛАСНІ USER AGENTS (v3.6.0)
    // ========================================================================
    
    private $customUserAgents = array();
    
    public function __construct() {
        global $CUSTOM_USER_AGENTS;
        // Завантажуємо власні UA з глобальної конфігурації
        $this->customUserAgents = $CUSTOM_USER_AGENTS;
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
     * ГОЛОВНИЙ МЕТОД ЗАХИСТУ (з пріоритетом SEO)
     * ========================================================================
     */
    public function protect() {
        try {
            $ip = $this->getClientIP();
            $userAgent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
            
            // ================================================================
            // КРОК 1: ШВИДКА ПЕРЕВІРКА ВЛАСНИХ USER AGENTS (найвищий пріоритет)
            // ================================================================
            if ($this->isCustomUserAgent($userAgent)) {
                if ($this->debugMode) {
                    error_log("BOT PROTECTION: Custom User Agent detected, allowing: " . substr($userAgent, 0, 50));
                }
                return; // Пропускаємо власні UA
            }
            
            // ================================================================
            // КРОК 2: ПЕРЕВІРКА ПОШУКОВИХ СИСТЕМ (другий пріоритет)
            // ================================================================
            if ($this->isSearchEngineByIP($ip, $userAgent)) {
                if ($this->debugMode) {
                    error_log("BOT PROTECTION: Search engine verified by IP, allowing");
                }
                return; // Пошукові боти пропускаємо
            }
            
            // rDNS верифікація (якщо не пройшов IP whitelist)
            if ($this->verifySearchEngineRDNS($ip, $userAgent)) {
                if ($this->debugMode) {
                    error_log("BOT PROTECTION: Search engine verified by rDNS, allowing");
                }
                return; // Верифікований пошуковий бот
            }
            
            // ================================================================
            // КРОК 3: ПЕРЕВІРКА REDIS (якщо доступний)
            // ================================================================
            if (!$this->redis) {
                if ($this->debugMode) {
                    error_log("BOT PROTECTION: Redis not available, protection disabled");
                }
                return; // Якщо Redis недоступний - пропускаємо
            }
            
            // Debug logging
            if ($this->debugMode) {
                error_log("BOT PROTECTION: Checking IP=$ip, UA=" . substr($userAgent, 0, 50));
            }
            
            // ================================================================
            // КРОК 4: ПЕРЕВІРКИ ЗАХИСТУ (для звичайних користувачів)
            // ================================================================
            
            // Перевірка UA Rotation
            if ($this->checkUserAgentRotation($ip)) {
                error_log("BOT PROTECTION: UA rotation detected, blocking IP=$ip");
                $this->show502Error();
            }
            
            // Перевірка Rate Limit і Burst
            if ($this->checkRateLimit($ip)) {
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
        
        $full_bytes = floor($mask / 8);
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
    private function checkRateLimit($ip) {
        $now = time();
        $userId = $this->generateUserIdentifier();
        $hasCookie = $this->hasValidCookie();
        
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
        
        $multiplier = 1.0;
        if ($hasCookie) {
            $multiplier = $this->rateLimitSettings['cookie_multiplier'];
        }
        if ($this->isJSVerified()) {
            $multiplier = $this->rateLimitSettings['js_verified_multiplier'];
        }
        
        $limits = array(
            'minute' => (int)($this->rateLimitSettings['max_requests_per_minute'] * $multiplier),
            '5min' => (int)($this->rateLimitSettings['max_requests_per_5min'] * $multiplier),
            'hour' => (int)($this->rateLimitSettings['max_requests_per_hour'] * $multiplier),
            'burst' => (int)($this->rateLimitSettings['burst_threshold'] * $multiplier)
        );
        
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
     */
    private function callBlockingAPI($ip, $action = 'block') {
        if (!$this->apiSettings['enabled']) {
            return array('status' => 'disabled', 'message' => 'API disabled');
        }
        
        if (!$this->apiSettings['block_on_api']) {
            return array('status' => 'skipped', 'message' => 'API blocking disabled');
        }
        
        $url = $this->apiSettings['url'] .
               '?action=' . urlencode($action) .
               '&ip=' . urlencode($ip) .
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
                
                curl_setopt_array($ch, array(
                    CURLOPT_URL => $url,
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
                ));
                
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
}

// ============================================================================
// АВТОМАТИЧНИЙ ЗАХИСТ
// ============================================================================

$protection = new SimpleBotProtection();

// ============================================================================
// ПРИКЛАД ДИНАМІЧНОГО ДОДАВАННЯ ВЛАСНИХ USER AGENTS
// ============================================================================
// Якщо потрібно додати UA динамічно (після створення об'єкту):
/*
$protection->addCustomUserAgent('MyNewBot/1.0');
$protection->addCustomUserAgent('AnotherService');

// Або встанови масив:
$protection->setCustomUserAgents([
    'hosttracker',
    'nexus',
    'MyApp/1.0',
    'MyBot/2.0',
]);
*/

// ============================================================================
// ІНФОРМАЦІЯ ПРО ПОТОЧНІ НАЛАШТУВАННЯ
// ============================================================================
// Розкоментуй для перевірки:
/*
echo "Custom User Agents: " . print_r($protection->getCustomUserAgents(), true);
*/

// Запуск захисту
$protection->protect();

?>
