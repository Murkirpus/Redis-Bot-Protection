# Redis MurKir Security v2.0 - Полное описание системы

## 🛡️ Что это такое?

**Redis MurKir Security v2.0** - это продвинутая система защиты веб-сайтов от автоматизированных ботов, скреперов и вредоносного трафика. Система работает в реальном времени, анализируя поведение посетителей и блокируя подозрительную активность.

## 🎯 От кого защищает?

### ✅ **Эффективно блокирует:**

**1. Автоматизированные боты:**
- cURL, wget, Python requests
- Selenium WebDriver, Puppeteer
- Headless браузеры (Chrome --headless)
- Скрипты парсинга и скрейпинга

**2. Вредоносный трафик:**
- DDoS атаки малой и средней интенсивности
- Брутфорс атаки на формы
- Автоматизированный спам
- Накрутка просмотров

**3. Нежелательные сканеры:**
- Сканеры уязвимостей
- SEO-боты (кроме разрешенных)
- Контент-парсеры
- Автоматические мониторинги цен

**4. Подозрительное поведение:**
- Слишком быстрая навигация (>50-200 запросов/мин)
- Регулярные интервалы между запросами
- Отсутствие стандартных браузерных заголовков
- Множественные User-Agent с одного IP

### ❌ **НЕ блокирует (безопасно пропускает):**

**1. Легитимные поисковые боты:**
- Googlebot, Bingbot, Yandexbot
- Проверяется по rDNS + User-Agent
- Автоматическое whitelisting

**2. Обычные пользователи:**
- Настоящие браузеры (Chrome, Firefox, Safari)
- Мобильные устройства оптимизированы
- Множественные браузеры на одном IP

**3. Мониторинг сервисы:**
- Uptime Robot, Pingdom, StatusCake
- CDN сервисы (Cloudflare, Fastly)
- Архивы (Archive.org)

## 🔧 Как работает система?

### **Многоуровневая защита:**

**1. Уровень IP анализа:**
```
Посетитель → Анализ частоты запросов → Проверка заголовков → Решение
```

**2. Уровень хеш-анализа (v2.0):**
```
Браузерный отпечаток → Уникальный хеш → Отслеживание поведения → Блокировка
```

**3. Уровень сессий/cookies:**
```
Cookie проверка → Сессия активность → Поведенческий анализ → Решение
```

### **Алгоритм принятия решений:**

```
1. Статические файлы → ПРОПУСК
2. Поисковые боты → ПРОВЕРКА rDNS → ПРОПУСК/БЛОК
3. Хеш заблокирован? → БЛОК
4. IP/Сессия/Cookie заблокированы? → БЛОК
5. Валидный cookie? → АНАЛИЗ ПОВЕДЕНИЯ → РЕШЕНИЕ
6. Новый пользователь → СОЗДАНИЕ COOKIE → ПРОПУСК
```

### **Поведенческий анализ включает:**

- **Скорость запросов** (запросов в минуту)
- **Регулярность интервалов** (бот-паттерны)
- **Разнообразие страниц** (монотонность поведения)
- **HTTP заголовки** (полнота и корректность)
- **User-Agent анализ** (подозрительные паттерны)
- **Множественность устройств** на IP

## 🔌 Как подключать?

### **1. Требования системы:**

**PHP версии:**
- ✅ **PHP 7.4+** (рекомендуется)
- ✅ **PHP 8.0+** (оптимально)
- ✅ **PHP 8.1, 8.2, 8.3** (полная поддержка)
- ❌ PHP 7.3 и ниже (не поддерживается)

**Зависимости:**
- **Redis 4.0+** (обязательно)
- **php-redis расширение** (обязательно)
- **Sessions поддержка** (включена по умолчанию)

**Проверка совместимости:**
```php
<?php
// Проверьте эти требования
echo "PHP версия: " . PHP_VERSION . "\n";
echo "Redis расширение: " . (extension_loaded('redis') ? 'ДА' : 'НЕТ') . "\n";
echo "Sessions: " . (function_exists('session_start') ? 'ДА' : 'НЕТ') . "\n";
?>
```

### **2. Установка Redis:**

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install redis-server php-redis
sudo systemctl start redis
sudo systemctl enable redis
```

**CentOS/RHEL:**
```bash
sudo yum install redis php-redis
sudo systemctl start redis
sudo systemctl enable redis
```

**Проверка Redis:**
```bash
redis-cli ping
# Должно вернуть: PONG
```

### **3. Базовое подключение:**

**Скачайте файлы:**
```
/your-site/bot_protection/
├── inline_check.php          # Основной файл защиты
├── redis-admin.php           # Панель администратора  
├── redis_test.php            # Тестовая страница
└── README.txt                # Документация
```

**Подключение в начале каждой PHP страницы:**
```php
<?php
// В самом начале страницы, до любого вывода
require_once '/path/to/bot_protection/inline_check.php';

try {
    $protection = new RedisBotProtectionWithSessions(
        '127.0.0.1',    // Redis host
        6379,           // Redis port  
        null,           // Redis password (если есть)
        0               // Redis database (обычно 0)
    );
    
    $protection->protect();
    
} catch (Exception $e) {
    error_log("Bot protection error: " . $e->getMessage());
    // Продолжаем работу без защиты в случае ошибки
}

// Ваш обычный код страницы
?>
<!DOCTYPE html>
<html>
...
```

### **4. Автоматическое подключение:**

**Через .htaccess (простой способ):**
```apache
# Добавьте в .htaccess
php_value auto_prepend_file "/full/path/to/bot_protection/inline_check.php"
```

**Через PHP-FPM pool (рекомендуется для VPS/выделенных серверов):**
```ini
# Добавьте в /etc/php/7.4/fpm/pool.d/your-site.conf
# или в существующий pool конфиг

; Подключение защиты от ботов с сессиями
php_admin_value[auto_prepend_file] = "/home/user/site/bot_protection/inline_check.php"

# После изменения перезапустите PHP-FPM:
# sudo systemctl reload php7.4-fpm
```

**Преимущества PHP-FPM подключения:**
- ✅ Работает на уровне процесса (быстрее)
- ✅ Не зависит от .htaccess
- ✅ Централизованное управление
- ✅ Работает с любыми веб-серверами (Nginx + PHP-FPM)
- ✅ Более безопасно (системный уровень)

**Через php.ini (глобально для всех сайтов):**
```ini
; Добавьте в php.ini (осторожно - для всех сайтов!)
auto_prepend_file = "/full/path/to/bot_protection/inline_check.php"
```

**Через WordPress (functions.php):**
```php
// Добавьте в functions.php темы
add_action('init', function() {
    if (!is_admin()) {
        require_once '/path/to/bot_protection/inline_check.php';
        
        try {
            $protection = new RedisBotProtectionWithSessions();
            $protection->protect();
        } catch (Exception $e) {
            error_log("Bot protection error: " . $e->getMessage());
        }
    }
});
```

**Через Nginx + PHP-FPM (серверный уровень):**
```nginx
# В конфигурации Nginx location блока
location ~ \.php$ {
    fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
    fastcgi_param PHP_VALUE "auto_prepend_file=/home/user/site/bot_protection/inline_check.php";
    # остальные fastcgi параметры...
}
```

## ⚙️ Настройка конфигурации

### **Обязательные настройки:**

**1. Смените секретный ключ:**
```php
private $secretKey = 'ваш_уникальный_ключ_минимум_32_символа_2025';
```

**2. Настройте Redis подключение:**
```php
$protection = new RedisBotProtectionWithSessions(
    'localhost',        // или IP вашего Redis сервера
    6379,              // порт Redis  
    'password',        // пароль Redis (если установлен)
    0                  // номер базы данных
);
```

### **Дополнительные настройки:**

**Мягкий режим (для сайтов с высоким трафиком):**
```php
// В analyzeUserHashBehavior() измените:
$blockThreshold = $isMobile ? 40 : 30;  // вместо 25:12

// В ttlSettings измените:
'ip_blocked' => 600,                    // 10 минут вместо 30
'user_hash_blocked' => 1800,            // 30 минут вместо 2 часов
```

## 📊 Мониторинг и управление

### **Панель администратора:**
```
https://your-site.com/bot_protection/redis-admin.php
```
**Функции:**
- Просмотр заблокированных IP/хешей
- Разблокировка пользователей
- Статистика блокировок
- Очистка данных
- Мониторинг активности

### **Тестовая страница:**
```
https://your-site.com/bot_protection/redis_test.php  
```
**Функции:**
- Проверка работы защиты
- Информация о текущем пользователе
- Тестирование различных сценариев
- Debug информация

### **Логирование:**
```bash
# Мониторинг блокировок в реальном времени
tail -f /var/log/apache2/error.log | grep "blocked"

# Статистика Redis
redis-cli keys "bot_protection:*" | wc -l
```

## 🔍 Диагностика проблем

### **Частые проблемы и решения:**

**1. "Redis connection failed"**
```bash
# Проверьте статус Redis
sudo systemctl status redis
redis-cli ping

# Проверьте PHP расширение
php -m | grep redis
```

**2. "Блокируются обычные пользователи"**
```php
// Увеличьте пороги блокировки
$blockThreshold = $isMobile ? 40 : 30;
'ip_blocked' => 300,  // 5 минут вместо 30
```

**3. "Боты проходят защиту"**
```php
// Уменьшите пороги
$blockThreshold = $isMobile ? 15 : 10;
if ($trackingData['requests'] < 3) // вместо 5
```

**4. "Мобильные браузеры блокируют друг друга"**
```php
// ✅ Уже исправлено в v2.0!
// Используется lastOctet IP для различия браузеров
```

## 📈 Производительность

### **Системные требования:**

**Минимальные:**
- 1 CPU ядро
- 512 MB RAM  
- 100 MB свободного места
- Redis 50 MB RAM

**Рекомендуемые:**
- 2+ CPU ядра
- 2+ GB RAM
- 1 GB свободного места  
- Redis 200+ MB RAM

### **Нагрузка на систему:**

**При 1000 посетителей/час:**
- Redis память: ~50-100 MB
- PHP память: +5-10 MB на запрос
- CPU нагрузка: +5-15%
- Задержка ответа: +5-50 мс

**Оптимизация:**
- Включите Redis persistence
- Настройте TTL оптимально
- Используйте мягкие режимы для высокого трафика

## 🛠️ Интеграция с популярными CMS

### **WordPress:**
```php
// functions.php
add_action('template_redirect', function() {
    require_once '/path/to/inline_check.php';
    $protection = new RedisBotProtectionWithSessions();
    $protection->protect();
});
```

### **Laravel:**
```php
// Middleware
php artisan make:middleware BotProtection

// В BotProtection.php
public function handle($request, Closure $next) {
    require_once '/path/to/inline_check.php';
    $protection = new RedisBotProtectionWithSessions();
    $protection->protect();
    return $next($request);
}
```

### **Drupal:**
```php
// settings.php
$settings['container_yamls'][] = '/path/to/bot_protection_services.yml';
// Или через hook_init()
```

## 🔒 Безопасность

### **Что система НЕ заменяет:**
- ❌ Firewall (iptables/ufw)
- ❌ DDoS защиту провайдера  
- ❌ SSL/TLS шифрование
- ❌ Антивирус на сервере
- ❌ Backup стратегию

### **Рекомендации по безопасности:**
- Регулярно обновляйте secretKey
- Мониторьте логи ошибок
- Настройте Redis аутентификацию
- Ограничьте доступ к админ панели
- Делайте бэкапы настроек

## 📋 Итоговые рекомендации

### **Для большинства сайтов:**
1. Установите с настройками по умолчанию
2. Смените secretKey на уникальный
3. Мониторьте 1-2 недели
4. Корректируйте при необходимости

### **Система готова к работе сразу после установки!**

**Версия:** v2.0  
**Статус:** Стабильная  
**Совместимость:** PHP 7.4+ / Redis 4.0+  
**Лицензия:** Проприетарная  
**Поддержка:** Через логи и админ панель

Redis Bot Protection v2.0 - Полное руководство по настройке
===========================================================

🎯 ОСНОВНЫЕ НАСТРОЙКИ (минимальные изменения в коде)

1. СТРОГОСТЬ БЛОКИРОВКИ ХЕШЕЙ
─────────────────────────────────
Найти в analyzeUserHashBehavior():
$blockThreshold = $isMobile ? 25 : 12;

Варианты замены:
• Мягко:     $blockThreshold = $isMobile ? 40 : 30;
• Средне:    $blockThreshold = $isMobile ? 35 : 20;
• Строго:    $blockThreshold = $isMobile ? 15 : 8;

2. ВРЕМЯ БЛОКИРОВКИ (в ttlSettings)
──────────────────────────────────
'ip_blocked' => 1800,                    // IP блокировка
'user_hash_blocked' => 7200,             // Хеш блокировка  
'session_blocked' => 21600,              // Сессия блокировка
'cookie_blocked' => 14400,               // Cookie блокировка

Варианты для мягкой защиты:
• 'ip_blocked' => 300,                   // 5 минут
• 'user_hash_blocked' => 1800,           // 30 минут
• 'session_blocked' => 3600,             // 1 час

3. ПРИОРИТЕТ ХЕША НАД IP
───────────────────────────
В методе protect() найти:
} else {
    $this->blockIP($ip);
}

Заменить на:
} else {
    // НЕ блокируем IP, только хеш
}

4. МОБИЛЬНЫЕ ХЕШИ (ИСПРАВЛЕНО!)
─────────────────────────────────
В generateUserHash() используется:
if ($this->isMobileDevice($userAgent)) {
    $ipParts = explode('.', $ip);
    $lastOctet = end($ipParts);
    $fingerprint .= '|' . $lastOctet;
} else {
    $fingerprint .= '|' . $ip;
}

✅ Это правильно - разные браузеры = разные хеши!

5. МИНИМУМ ЗАПРОСОВ ДЛЯ АНАЛИЗА
──────────────────────────────────
В analyzeUserHashBehavior() найти:
if ($trackingData['requests'] < 5) {

Варианты:
• Быстро:    if ($trackingData['requests'] < 3) {
• Средне:    if ($trackingData['requests'] < 8) {
• Медленно:  if ($trackingData['requests'] < 15) {

В shouldAnalyzeIP() найти:
if ($requests > 5) {

Варианты:
• Мягко:     if ($requests > 15) {
• Средне:    if ($requests > 8) {
• Строго:    if ($requests > 3) {

🛡️ ГОТОВЫЕ РЕЖИМЫ ЗАЩИТЫ

ОЧЕНЬ МЯГКИЙ РЕЖИМ (семьи, офисы, общий WiFi)
────────────────────────────────────────────────
$blockThreshold = $isMobile ? 50 : 40;
'ip_blocked' => 300,
'user_hash_blocked' => 900,
if ($trackingData['requests'] < 20) {
if ($requests > 20) {

СБАЛАНСИРОВАННЫЙ РЕЖИМ (рекомендуемый)
─────────────────────────────────────────
$blockThreshold = $isMobile ? 35 : 25;
'ip_blocked' => 600,
'user_hash_blocked' => 1800,
if ($trackingData['requests'] < 8) {
if ($requests > 10) {

СТРОГИЙ РЕЖИМ (высокая защита)
─────────────────────────────────
$blockThreshold = $isMobile ? 20 : 15;
'ip_blocked' => 1800,
'user_hash_blocked' => 3600,
if ($trackingData['requests'] < 3) {
if ($requests > 5) {

⚡ БЫСТРЫЕ ИСПРАВЛЕНИЯ ЧАСТЫХ ПРОБЛЕМ

Проблема: "Блокируется вся семья на одном IP"
Решение: 
• Увеличить $blockThreshold до 40+
• Уменьшить 'ip_blocked' до 300 сек
• Убрать $this->blockIP($ip); в protect()

Проблема: "Мобильные браузеры блокируют друг друга"  
Решение: ✅ УЖЕ ИСПРАВЛЕНО в коде!
• Используется lastOctet IP для различия

Проблема: "IP блокируется слишком часто"
Решение:
• Убрать все $this->blockIP($ip);
• Оставить только $this->blockUserHash();
• Увеличить shouldAnalyzeIP пороги

Проблема: "Боты проходят защиту"
Решение:
• Уменьшить $blockThreshold
• Уменьшить минимум запросов для анализа
• Проверить suspicious user agents

Проблема: "Долгие блокировки"
Решение:
• 'ip_blocked' => 300,
• 'user_hash_blocked' => 900,

🔧 ГДЕ ИСКАТЬ В КОДЕ (inline_check.php)

├── analyzeUserHashBehavior()        → пороги блокировки хешей
├── analyzeRequest()                 → пороги блокировки IP  
├── shouldAnalyzeIP()               → условия анализа IP
├── generateUserHash()              → создание хешей (мобильные исправлены)
├── protect()                       → основная логика защиты
├── ttlSettings                     → время блокировок
└── isSuspiciousUserAgent()         → определение ботов

🔑 ОБЯЗАТЕЛЬНЫЕ НАСТРОЙКИ

СЕКРЕТНЫЙ КЛЮЧ (КРИТИЧНО!)
─────────────────────────
private $secretKey = 'your_secret_key_here_change_this';

⚠️ ОБЯЗАТЕЛЬНО СМЕНИТЕ НА:
private $secretKey = 'ваш_уникальный_ключ_минимум_32_символа_2025';

COOKIE НАСТРОЙКИ
───────────────
private $cookieName = 'visitor_verified';      // Можно сменить
private $cookieLifetime = 86400 * 30;          // 30 дней, можно изменить

📊 НОВЫЕ ВОЗМОЖНОСТИ v2.0

✅ Блокировка по хешу пользователя
✅ Исправленные мобильные хеши (разные браузеры)
✅ Оптимизированные TTL настройки
✅ Приоритет хеш-блокировки над IP
✅ Улучшенная детекция мобильных устройств
✅ Расширенная админ панель
✅ Подробная статистика и логирование

⚠️ ОПАСНЫЕ НАСТРОЙКИ (НЕ ТРОГАТЬ БЕЗ ЭКСПЕРТИЗЫ)

❌ НЕ ИЗМЕНЯЙТЕ:
• Префиксы Redis ключей (bot_protection:, tracking: и т.д.)
• Алгоритмы хеширования (hash('sha256', ...))
• Логику isMobileDevice()
• Паттерны suspicious user agents
• Настройки allowedSearchEngines
• Структуру generateUserHash() - уже оптимизирована!

🚨 ВАЖНЫЕ ЗАМЕЧАНИЯ

• Всегда делайте БЭКАП перед изменениями
• Тестируйте на тестовом сайте
• Мониторьте логи 24-48 часов после изменений
• Изменяйте по ОДНОМУ параметру за раз
• Начинайте с более мягких настроек

📊 МОНИТОРИНГ И ДИАГНОСТИКА

Логи блокировок:
tail -f /var/log/apache2/error.log | grep "blocked"
tail -f /var/log/apache2/error.log | grep "Hash analysis"

Статистика Redis:
redis-cli keys "bot_protection:*" | wc -l
redis-cli keys "bot_protection:user_hash:*" | wc -l

Админ панель v2.0:
https://ваш-сайт.com/dos/bot_protection/redis-admin.php

Тест системы:
https://ваш-сайт.com/dos/bot_protection/redis_test.php

🎛️ РЕКОМЕНДАЦИИ ПО ТИПУ САЙТА

📰 НОВОСТНОЙ САЙТ (активное чтение)
──────────────────────────────────
$blockThreshold = $isMobile ? 45 : 35;
'user_hash_blocked' => 900,
if ($trackingData['requests'] < 15) {

🛍️ ИНТЕРНЕТ-МАГАЗИН (изучение товаров)
─────────────────────────────────────
$blockThreshold = $isMobile ? 30 : 25;
'user_hash_blocked' => 1800,
if ($trackingData['requests'] < 8) {

📝 БЛОГ/КОНТЕНТ (средняя активность)
──────────────────────────────────
Текущие настройки оптимальны!

🔐 API/SaaS (особые правила)
──────────────────────────
Рассмотрите создание отдельного класса наследника

🎯 ТЕКУЩИЙ СТАТУС СИСТЕМЫ

При правильной настройке системы:
✅ Заблокированные боты: эффективно
✅ Ложные срабатывания: минимальны  
✅ Мобильные устройства: работают корректно
✅ Множественные браузеры: не блокируют друг друга

💡 РЕКОМЕНДАЦИЯ ДЛЯ БОЛЬШИНСТВА САЙТОВ

Оптимальные настройки для старта:
1. Смените secretKey
2. Установите мягкий режим:
   $blockThreshold = $isMobile ? 40 : 30;
   'ip_blocked' => 600,
   'user_hash_blocked' => 1800,
3. Мониторьте 1-2 недели
4. Корректируйте при необходимости

🆘 ПОДДЕРЖКА

Логи: /var/log/apache2/error.log
Админка: redis-admin.php  
Тесты: redis_test.php
Статистика: $protection->getStats()

Версия: v2.0
Последнее обновление: 2025-07-05
Статус: Стабильная версия с исправленными мобильными хешами
