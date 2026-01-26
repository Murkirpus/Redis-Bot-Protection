<img src="/images/2026-01-15.png" alt="Демонстрация" width="800">

Не ругаются поисковики, их IP добавленны в исключения для всех их USER-AGENT!

Работает на https://dj-x.info/
Убирает 95% не нужных запросов!

пароль: info@murkir.pp.ua

Подключается в index.php в верху страницы.  
require_once $_SERVER['DOCUMENT_ROOT'] . '/js_challenge_lite/inline_check_lite.php';

Или здесь  
/etc/php/8.3/fpm/pool.d/php8.conf  
php_admin_value[auto_prepend_file] = "/home/myuser/dj-x.info/js_challenge_lite/inline_check_lite.php"


