# Redis MurKir Security v2.0

Много всего изменено и доделано!
Теперь при блокировке одного браузера или бота на одном IP не блокируются другие!
И это хорошо!
Крон-задача для очистки Redis 
0 3 * * * cd /home/user/site/bot_protection && php cleanup.php --force >> /var/log/bot-cleanup.log 2>&1
