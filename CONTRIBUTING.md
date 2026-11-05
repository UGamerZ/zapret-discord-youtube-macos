# Участие в разработке / Contributing

Issues и pull requests принимаются на русском и английском. / Russian and English reports and pull requests are welcome.

## Отчёты

Используйте [формы Issues](https://github.com/UGamerZ/zapret-discord-youtube-macos/issues/new/choose). Для ошибки нужны версия macOS и приложения, процессор, интерфейс, профиль, шаги воспроизведения и фактическое сообщение. Для проверки обхода сравните результат без zapret и с ним на одной сети; отдельно укажите сайт, видео и голос. Полный IP, домашний адрес, пароли и неотредактированные личные журналы не нужны.

## Изменения кода

1. Создайте fork и отдельную ветку.
2. Для сборки выполните `./scripts/build.sh`, для автономных проверок — `./scripts/test.sh`.
3. Опишите проблему, изменение поведения и проверку в pull request.

Изменения интерфейса сопровождайте скриншотом. Изменения транспорта и обработки пакетов проверяйте на соответствующих IPv4/IPv6 сценариях и в PCAP-тестах. Автономные тесты не заменяют сетевую проверку с правами администратора: отдельно отмечайте, что именно проверено в реальной сети.

Не меняйте зафиксированные BAT, бинарные шаблоны или upstream-движок без необходимости. При обновлении источников сохраняйте атрибуцию и лицензии, обновляйте `THIRD_PARTY.md` и импорт профилей. Не объединяйте повторяющиеся параметры fake-TLS: порядок и повторы влияют на результат.

CI собирает универсальное приложение и запускает автономные проверки на Apple Silicon и Intel. Он не включает привилегированный перехват и не проверяет обход блокировок.

## Contributor quick start

Build with `./scripts/build.sh`, then run `./scripts/test.sh`. Preserve upstream provenance, licenses, argument order and repeated fake options. Describe validation and its limits in your PR. Do not claim live bypass based only on PCAP replay. See [SECURITY.md](SECURITY.md) for private vulnerability reports.
