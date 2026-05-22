# План реализации

Репозиторий сейчас пустой. План ниже рассчитан на реализацию с нуля, без внешних
зависимостей кроме libc, с дефолтной статической сборкой через musl.

1. `build: add root makefile and project skeleton`
Создать `Makefile` в корне, добавить дефолтный `CC ?= musl-gcc`, цель `all`,
цель `static`, цель `clean`, каталог `cmd/udump/`, каталог `docs/`, пустой
`README.md`. На этом шаге должен собираться пустой каркас без функционала.

2. `udump: add minimal main and argument parsing`
Добавить `cmd/udump/main.c` с линейным `main()`, разбором обязательных
`-i <ifname>` и `-w <output_file>`, плюс остатка argv как текста фильтра. Без
сложных слоёв: только проверка аргументов, usage и каркас запуска.

3. `udump: add raw packet capture on linux`
Добавить открытие `AF_PACKET`/`SOCK_RAW`, bind к интерфейсу через
`if_nametoindex()`, базовый цикл `recvfrom()`, обработку ошибок. Пока без
фильтрации и без записи, только получение кадров.

4. `pcap: add file writer for global and per-packet records`
Добавить запись в `pcap` без libpcap: глобальный заголовок файла, timestamp,
captured length, original length, flush/close, обработку ошибок записи.
Формат выхода должен быть стандартный `pcap`, пригодный для чтения `tcpdump`
и Wireshark.

5. `filter: add minimal packet parser for matching`
Добавить минимальный разбор Ethernet, IPv4, TCP и UDP только в объёме, нужном
для фильтрации. Это внутренний разбор пакета, без пользовательского вывода и
без задачи печатать декодирование на экран.

6. `filter: add lexer-free parser for minimal expression set`
Добавить простой ручной парсер без генераторов и без отдельного lexer:
поддержать только формы `tcp`, `udp`, `port <n>`, `ether src <mac>`,
`ether dst <mac>`, `ether host <mac>`. Разрешить последовательность терминов
через неявное `and`, без `or`, `not`, скобок и расширений.

7. `filter: evaluate l2 and l4 predicates on decoded packet`
Добавить структуру фильтра и прямую проверку пакета после разбора заголовков.
`ether *` применять по L2, `tcp`/`udp` по IPv4 protocol, `port` по TCP/UDP
src/dst port. Если пакет не содержит нужного уровня, фильтр должен давать false.

8. `udump: write matched packets to pcap and tighten errors`
Подключить фильтр в основной цикл и писать в `pcap` только совпавшие пакеты.
Добавить понятные ошибки для неверного MAC, неверного порта, неподдержанного
токена, отсутствующего интерфейса и проблем с выходным файлом. Завершение по
ошибке фильтра должно происходить до открытия сокета.

9. `test: add module tests for parser and packet matcher`
Добавить простой `tests/` с автономными C-тестами без сторонних фреймворков:
позитивные и негативные случаи для парсера фильтра, проверки совпадения
`ether src/dst/host`, `tcp`, `udp`, `port`, а также smoke-test записи `pcap`
заголовка и packet record. Подключить `make test`.

10. `docs: document build, usage, and supported filters`
Заполнить `README.md`: статическая сборка через musl, запуск от root/с нужными
capabilities, формат команды с `-i <ifname>` и `-w <output_file>`, ограничения,
примеры фильтров, формат выходного файла `pcap`, список поддерживаемого
функционала и явно неподдерживаемых возможностей, включая отсутствие печати
разбора пакетов на экран.
