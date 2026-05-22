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

3. `udump: add capture limit options`
Добавить поддержку `-c <count>` для остановки после заданного числа пакетов и
`-G <seconds>` для остановки после заданного времени работы. На этом шаге
только разбор и валидация аргументов, без привязки к циклу захвата.

4. `udump: add raw packet capture on linux`
Добавить открытие `AF_PACKET`/`SOCK_RAW`, bind к интерфейсу через
`if_nametoindex()`, базовый цикл `recvfrom()`, обработку ошибок, остановку по
`-c` и `-G`. Пока без фильтрации и без записи, только получение кадров.

5. `pcap: add file writer for global and per-packet records`
Добавить запись в `pcap` без libpcap: глобальный заголовок файла, timestamp,
captured length, original length, flush/close, обработку ошибок записи.
Формат выхода должен быть стандартный `pcap`, пригодный для чтения `tcpdump`
и Wireshark.

6. `filter: add minimal packet parser for matching`
Добавить минимальный разбор Ethernet, IPv4, TCP и UDP только в объёме, нужном
для фильтрации. Это внутренний разбор пакета, без пользовательского вывода и
без задачи печатать декодирование на экран.

7. `filter: add lexer-free parser for minimal expression set`
Добавить простой ручной парсер без генераторов и без отдельного lexer:
поддержать только формы `tcp`, `udp`, `port <n>`, `ether src <mac>`,
`ether dst <mac>`, `ether host <mac>`. Разрешить последовательность терминов
через неявное `and`, без `or`, `not`, скобок и расширений.

8. `filter: evaluate l2 and l4 predicates on decoded packet`
Добавить структуру фильтра и прямую проверку пакета после разбора заголовков.
`ether *` применять по L2, `tcp`/`udp` по IPv4 protocol, `port` по TCP/UDP
src/dst port. Если пакет не содержит нужного уровня, фильтр должен давать false.

9. `udump: write matched packets to pcap and tighten errors`
Подключить фильтр в основной цикл и писать в `pcap` только совпавшие пакеты.
Добавить понятные ошибки для неверного MAC, неверного порта, неподдержанного
токена, отсутствующего интерфейса и проблем с выходным файлом. Завершение по
ошибке фильтра должно происходить до открытия сокета.

10. `test: add module tests for parser and packet matcher`
Добавить простой `tests/` с автономными C-тестами без сторонних фреймворков:
позитивные и негативные случаи для парсера фильтра, проверки совпадения
`ether src/dst/host`, `tcp`, `udp`, `port`, а также smoke-test записи `pcap`
заголовка и packet record. Подключить `make test`.

11. `docs: document build, usage, and supported filters`
Заполнить `README.md`: статическая сборка через musl, запуск от root/с нужными
capabilities, формат команды с `-i <ifname>`, `-w <output_file>`,
`-c <count>` и `-G <seconds>`, ограничения, примеры фильтров, формат выходного
файла `pcap`, список поддерживаемого функционала и явно неподдерживаемых
возможностей, включая отсутствие печати разбора пакетов на экран.

12. `bpf: add classic bpf program builder for supported filter subset`
Добавить внутренний генератор classic BPF без libpcap и без JIT-зависимостей:
по уже разобранному минимальному AST собирать `struct sock_filter[]` и
`struct sock_fprog` для текущего подмножества выражений `tcp`, `udp`,
`port <n>`, `ether src <mac>`, `ether dst <mac>`, `ether host <mac>`, с тем же
неявным `and`, что и в userspace-фильтре.

13. `bpf: compile l2 and ipv4 port predicates to socket filter bytecode`
Реализовать генерацию инструкций для проверок Ethernet source/destination MAC,
EtherType IPv4, IPv4 protocol и TCP/UDP source/destination port. Для `port`
сразу закладывать безопасные проверки длины, IPv4 IHL и нужного смещения, чтобы
ядро отбрасывало неподходящие кадры до передачи в userspace.

14. `udump: attach compiled bpf to packet socket by default`
Подключить генерацию и `setsockopt(..., SO_ATTACH_FILTER, ...)` в основном пути
запуска. Если фильтр задан и он поддерживается компилятором, по умолчанию
вешать BPF на сокет и принимать в userspace только уже отфильтрованные пакеты.
При отсутствии фильтра сокет оставлять без BPF.

15. `udump: keep userspace filtering as explicit fallback mode`
Оставить текущую userspace-фильтрацию как опциональный режим. Добавить явный
ключ выбора, например `--filter-mode=user`, чтобы можно было принудительно
обойти kernel BPF для отладки и сравнения поведения. Дефолтным режимом должен
быть `bpf`, а при ошибке компиляции поддерживаемого фильтра программа должна
завершаться с понятной ошибкой, а не молча переключаться на userspace.

16. `test: compare classic bpf path with userspace matcher`
Добавить тесты, которые проверяют генерацию `sock_fprog` для каждого
поддержанного примитива и сверяют поведение kernel BPF пути с текущим
userspace matcher на одинаковых фикстурах. Отдельно проверить, что `tcpdump`
нормально читает `pcap`, записанный при захвате с включённым BPF на сокете.

17. `docs: document default kernel filtering and fallback mode`
Обновить `README.md` и описание ограничений: фильтр по умолчанию компилируется
в classic BPF и крепится к сокету, userspace-фильтрация остаётся только как
явный fallback-режим, перечислить поддерживаемое подмножество выражений и
зафиксировать, что это минимальный аналог `pcap_compile`, а не совместимость
со всем синтаксисом libpcap.
