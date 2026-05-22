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

18. `filter: replace flat term list with boolean expression tree`
Заменить текущий плоский список терминов на простой AST для булевых выражений.
Поддержать узлы `TERM`, `AND`, `OR` и группировку через скобки, без `not` и без
других расширений. Хранение сделать прямым и простым, без лишних уровней и
универсальных visitor-абстракций.

19. `filter: parse explicit and/or with libpcap precedence and parenthesis groups`
Переделать ручной парсер на разбор выражений с семантикой libpcap: скобки выше
всего, а `and`, `or` и неявная конъюнкция имеют одинаковый приоритет и
ассоциируются слева направо. То есть выражение `tcp or udp and port 53`
должно разбираться как `(tcp or udp) and port 53`, а не как
`tcp or (udp and port 53)`. Добавить понятные ошибки для незакрытой скобки,
пустой группы, двух операторов подряд и других битых выражений.

20. `filter: evaluate boolean expression tree in userspace matcher`
Переделать userspace matcher с прохода по плоскому массиву на рекурсивную или
явно стековую проверку AST. Сохранить короткое замыкание для `and` и `or`,
чтобы не делать лишний разбор и лишние проверки по пакету.

21. `bpf: compile boolean expression tree to classic bpf with short-circuit`
Расширить текущий генератор classic BPF так, чтобы он умел собирать `AND` и
`OR` над уже поддержанными примитивами и группами в скобках. Генерацию делать
с коротким замыканием по веткам и с сохранением лево-ассоциативной семантики
libpcap, чтобы выражения вроде
`ether host aa:bb:cc:dd:ee:ff and (tcp port 22 or udp port 53)` не
разворачивались в избыточный линейный мусор без нужды.

22. `bpf: add expression normalization for shared checks`
Добавить простой этап нормализации перед codegen: схлопывать дубли,
поднимать общие префиксы там, где это тривиально и безопасно, и переиспользовать
общие проверки IPv4/proto внутри булевых веток. Нормализация не должна менять
AST и наблюдаемую семантику libpcap-разбора; любые преобразования допустимы
только если они строго эквивалентны исходному дереву. Цель не в общем
оптимизаторе libpcap-уровня, а в предсказуемом уменьшении размера и числа
инструкций для нашего ограниченного grammar.

23. `test: add parser, matcher, and bpf parity coverage for and/or groups`
Добавить тесты на libpcap-семантику, приоритеты и группировку:
`tcp or udp and port 53`, `(tcp or udp) and port 53`,
`tcp or (udp and port 53)`, `ether src ... and (tcp port 22 or udp port 53)`,
вложенные скобки, ошибки разбора и сверку kernel BPF пути с userspace matcher
на одинаковых пакетах и фикстурах.

24. `docs: document boolean filter grammar and remaining limits`
Обновить `README.md`: описать поддержку `and`, `or` и скобок, указать
точную семантику libpcap, где `and`, `or` и неявная конъюнкция имеют одинаковый
приоритет и ассоциируются слева направо, привести короткие примеры
группировки и отдельно зафиксировать, что `not` и полный синтаксис `tcpdump`
всё ещё не поддерживаются.

25. `debug: add -d filter compilation trace output`
Добавить отдельный диагностический ключ `-d`, который не меняет семантику
фильтрации, а подробно печатает этапы компиляции фильтра: токены/разобранные
примитивы, исходный AST после парсинга, AST или эквивалентный внутренний план
после нормализации/оптимизации, а затем итоговую classic BPF программу.
Финальный disassembly BPF должен печататься не в произвольном внутреннем
формате, а максимально близко к `tcpdump -d`: те же номера инструкций в виде
`(000)`, те же мнемоники `ldh`, `ldb`, `ldxb`, `jeq`, `jset`, `ret`, тот же
показ `jt`/`jf`/`#0x...` и те же адресные формы вроде `[12]` или `[x + 14]`.
Если для текущего datalink поведение эквивалентно `tcpdump` с
`Warning: assuming Ethernet`, это тоже должно печататься в совместимом виде.
Вывод должен быть пригоден для прямого сравнения с `tcpdump -d` при отладке
расхождений между userspace matcher, оптимизатором и kernel BPF path.
