### PE структура
|№ |1 уровень|2 уровень             |         |
|--|---------|----------------------|---------|
|01|Загловки |DOS заголовок         |         |
|02|         |PE заголовок          |         |
|03|         |Опциональный заголовок|         |
|04|         |Диретории данных      |         |
|05|         |Таблицы секций        |         |
|06|Секции   |Код                   |         |
|07|         |Импорт                |         |
|08|         |Данные                |         |

## 01 DOS Заголовок
Эта структура предшествует основному заголовку PE и используется для поддержки совместимости с DOS (64 байта).

<details>
  <summary><b>struct _IMAGE_DOS_HEADER</b></summary>
  
  ``` C++
typedef struct _IMAGE_DOS_HEADER {
    WORD e_magic;         // Магическое число
    WORD e_cblp;          // Bytes on last page of file
    WORD e_cp;            // Pages in file
    WORD e_crlc;          // Relocations
    WORD e_cparhdr;       // Size of header in paragraphs
    WORD e_minalloc;      // Minimum extra paragraphs needed
    WORD e_maxalloc;      // Maximum extra paragraphs needed
    WORD e_ss;            // Initial (relative) SS value
    WORD e_sp;            // Initial SP value
    WORD e_csum;          // Checksum
    WORD e_ip;            // Initial IP value
    WORD e_cs;            // Initial (relative) CS value
    WORD e_lfarlc;        // File address of relocation table
    WORD e_ovno;          // Overlay number
    WORD e_res[4];        // Reserved words
    WORD e_oemid;         // OEM identifier (for e_oeminfo)
    WORD e_oeminfo;       // OEM information; e_oemid specific
    WORD e_res2[10];      // Reserved words
    LONG e_lfanew;        // File address of new exe header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
```
</details>

| №|Смещение|Название  |Байт|Описание                                                                              |
|--|--------|----------|----|--------------------------------------------------------------------------------------|
|01|0x00    |e_magic   |2   |Магическое число, используемое для идентификации PE-файла. Обычно имеет значение "MZ".|
|02|0x02    |e_cblp    |2   |Количество байт на последней странице файла.                                          |
|03|0x04    |e_cp      |2   |Общее количество страниц в файле.                                                     |
|04|0x06    |e_crlc    |2   |Количество релокаций.                                                                 |
|05|0x08    |e_cparhdr |2   |Размер заголовка в абзацах.                                                           |
|06|0x0a    |e_minalloc|2   |Минимальное количество абзацев, которые нужны сверх размера заголовка.                |
|07|0x0c    |e_maxalloc|2   |Максимальное количество абзацев, которые можно выделить.                              |
|08|0x0e    |e_ss      |2   |Начальное значение регистра SS.                                                       |
|09|0x10    |e_sp      |2   |Начальное значение регистра SP.                                                       |
|10|0x12    |e_csum    |2   |Контрольная сумма файла.                                                              |
|11|0x14    |e_ip      |2   |Начальное значение регистра IP.                                                       |
|12|0x16    |e_cs      |2   |Начальное значение регистра CS.                                                       |
|13|0x18    |e_lfarlc  |2   |Адрес таблицы релокаций в файле.                                                      |
|14|0x1a    |e_ovno    |2   |Номер оверлея.                                                                        |
|15|0x1c    |e_res[4]  |2   |Зарезервированные слова.                                                              |
|16|0x24    |e_oemid   |2   |Идентификатор OEM.                                                                    |
|17|0x26    |e_oeminfo |2   |Информация OEM, специфичная для e_oemid.                                              |
|18|0x28    |e_res2[10]|2   |Зарезервированные слова.                                                              |
|19|0x3c    |e_lfanew  |2   |Адрес нового заголовка исполняемого файла в файле.                                    |


