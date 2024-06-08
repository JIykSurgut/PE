### PE структура
|№ |1 уровень|2 уровень             |         |
|--|---------|----------------------|---------|
|01|Загловки |DOS Header            |         |
|02|         |DOS stub              |         |
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

## 02
<details>
  <summary><b>struct _IMAGE_FILE_HEADER</b></summary>
  
  ``` C++
typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
```
</details>

| №|Смещение|Название             |Байт|Описание                                                                                        |
|--|--------|---------------------|----|------------------------------------------------------------------------------------------------|
|01|0x00    |e_magic              |2   | указывает тип машины, для которой предназначен файл, например, IMAGE_FILE_MACHINE_I386 для x86.|
|02|0x00    |NumberOfSections     |2   | количество секций в файле, каждая из которых содержит код, данные или ресурсы.                 |
|03|0x00    |TimeDateStamp        |4   | временная метка создания файла.                                                                |
|04|0x00    |PointerToSymbolTable |4   | указатель на таблицу символов для отладки; обычно не используется в исполняемых файлах Windows.|
|05|0x00    |NumberOfSymbols      |4   | количество символов в таблице символов; также обычно не используется.                          |
|06|0x00    |SizeOfOptionalHeader |2   | размер заголовка IMAGE_OPTIONAL_HEADER, следующего за IMAGE_FILE_HEADER.                       |
|07|0x00    |Characteristics      |2   | флаги, описывающие характеристики файла, например, если файл является исполняемым (exe) или библиотекой (dll), поддерживает ли он 32-битный или 64-битный режим и т.д.|

<details>
  <summary><b>struct _IMAGE_OPTIONAL_HEADER</b></summary>
  
  ``` C++
typedef struct _IMAGE_OPTIONAL_HEADER {
    WORD    Magic;
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;
    DWORD   BaseOfData;
    DWORD   ImageBase;
    DWORD   SectionAlignment;
    DWORD   FileAlignment;
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;
    WORD    Subsystem;
    WORD    DllCharacteristics;
    DWORD   SizeOfStackReserve;
    DWORD   SizeOfStackCommit;
    DWORD   SizeOfHeapReserve;
    DWORD   SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;
```
</details>

| №|Смещение|Название             |Байт|Описание                                                                |
|--|--------|---------------------|----|------------------------------------------------------------------------|
|01|0x00    |Magic                |2   | магическое число, определяющее формат файла (например, PE32 или PE32+).|
|01|0x00    |MajorLinkerVersion   |1   | версия линкера, использованного для создания файла.                    |
|01|0x00    |MinorLinkerVersion   |1   | версия линкера, использованного для создания файла.                    |
|01|0x00    |SizeOfCode           |1   | размер кода в файле.                                                   |
|01|0x00    |AddressOfEntryPoint  |1   | точка входа исполняемого кода.                                         |
|01|0x00    |ImageBase            |1   | предпочтительный адрес загрузки в памяти.                              |
|01|0x00    |SectionAlignment     |1   | выравнивание секций в памяти.                                          |
|01|0x00    |FileAlignment        |1   | выравнивание секций в файле.                                           |
|01|0x00    |Subsystem            |1   | подсистема, для которой предназначен файл (например, Windows GUI или консоль).|
|01|0x00    |DllCharacteristics   |1   | флаги, специфичные для DLL.|
|01|0x00    |SizeOfStackReserve   |1   | размер резервирования и фактического выделения стека.|
|01|0x00    |SizeOfStackCommit    |1   | размер резервирования и фактического выделения стека.|
|01|0x00    |SizeOfHeapReserve    |1   | размер резервирования и фактического выделения кучи. |
|01|0x00    |SizeOfHeapCommit     |1   | размер резервирования и фактического выделения кучи. |
|01|0x00    |NumberOfRvaAndSizes  |1   | количество каталогов данных. |
|01|0x00    |DataDirectory        |1   | массив структур IMAGE_DATA_DIRECTORY, каждая из которых описывает каталог данных, такой как таблицы импорта и экспорта. |


## Секции 
|  |       |                                                                                                                 |
|--|-------|-----------------------------------------------------------------------------------------------------------------|
|01|.text  |Содержит исполняемый код программы                                                                               |
|02|.data  |Содержит инициализированные глобальные и статические переменные                                                  |
|03|.rdata |Содержит константы и информацию для отладки                                                                      |
|04|.bss   |Содержит неинициализированные глобальные и статические переменные                                                |
|05|.idata |Содержит таблицу импорта, используемую для динамической связи с другими DLL                                      |
|06|.edata |Содержит таблицу экспорта, которая перечисляет функции и переменные, экспортируемые файлом                       |
|07|.rsrc  |Содержит ресурсы программы, такие как иконки, меню и строковые таблицы                                           |
|08|.reloc |Содержит информацию для базовой переадресации, необходимую, если файл не загружается по предпочтительному адресу |


<details>
  <summary><b>struct _IMAGE_OPTIONAL_HEADER</b></summary>
  
  ``` C++
typedef struct _IMAGE_SECTION_HEADER {
    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        DWORD   PhysicalAddress;
        DWORD   VirtualSize;
    } Misc;
    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;
    WORD    NumberOfLinenumbers;
    DWORD   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
```
</details>

| №|Смещение|Название             |Байт|Описание                                                                |
|--|--------|---------------------|----|------------------------------------------------------------------------|
|01|0x00    |Name                |2   | имя секции.|
|01|0x00    |Misc.VirtualSize    |2   | размер секции в памяти.|
|01|0x00    |VirtualAddress      |2   | виртуальный адрес секции в памяти.|
|01|0x00    |SizeOfRawData       |2   | размер секции в файле.|
|01|0x00    |PointerToRawData    |2   |  указатель на начало данных секции в файле.|
|01|0x00    |Characteristics     |2   |  флаги, определяющие атрибуты секции, такие как доступность для чтения, записи и выполнения.|





