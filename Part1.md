## DOS Header
|offset|          |     |       |                                                                     |
|------|----------|-----|-------|---------------------------------------------------------------------|
|0x00  |e_magic   |4d 5a|MZ     |Магическое число                                                     |
|0x02  |e_cblp    |90 00|144    |Количество байт на последней странице файла                          |
|0x04  |e_cp      |03 00|3      |Общее количество страниц в файле                                     |
|0x06  |e_crlc    |00 00|0      |Количество релокаций                                                 |
|0x08  |e_cparhdr |04 00|4      |Размер заголовка в абзацах                                           |
|0x0a  |e_minalloc|00 00|0      |Минимальное количество абзацев, которые нужны сверх размера заголовка|
|0x0c  |e_maxalloc|ff ff|65535  |Максимальное количество абзацев, которые можно выделить              |
|0x0e  |e_ss      |00 00|0000   |Начальное значение регистра SS                                       |
|0x10  |e_sp      |b8 00|00b8   |Начальное значение регистра SP                                       |
|0x12  |e_csum    |00 00|0000   |Контрольная сумма файла                                              |
|0x14  |e_ip      |00 00|0000   |Начальное значение регистра IP                                       |
|0x16  |e_cs      |00 00|0000   |Начальное значение регистра CS                                       |
|0x18  |e_lfarlc  |40 00|0040   |Адрес таблицы релокаций в файле                                      |
|0x1a  |e_ovno    |00 00|0      |Номер оверлея                                                        |
|0x1c  |e_res[4]  |00 00 00 00| |Зарезервированные слова                                              |
|0x24  |e_oemid   |00 00|00 00  |Идентификатор OEM                                                    |
|0x26  |e_oeminfo |00 00|00 00  |Информация OEM, специфичная для e_oemid                              |
|0x28  |e_res2[10]|00 00 ..|00 00 ..  |Зарезервированные слова                                        |
|0x3c  |e_lfanew  |48 01 |01 48 |Адрес нового заголовка исполняемого файла в файле                    |

## DOS stub
|offset  |
|--------|
|0x00 3e |
|...     |
|0x01 47 |

## PE заголовок
|offset|                            |                 |                                                                       |
|------|----------------------------|-----------------|-----------------------------------------------------------------------|
|      |<b>IMAGE_NT_HEADERS64</b>   |                 |                                                                       | 
|0x0148|Signature                   |00004550         |Сигнатура                                                              |
|      |<b>IMAGE_FILE_HEADER</b>    |                 |                                                                       |
|0x014c|Machine                     |8668             |указывает тип машины                                                   |
|0x014e|NumberOfSections            |0007             |количество секций в файле                                              |
|0x0150|TimeDateStamp               |65bce66a         |временная метка создания файла                                         |
|0x0154|PointerToSymbolTable        |00000000         |указатель на таблицу символов для отладки                              |
|0x0158|NumberOfSymbols             |00000000         |количество символов в таблице символов                                 |
|0x015c|SizeOfOptionalHeader        |00f0             |размер заголовка IMAGE_OPTIONAL_HEADER, следующего за IMAGE_FILE_HEADER (240 байт)|
|0x015e|Characteristics             |0022             |флаги, описывающие характеристики файла (34)                           |
|      |<b>IMAGE_OPTIONAL_HEADER64</b>|                 |                                                                       |
|0x0160|Magic                       |020b             |магическое число, определяющее формат файла (например, PE32 или PE32+) |
|0x0162|MajorLinkerVersion          |0e               |версия линкера, использованного для создания файла                     |
|0x0163|MinorLinkerVersion          |00               |версия линкера, использованного для создания файла                     |
|0x0164|SizeOfCode                  |00c6b400         |размер кода в файле 13 022 208 байт                                    |
|0x0168|SizeOfInitializedData       |01725e00         | 24 272 384 байт                                                       |
|0x016с|SizeOfUninitializedData     |00000000         | 0 байт                                                                |
|0x0170|AddressOfEntryPoint         |00483de0         | точка входа исполняемого кода                                         |
|0x0174|BaseOfCode                  |00001000         |                                                                       |
|0x0178|ImageBase                   |00000001 40000000|предпочтительный адрес загрузки в памяти                               |
|0x0180|SectionAlignment            |00001000         |выравнивание секций в памяти                                           |
|0x0184|FileAlignment               |00000200         |выравнивание секций в файле                                            |
|0x0188|MajorOperatingSystemVersion |0006             |                                                                       |
|0x018a|MinorOperatingSystemVersion |0000             |                                                                       |
|0x018c|MajorImageVersion           |0000             |                                                                       |
|0x018e|MinorImageVersion           |0000             |                                                                       |
|0x0190|MajorSubsystemVersion       |0006             |                                                                       |
|0x0192|MinorSubsystemVersion       |0000             |                                                                       |
|0x0194|Win32VersionValue           |00000000         |                                                                       |
|0x0198|SizeOfImage                 |02396000         |                                                                       |
|0x019c|SizeOfHeaders               |00000400         |                                                                       |
|0x01a0|CheckSum                    |0109af11         |                                                                       |
|0x01a4|Subsystem                   |0002             | подсистема, для которой предназначен файл                             |
|0x01a6|DllCharacteristics          |c160             | флаги, специфичные для DLL.                                           |
|0x01a8|SizeOfStackReserve          |00000000 00200000|                                                                       |
|0x01b0|SizeOfStackCommit           |00000000 00001000|                                                                       |
|0x01b8|SizeOfHeapReserve           |00000000 00100000|                                                                       |
|0x01c0|SizeOfHeapCommit            |00000000 00001000|                                                                       |
|0x01c8|LoaderFlags                 |00000000         |                                                                       |
|0x01cc|NumberOfRvaAndSizes         |00000010         |                                                                       |
|      |<b>IMAGE_DATA_DIRECTORY</b> |                 |                                                                       |
|0x01d0|IMAGE_DIRECTORY_ENTRY_EXPORT        |00ebd520 000006dc|VirtualAddress=00ebd520 Size=000006dc                          |
|0x01d8|IMAGE_DIRECTORY_ENTRY_IMPORT        |00ebdbfc 0000021c|VirtualAddress=00ebdbfc Size=0000021c                          |
|0x01e0|IMAGE_DIRECTORY_ENTRY_RESOURCE      |0237a000 0000a780|VirtualAddress=0237a000 Size=0000a780                          |
|0x01e8|IMAGE_DIRECTORY_ENTRY_EXCEPTION     |022aa000 000ce52c|VirtualAddress=022aa000 Size=000ce52c                          |
|0x01f0|IMAGE_DIRECTORY_ENTRY_SECURITY      |01089600 00002aa8|VirtualAddress=01089600 Size=00002aa8                          |
|0x01f8|IMAGE_DIRECTORY_ENTRY_BASERELOC     |02385000 00010cf0|VirtualAddress=02385000 Size=00010cf0                          |
|0x0200|IMAGE_DIRECTORY_ENTRY_DEBUG         |00d689e0 00000054|VirtualAddress=00d689e0 Size=00000054                          |
|0x0208|IMAGE_DIRECTORY_ENTRY_ARCHITECTURE  |00000000 00000000|VirtualAddress=00000000 Size=00000000                          |
|0x0210|IMAGE_DIRECTORY_ENTRY_GLOBALPTR     |00000000 00000000|VirtualAddress=00000000 Size=00000000                          |
|0x0218|IMAGE_DIRECTORY_ENTRY_TLS           |00d68ad8 00000028|VirtualAddress=00d68ad8 Size=00000028                          |
|0x0220|IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG   |00d68a40 00000094|VirtualAddress=00d68a40 Size=00000094                          |
|0x0228|IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT  |00000000 00000000|VirtualAddress=00000000 Size=00000000                          |
|0x0230|IMAGE_DIRECTORY_ENTRY_IAT           |00c6d000 000022f0|VirtualAddress=00c6d000 Size=000022f0                          |
|0x0238|IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT  |00000000 00000000|VirtualAddress=00000000 Size=00000000                          |
|0x0240|IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR|00000000 00000000|VirtualAddress=00000000 Size=00000000                          |
|0x0248|                                    |00000000 00000000|VirtualAddress=00000000 Size=00000000                          |

## Секции
|offset|                            |                |                                                                       |
|------|----------------------------|----------------|-----------------------------------------------------------------------|
|0x0250|Name                        |2e74657874000000| .text                                                                 |
|0x0258|VirtualSize                 |00c6b35c        | 00c6b35c = 13 022 044 байт                                            |
|0x025с|VirtualAddress              |00001000        | 00001000                                                              |
|0x0260|SizeOfRawData               |00b4c600        | 00c6b400                                                              |
|0x0264|PointerToRawData            |00040000        | 00000400                                                              |
|0x0268|PointerToRelocations        |00000000        |                                                                       |
|0x026c|PointerToLinenumbers        |00000000        |                                                                       |
|0x0270|NumberOfRelocations         |0000            |                                                                       |
|0x0272|NumberOfLinenumbers         |0000            |                                                                       |
|0x0274|Characteristics             |60000020        |                                                                       |

|offset|                            |                |                                                                       |
|------|----------------------------|----------------|-----------------------------------------------------------------------|
|0x0250|Name                        |2e74657874000000| .rdata                                                                 |
|0x0258|VirtualSize                 |5cb3c600        | 00c6b35c = 13 022 044 байт                                            |
|0x025с|VirtualAddress              |00001000        | 00001000                                                              |
|0x0260|SizeOfRawData               |00b4c600        | 00c6b400                                                              |
|0x0264|PointerToRawData            |00040000        | 00000400                                                              |
|0x0268|PointerToRelocations        |00000000        |                                                                       |
|0x026c|PointerToLinenumbers        |00000000        |                                                                       |
|0x0270|NumberOfRelocations         |0000            |                                                                       |
|0x0272|NumberOfLinenumbers         |0000            |                                                                       |
|0x0274|Characteristics             |60000020        |                                                                       |

|offset|                            |                |                                                                       |
|------|----------------------------|----------------|-----------------------------------------------------------------------|
|0x0250|Name                        |2e74657874000000| .data                                                                 |
|0x0258|VirtualSize                 |5cb3c600        | 00c6b35c = 13 022 044 байт                                            |
|0x025с|VirtualAddress              |00001000        | 00001000                                                              |
|0x0260|SizeOfRawData               |00b4c600        | 00c6b400                                                              |
|0x0264|PointerToRawData            |00040000        | 00000400                                                              |
|0x0268|PointerToRelocations        |00000000        |                                                                       |
|0x026c|PointerToLinenumbers        |00000000        |                                                                       |
|0x0270|NumberOfRelocations         |0000            |                                                                       |
|0x0272|NumberOfLinenumbers         |0000            |                                                                       |
|0x0274|Characteristics             |60000020        |                                                                       |

|offset|                            |                |                                                                       |
|------|----------------------------|----------------|-----------------------------------------------------------------------|
|0x0250|Name                        |2e74657874000000| .data                                                                 |
|0x0258|VirtualSize                 |5cb3c600        | 00c6b35c = 13 022 044 байт                                            |
|0x025с|VirtualAddress              |00001000        | 00001000                                                              |
|0x0260|SizeOfRawData               |00b4c600        | 00c6b400                                                              |
|0x0264|PointerToRawData            |00040000        | 00000400                                                              |
|0x0268|PointerToRelocations        |00000000        |                                                                       |
|0x026c|PointerToLinenumbers        |00000000        |                                                                       |
|0x0270|NumberOfRelocations         |0000            |                                                                       |
|0x0272|NumberOfLinenumbers         |0000            |                                                                       |
|0x0274|Characteristics             |60000020        |                                                                       |

|offset|                            |                |                                                                       |
|------|----------------------------|----------------|-----------------------------------------------------------------------|
|0x0250|Name                        |2e74657874000000| .pdata                                                                |
|0x0258|VirtualSize                 |5cb3c600        | 00c6b35c = 13 022 044 байт                                            |
|0x025с|VirtualAddress              |00001000        | 00001000                                                              |
|0x0260|SizeOfRawData               |00b4c600        | 00c6b400                                                              |
|0x0264|PointerToRawData            |00040000        | 00000400                                                              |
|0x0268|PointerToRelocations        |00000000        |                                                                       |
|0x026c|PointerToLinenumbers        |00000000        |                                                                       |
|0x0270|NumberOfRelocations         |0000            |                                                                       |
|0x0272|NumberOfLinenumbers         |0000            |                                                                       |
|0x0274|Characteristics             |60000020        |                                                                       |

|offset|                            |                |                                                                       |
|------|----------------------------|----------------|-----------------------------------------------------------------------|
|0x0250|Name                        |2e74657874000000| .tls                                                                  |
|0x0258|VirtualSize                 |5cb3c600        | 00c6b35c = 13 022 044 байт                                            |
|0x025с|VirtualAddress              |00001000        | 00001000                                                              |
|0x0260|SizeOfRawData               |00b4c600        | 00c6b400                                                              |
|0x0264|PointerToRawData            |00040000        | 00000400                                                              |
|0x0268|PointerToRelocations        |00000000        |                                                                       |
|0x026c|PointerToLinenumbers        |00000000        |                                                                       |
|0x0270|NumberOfRelocations         |0000            |                                                                       |
|0x0272|NumberOfLinenumbers         |0000            |                                                                       |
|0x0274|Characteristics             |60000020        |                                                                       |

|offset|                            |                |                                                                       |
|------|----------------------------|----------------|-----------------------------------------------------------------------|
|0x0250|Name                        |2e74657874000000| .rsrc                                                                  |
|0x0258|VirtualSize                 |5cb3c600        | 00c6b35c = 13 022 044 байт                                            |
|0x025с|VirtualAddress              |00001000        | 00001000                                                              |
|0x0260|SizeOfRawData               |00b4c600        | 00c6b400                                                              |
|0x0264|PointerToRawData            |00040000        | 00000400                                                              |
|0x0268|PointerToRelocations        |00000000        |                                                                       |
|0x026c|PointerToLinenumbers        |00000000        |                                                                       |
|0x0270|NumberOfRelocations         |0000            |                                                                       |
|0x0272|NumberOfLinenumbers         |0000            |                                                                       |
|0x0274|Characteristics             |60000020        |                                                                       |
