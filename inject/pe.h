#include <cstdint>

typedef int LONG;
typedef unsigned char BYTE;
typedef uint32_t DWORD;
typedef unsigned short WORD;
typedef unsigned short USHORT;


#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

#define IMAGE_DIRECTORY_ENTRY_EXPORT              0
#define IMAGE_DIRECTORY_ENTRY_IMPORT              1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE            2
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION           3
#define IMAGE_DIRECTORY_ENTRY_SECURITY            4
#define IMAGE_DIRECTORY_ENTRY_BASERELOC           5
#define IMAGE_DIRECTORY_ENTRY_DEBUG               6
//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT               7
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE        7
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR           8
#define IMAGE_DIRECTORY_ENTRY_TLS                 9
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG         10
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT        11
#define IMAGE_DIRECTORY_ENTRY_IAT                 12
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT        13
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR      14




typedef struct _IMAGE_DOS_HEADER {
    USHORT e_magic;
    USHORT e_cblp;
    USHORT e_cp;
    USHORT e_crlc;
    USHORT e_cparhdr;
    USHORT e_minalloc;
    USHORT e_maxalloc;
    USHORT e_ss;
    USHORT e_sp;
    USHORT e_csum;
    USHORT e_ip;
    USHORT e_cs;
    USHORT e_lfarlc;
    USHORT e_ovno;
    USHORT e_res[4];
    USHORT e_oemid;
    USHORT e_oeminfo;
    USHORT e_res2[10];
    LONG   e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;




typedef struct _IMAGE_FILE_HEADER {
    WORD  Machine; // Архитектура процессора
    WORD  NumberOfSections; // Кол-во секций
    DWORD TimeDateStamp; // Дата и время создания программы
    DWORD PointerToSymbolTable; // Указатель на таблицу символов
    DWORD NumberOfSymbols; // Число символов в таблицу
    WORD  SizeOfOptionalHeader; // Размер дополнительного заголовка
    WORD  Characteristics; // Характеристика
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;



typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress;
    DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;



typedef struct _IMAGE_OPTIONAL_HEADER {
    WORD        Magic;
    BYTE        MajorLinkerVersion;
    BYTE        MinorLinkerVersion;
    DWORD       SizeOfCode;
    DWORD       SizeOfInitializedData;
    DWORD       SizeOfUninitializedData;
    DWORD       AddressOfEntryPoint;
    DWORD       BaseOfCode;
    DWORD       BaseOfData;
    DWORD       ImageBase;
    DWORD       SectionAlignment;
    DWORD       FileAlignment;
    WORD        MajorOperatingSystemVersion;
    WORD        MinorOperatingSystemVersion;
    WORD        MajorImageVersion;
    WORD        MinorImageVersion;
    WORD        MajorSubsystemVersion;
    WORD        MinorSubsystemVersion;
    DWORD       Win32VersionValue;
    DWORD       SizeOfImage;
    DWORD       SizeOfHeaders;
    DWORD       CheckSum;
    WORD        Subsystem;
    WORD        DllCharacteristics;
    DWORD       SizeOfStackReserve;
    DWORD       SizeOfStackCommit;
    DWORD       SizeOfHeapReserve;
    DWORD       SizeOfHeapCommit;
    DWORD       LoaderFlags;
    DWORD       NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;



typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature; // Сигнатура
    IMAGE_FILE_HEADER FileHeader; // Файловый заголовка
    IMAGE_OPTIONAL_HEADER32 OptionalHeader; // Дополнительный
          
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

