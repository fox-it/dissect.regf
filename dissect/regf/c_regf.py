from __future__ import annotations

from dissect.cstruct import cstruct

regf_def = """
typedef ULONG       HCELL_INDEX;
typedef ULONGLONG   LARGE_INTEGER;

#define HTYPE_COUNT 2

flag KEY : USHORT {
    IS_VOLATILE     = 0x0001,
    HIVE_EXIT       = 0x0002,
    HIVE_ENTRY      = 0x0004,
    NO_DELETE       = 0x0008,
    SYM_LINK        = 0x0010,
    COMP_NAME       = 0x0020,
    PREDEF_HANDLE   = 0x0040,
    VIRT_MIRRORED   = 0x0080,
    VIRT_TARGET     = 0x0100,
    VIRTUAL_STORE   = 0x0200,
};

flag VALUE : USHORT {
    COMP_NAME       = 0x0001,
    TOMBSTONE       = 0x0002,
};

typedef struct _HBASE_BLOCK {
    ULONG           Signature;
    ULONG           Sequence1;
    ULONG           Sequence2;
    LARGE_INTEGER   TimeStamp;
    ULONG           Major;
    ULONG           Minor;
    ULONG           Type;
    ULONG           Format;
    HCELL_INDEX     RootCell;
    ULONG           Length;
    ULONG           Cluster;
    WCHAR           FileName[32];
    ULONG           Reserved1[99];
    ULONG           CheckSum;
    ULONG           Reserved2[0x37e];
    ULONG           BootType;
    ULONG           BootRecover;
} HBASE_BLOCK;

typedef struct _HBIN {
    ULONG           Signature;
    HCELL_INDEX     FileOffset;
    ULONG           Size;
    ULONG           Reserved[2];
    LARGE_INTEGER   TimeStamp;
    ULONG           Spare;
} HBIN;

typedef struct _CHILD_LIST {
    ULONG           Count;
    HCELL_INDEX     List;
} CHILD_LIST;

typedef struct _CM_KEY_NODE {
    CHAR            Signature[2];
    KEY             Flags;
    LARGE_INTEGER   LastWriteTime;
    ULONG           Spare;
    HCELL_INDEX     Parent;
    ULONG           SubKeyCounts[HTYPE_COUNT];

    /* Union with CM_KEY_REFERENCE ChildHiveReference; */
    ULONG           SubKeyLists[HTYPE_COUNT];
    CHILD_LIST      ValueList;

    HCELL_INDEX     Security;
    HCELL_INDEX     Class;
    ULONG           MaxNameLen;
    ULONG           MaxClassLen;
    ULONG           MaxValueNameLen;
    ULONG           MaxValueDataLen;
    ULONG           WorkVar;
    USHORT          NameLength;
    USHORT          ClassLength;
    // WCHAR           Name[1];
} CM_KEY_NODE;

typedef struct _CM_INDEX {
    HCELL_INDEX     Cell;
    CHAR            NameHint[4];
} CM_INDEX;

typedef struct _CM_HASH_INDEX {
    HCELL_INDEX     Cell;
    ULONG           HashKey;
} CM_HASH_INDEX;

typedef struct _CM_KEY_INDEX {
    CHAR            Signature[2];
    USHORT          Count;
    HCELL_INDEX     List[Count];
} CM_KEY_INDEX;

typedef struct _CM_KEY_FAST_INDEX {
    CHAR            Signature[2];
    USHORT          Count;
    CM_INDEX        List[Count];
} CM_KEY_FAST_INDEX;

typedef struct _CM_KEY_HASH_INDEX {
    CHAR            Signature[2];
    USHORT          Count;
    CM_HASH_INDEX   List[Count];
} CM_KEY_HASH_INDEX;

typedef struct _CM_KEY_VALUE {
    CHAR            Signature[2];
    USHORT          NameLength;
    ULONG           DataLength;
    HCELL_INDEX     Data;
    ULONG           Type;
    VALUE           Flags;
    USHORT          Spare;
    // WCHAR           Name[1];
} CM_KEY_VALUE;

typedef struct _CM_KEY_SECURITY {
    CHAR            Signature[2];
    USHORT          Reserved;
    HCELL_INDEX     Flink;
    HCELL_INDEX     Blink;
    ULONG           ReferenceCount;
    ULONG           DescriptorLength;
    CHAR            Descriptor[DescriptorLength];
} CM_KEY_SECURITY;

typedef struct _CM_BIG_DATA {
    CHAR            Signature[2];
    USHORT          Count;
    HCELL_INDEX     List;
} CM_BIG_DATA;
"""

c_regf = cstruct().load(regf_def)

KEY = c_regf.KEY
VALUE = c_regf.VALUE

REG_NONE = 0x0
REG_SZ = 0x1
REG_EXPAND_SZ = 0x2
REG_BINARY = 0x3
REG_DWORD = 0x4
REG_DWORD_BIG_ENDIAN = 0x5
REG_LINK = 0x6
REG_MULTI_SZ = 0x7
REG_RESOURCE_LIST = 0x8
REG_FULL_RESOURCE_DESCRIPTOR = 0x9
REG_RESOURCE_REQUIREMENTS_LIST = 0xA
REG_QWORD = 0xB
