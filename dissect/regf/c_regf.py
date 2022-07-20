from dissect import cstruct


c_regf_def = """
struct REGF_HEADER {
    uint32 signature;
    uint32 primary_sequence;
    uint32 secondary_sequence;
    uint64 last_modification_time;
    uint32 major_version;
    uint32 minor_version;
    uint32 file_type;
    uint32 file_format;
    uint32 root_key_offset;
    uint32 hive_bin_size;
    uint32 clustering_factor;
    char filename[64];
    char reserved[396];
    uint32 checksum;
};

struct HBIN_HEADER {
    uint32 signature;
    uint32 offset;
    uint32 size;
    uint64 reserved;
    uint64 last_modification_time;
    uint32 spare;
};

struct NK_FLAGS {
    uint16 Volatile:1;
    uint16 HiveExit:1;
    uint16 HiveEntry:1;
    uint16 NoDelete:1;
    uint16 SymLink:1;
    uint16 CompName:1;
    uint16 PredefinedHandle:1;
    uint16 VirtualSource:1;

    uint16 VirtualTarget:1;
    uint16 VirtualStore:1;
    uint16 a:1;
    uint16 b:1;
    uint16 c:1;
    uint16 d:1;
    uint16 e:1;
    uint16 f:1;
};

struct NAMED_KEY {
    char signature[2];
    NK_FLAGS flags;
    uint64 last_written;
    uint32 access_bits;
    uint32 parent_key_offset;
    uint32 num_subkeys;
    uint32 num_volatile_subkeys;
    uint32 subkey_list_offset;
    uint32 volatile_subkey_list_offset;
    uint32 num_values;
    uint32 value_list_offset;
    uint32 security_key_offset;
    uint32 class_name_offset;
    uint32 largest_subkey_name_size;
    uint32 largest_subkey_classname_size;
    uint32 largest_value_name_size;
    uint32 largest_value_data_size;
    uint32 workvar;
    uint16 key_name_size;
    uint16 class_name_size;
};

struct HASH_LEAF_ENTRY {
    uint32 key_node_offset;
    uint32 name_hash;
};

struct HASH_LEAF {
    uint16 signature;
    uint16 num_elements;
    HASH_LEAF_ENTRY entries[num_elements];
};

struct FAST_LEAF_ENTRY {
    uint32 key_node_offset;
    char name_hint[4];
};

struct FAST_LEAF {
    uint16 signature;
    uint16 num_elements;
    FAST_LEAF_ENTRY entries[num_elements];
};

struct INDEX_ROOT {
    uint16 signature;
    uint16 num_elements;
    uint32 entries[num_elements];
};

struct INDEX_LEAF {
    uint16 signature;
    uint16 num_elements;
    uint32 entries[num_elements];
};

struct KEY_VALUE_FLAGS {
    uint16 CompName:1;
    uint16 Tombstone:1;
};

struct KEY_VALUE {
    uint16 signature;
    uint16 name_length;
    uint32 data_size;
    uint32 data_offset;
    uint32 data_type;
    KEY_VALUE_FLAGS flags;
    uint16 spare;
};

struct KEY_SECURITY {
    uint16  signature;
    uint16  reserved;
    uint32  flink;
    uint32  blink;
    uint32  reference_count;
    uint32  security_descriptor_size;
    char    security_descriptor[security_descriptor_size];
};

struct BIG_DATA {
    uint16 signature;
    uint16 num_segments;
    uint32 segment_list_offset;
    uint32 a;
};
"""

c_regf = cstruct.cstruct()
c_regf.load(c_regf_def)


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
