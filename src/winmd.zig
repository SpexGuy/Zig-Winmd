//! winmd.zig
//!
//! PLEASE NOTE, THIS IS A WORK IN PROGRESS!
//! This code should not be used in production yet, or really for anything except reference.
//! It is not done yet or fully tested, and some cases are not even implemented.
//!
//! MIT License
//! 
//! Copyright (c) 2021 Martin Wickham
//! 
//! Permission is hereby granted, free of charge, to any person obtaining a copy
//! of this software and associated documentation files (the "Software"), to deal
//! in the Software without restriction, including without limitation the rights
//! to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//! copies of the Software, and to permit persons to whom the Software is
//! furnished to do so, subject to the following conditions:
//! 
//! The above copyright notice and this permission notice shall be included in all
//! copies or substantial portions of the Software.
//! 
//! THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//! IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//! FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//! AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//! LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//! OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//! SOFTWARE.
//!

const std = @import("std");
const assert = std.debug.assert;

// ----------------------- Public API -------------------------



// ---------------------------- Implementation -----------------------------

const ImageDosHeader = extern struct {
    signature: u16,
    cblp: u16,
    cp: u16,
    crlc: u16,
    cparhdr: u16,
    minalloc: u16,
    maxalloc: u16,
    ss: u16,
    sp: u16,
    csum: u16,
    ip: u16,
    cs: u16,
    lfarlc: u16,
    ovno: u16,
    res: [4]u16,
    oemid: u16,
    oeminfo: u16,
    res2: [10]u16,
    lfanew: i32,
};

const ImageFileHeader = extern struct {
    machine: u16,
    num_sections: u16,
    datetime: u32,
    symbol_table_offset: u32,
    num_symbols: u32,
    optional_header_size: u16,
    characteristics: u16,
};

const ImageDataDirectory = extern struct {
    virtual_address: u32,
    size: u32,
};

const ImageOptionalHeader32 = extern struct {
    magic: u16,
    major_linked_version: u8,
    minor_linked_version: u8,
    code_size: u32,
    initialized_data_size: u32,
    uninitialized_data_size: u32,
    entry_point_address: u32,
    start_of_code: u32,
    start_of_data: u32,
    start_of_image: u32,
    section_alignment: u32,
    file_alignment: u32,
    os_major_version: u16,
    os_minor_version: u16,
    image_major_version: u16,
    image_minor_version: u16,
    subsystem_major_version: u16,
    subsystem_minor_version: u16,
    win32_version: u32,
    image_size: u32,
    headers_size: u32,
    checksum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    stack_reserve_size: u32,
    stack_commit_size: u32,
    heap_reserve_size: u32,
    heap_commit_size: u32,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
    data_directories: [16]ImageDataDirectory,
};

const ImageOptionalHeader32Plus = extern struct {
    magic: u16,
    major_linked_version: u8,
    minor_linked_version: u8,
    code_size: u32,
    initialized_data_size: u32,
    uninitialized_data_size: u32,
    entry_point_address: u32,
    start_of_code: u32,
    start_of_image: u64,
    section_alignment: u32,
    file_alignment: u32,
    os_major_version: u16,
    os_minor_version: u16,
    image_major_version: u16,
    image_minor_version: u16,
    subsystem_major_version: u16,
    subsystem_minor_version: u16,
    win32_version: u32,
    image_size: u32,
    headers_size: u32,
    checksum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    stack_reserve_size: u64,
    stack_commit_size: u64,
    heap_reserve_size: u64,
    heap_commit_size: u64,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
    data_directories: [16]ImageDataDirectory,
};

const ImageNtHeaders32 = extern struct {
    signature: u32,
    header: ImageFileHeader,
    optional_header: ImageOptionalHeader32,
};

const ImageNtHeaders32Plus = extern struct {
    signature: u32,
    header: ImageFileHeader,
    optional_header: ImageOptionalHeader32Plus,
};

const IMAGE_SIZEOF_SHORT_NAME = 8;
const ImageSectionHeader = extern struct {
    name: [IMAGE_SIZEOF_SHORT_NAME]u8,
    misc: extern union {
        physical_address: u32,
        virtual_size: u32,
    },
    virtual_address: u32,
    raw_data_size: u32,
    raw_data_offset: u32,
    relocations_offset: u32,
    linenumbers_offset: u32,
    num_relocations: u16,
    num_linenumbers: u16,
    characteristics: u32,
};

const ImageCor20Header = extern struct {
    cb: u32,
    runtime_major_version: u16,
    runtime_minor_version: u16,
    metadata: ImageDataDirectory,
    flags: u32,
    // TODO fix this
    anon0: extern union {
        entry_point_token: u32,
        entry_point_rva: u32,
    },
    resources: ImageDataDirectory,
    strong_name_signature: ImageDataDirectory,
    code_manager_table: ImageDataDirectory,
    vtable_fixups: ImageDataDirectory,
    export_address_table_jumps: ImageDataDirectory,
    managed_native_header: ImageDataDirectory,
};

const TableKind = enum (u8) {
    module = 0x00,
    type_ref = 0x01,
    type_def = 0x02,

    field = 0x04,

    method_def = 0x06,

    param = 0x08,
    interface_impl = 0x09,
    member_ref = 0x0A,
    constant = 0x0B,
    custom_attribute = 0x0C,
    field_marshal = 0x0D,
    decl_security = 0x0E,
    class_layout = 0x0F,
    field_layout = 0x10,
    standalone_sig = 0x11,
    event_map = 0x12,

    event = 0x14,
    property_map = 0x15,

    property = 0x17,
    method_semantics = 0x18,
    method_impl = 0x19,
    module_ref = 0x1A,
    type_spec = 0x1B,
    impl_map = 0x1C,
    field_rva = 0x1D,

    assembly = 0x20,
    assembly_processor = 0x21,
    assembly_os = 0x22,
    assembly_ref = 0x23,
    assembly_ref_processor = 0x24,
    assembly_ref_os = 0x25,
    file = 0x26,
    exported_type = 0x27,
    manifest_resource = 0x28,
    nested_class = 0x29,
    generic_param = 0x2A,
    method_spec = 0x2B,
    generic_param_constraint = 0x2C,

    invalid = 0xFF,
    _,

    /// List of valid table kinds
    const values = comptime blk: {
        var t1 = [_]TableKind{};
        const Any = struct { v: anytype };
        var any = Any{ .v = t1 };
        for (@typeInfo(TableKind).Enum.fields) |field| {
            const tag = @field(@This(), field.name);
            if (tag != .invalid) {
                const tmp = any.v ++ [_]TableKind{ tag };
                any.v = tmp;
            }
        }
        break :blk any.v;
    };

    /// Use this value as the length of an array
    /// where kinds are keys.  Does not include
    /// invalid values, always check bounds.
    const num_valid_kinds = comptime blk: {
        var max_kind = 0;
        for (@typeInfo(TableKind).Enum.fields) |field| {
            if (@field(@This(), field.name) == .invalid) {
                continue;
            }
            if (field.value > max_kind) {
                max_kind = field.value;
            }
        }
        assert(max_kind == 0x2C);
        break :blk max_kind + 1;
    };

    // Array of row types, mapping from TableKind index to type
    const row_types = comptime blk: {
        var types = [_]type{ InvalidRow } ** num_valid_kinds;
        for (all_row_types) |Row| {
            if (Row.tag != .invalid) {
                const kind: TableKind = Row.tag;
                const index = @enumToInt(kind);
                if (types[index] != InvalidRow) {
                    @compileError("Both "++@typeName(types[index])++
                                  " and "++@typeName(Row)++
                                  " have tag "++@tagName(kind));
                }
                types[index] = Row;
            }
        }
        break :blk types;
    };

    /// Get the type of a row of the table corresponding to the given kind.
    pub fn RowType(comptime kind: TableKind) type {
        const index = @enumToInt(kind);
        if (index < row_types.len) {
            return row_types[index];
        }
        return InvalidRow;
    }
};

// Assert that no two rows have the same kind

const InvalidRow = packed struct {
    pub usingnamespace RowMixin(.invalid, @This());

    __reserved0: u16 = 0,
};

// The following enums are used for "coded indexes".
// A coded index is represented in the file as an index
// bit-packed with one of these restricted enums.\
// The names in these enums must exactly match the names
// in the TableKind enum, so that metaprogramming can
// match them when generating conversion code.
// Use `decodeIndex` to convert from a coded index
// to a table and index.
const GenericIndex = struct {
    table: TableKind,
    index: u32,
};

fn CodedIndexMixin(comptime Enum: type) type {
    const enum_info = @typeInfo(Enum).Enum;
    const num_bits = @bitSizeOf(Enum);
    const num_values = 1 << num_bits;
    const mask = num_values - 1;

    if (enum_info.fields.len != num_values and enum_info.is_exhaustive) {
        @compileError("Coded enum "++@typeName(Enum)++" does not fill all slots, but is not exhaustive.");
    }

    var kind_lookup = [_]TableKind{ .invalid } ** num_values;
    for (enum_info.fields) |field| {
        kind_lookup[field.value] = @field(TableKind, field.name);
    }

    return struct {
        pub fn Type(comptime self: Enum) type {
            return self.toGeneric().Type();
        }

        pub inline fn toGeneric(self: Enum) TableKind {
            return kind_lookup[@enumToInt(self)];
        }
        pub fn fromGeneric(target: TableKind) error{WinmdInvalidTableReference}!Enum {
            // For now don't generate a reverse lookup table.
            // since these enums are small, iterate the forward table.
            for (kind_lookup) |kind, i| {
                if (kind != .invalid and kind == target) {
                    const tag = @intCast(enum_info.tag_type, i);
                    return @intToEnum(Enum, tag);
                }
            }
            return error.WinmdInvalidTableReference;
        } 

        pub inline fn decodeTable(value: u32) Enum {
            return @intToEnum(Enum, @truncate(enum_info.tag_type, value));
        }
        pub inline fn decodeIndex(value: u32) u32 {
            return value >> num_bits;
        }

        pub fn decode(value: u32) GenericIndex {
            return .{
                .table = decodeTable(value).toGeneric(),
                .index = decodeIndex(value),
            };
        }

        pub fn encode(index: GenericIndex) error{WinmdInvalidTableReference}!u32 {
            const encoded_value = try fromGeneric(index.table);
            return (index.index << num_bits) | @as(u32, @enumToInt(encoded_value));
        }
    };
}

pub const TypeDefOrRef = enum (u2) {
    pub usingnamespace CodedIndexMixin(@This());

    type_def = 0,
    type_ref = 1,
    type_spec = 2,
    _,
};

/// A table which can be a declaring scope
/// for a constant.  The .constant table
/// has a back reference to its parent.
pub const HasConstant = enum (u2) {
    pub usingnamespace CodedIndexMixin(@This());

    field = 0,
    param = 1,
    property = 2,
    _,
};

pub const HasCustomAttribute = enum (u5) {
    pub usingnamespace CodedIndexMixin(@This());

    method_def = 0,
    field = 1,
    type_ref = 2,
    type_def = 3,
    param = 4,
    interface_impl = 5,
    member_ref = 6,
    module = 7,
    // This is called out in the spec,
    // but there is no permission table?
    // permission = 8,
    property = 9,
    event = 10,
    standalone_sig = 11,
    module_ref = 12,
    type_spec = 13,
    assembly = 14,
    assembly_ref = 15,
    file = 16,
    exported_type = 17,
    manifest_resource = 18,
    generic_param = 19,
    generic_param_constraint = 20,
    method_spec = 21,
    _,
};

pub const HasFieldMarshal = enum (u1) {
    pub usingnamespace CodedIndexMixin(@This());

    field = 0,
    param = 1,
};

pub const HasDeclSecurity = enum (u2) {
    pub usingnamespace CodedIndexMixin(@This());

    type_def = 0,
    method_def = 1,
    assembly = 2,
    _,
};

pub const MemberRefParent = enum (u3) {
    pub usingnamespace CodedIndexMixin(@This());

    type_def = 0,
    type_ref = 1,
    module_ref = 2,
    method_def = 3,
    type_spec  = 4,
    _,
};

pub const HasSemantics = enum (u1) {
    pub usingnamespace CodedIndexMixin(@This());

    event = 0,
    property = 1,
};

pub const MethodDefOrRef = enum (u1) {
    pub usingnamespace CodedIndexMixin(@This());

    method_def = 0,
    member_ref = 1,
};
const MemberForwarded = enum (u1) {
    pub usingnamespace CodedIndexMixin(@This());

    field = 0,
    method_def = 1,
};
const Implementation = enum (u2) {
    pub usingnamespace CodedIndexMixin(@This());

    file = 0,
    assembly_ref = 1,
    exported_type = 2,
    _,
};
const CustomAttributeType = enum (u3) {
    pub usingnamespace CodedIndexMixin(@This());

    method_def = 2,
    member_ref = 3,
    _,
};

pub const ResolutionScope = enum (u2) {
    pub usingnamespace CodedIndexMixin(@This());

    module = 0,
    module_ref = 1,
    assembly_ref = 2,
    type_ref = 3,
};

pub const TypeOrMethodDef = enum (u1) {
    pub usingnamespace CodedIndexMixin(@This());

    type_def = 0,
    method_def = 1,
};

const all_coded_enums = [_]type{
    TypeDefOrRef,
    HasConstant,
    HasCustomAttribute,
    HasFieldMarshal,
    HasDeclSecurity,
    MemberRefParent,
    HasSemantics,
    MethodDefOrRef,
    MemberForwarded,
    Implementation,
    CustomAttributeType,
    ResolutionScope,
    TypeOrMethodDef,
};


pub const MemberAccess = enum (u3) {
    /// cannot be referenced
    compiler_controlled = 0,

    /// only in own type
    private = 1,

    /// only in subtypes in assembly
    family_and_assembly = 2,

    /// only in assembly
    assembly = 3,

    /// only in subtypes (protected)
    family = 4,

    /// in subtypes or anywhere in this assembly
    family_or_assembly = 5,

    /// anywhere
    public = 6,

    _,
};

pub const CodeType = enum (u2) {
    cil = 0,
    native = 1,
    optil = 2,
    runtime = 3,
};

pub const Managed = enum (u1) {
    managed = 0,
    unmanaged = 1,
};

pub const VtableLayout = enum (u1) {
    reuse_slot = 0,
    new_slot = 1,
};

/// Note: These values exactly match the equivalent
/// values in ElementType, so they can be cross-cast.
pub const ConstantType = extern enum (u16) {
    bool = 2,
    char = 3,
    i8 = 4,
    u8 = 5,
    i16 = 6,
    u16 = 7,
    i32 = 8,
    u32 = 9,
    i64 = 10,
    u64 = 11,
    f32 = 12,
    f64 = 13,
    string = 14,
    class = 18,
};

// TODO: This might be a secret packed struct
pub const ElementType = extern enum (u8) {
    end_sentinel = 0,

    void = 1,
    bool = 2,
    char = 3,
    i8 = 4,
    u8 = 5,
    i16 = 6,
    u16 = 7,
    i32 = 8,
    u32 = 9,
    i64 = 10,
    u64 = 11,
    f32 = 12,
    f64 = 13,
    string = 14,

    /// followed by TypeSig
    ptr = 15,
    /// followed by TypeSig
    by_ref = 16,
    /// followed by TypeDef or TypeRef
    value_type = 17,
    /// followed by TypeDef or TypeRef
    class = 18,
    /// generic parameter in a type definition
    generic_type_parameter = 19,
    array = 20,
    generic_instance = 21,
    typed_by_ref = 22,

    // 23 is unused?

    isize = 24,
    usize = 25,

    // 26 is unused?

    /// followed by full method system
    fn_ptr = 27,
    /// C# System.Object
    object = 28,
    sized_array = 29,
    /// generic parameter in function definition
    generic_fn_parameter = 30,
    /// followed by TypeDef or TypeRef
    required_modifier = 31,
    /// followed by TypeDef or TypeRef
    optional_modifier = 32,
    internal = 33,

    /// Or'd with element types that follow
    modifier = 64,
    vararg_sentinel = 65,

    pinned = 69, // nice

    type = 80,
    tagged_object = 81,
    attr_field = 83,
    attr_property = 84,
    attr_enum = 85,
};

pub const CallingConvention = packed struct {
    kind: Kind,
    is_generic: bool,
    has_this: bool,
    has_explicit_this: bool,
    __reserved: bool = false,

    pub const Kind = enum (u4) {
        default = 0,
        var_args = 5,
        field = 6,
        local_signature = 7,
        property = 8,
        _,
    };
};

pub const AssemblyHashAlgorithm = extern enum (u32) {
    none = 0,
    reserved_md5 = 0x8003,
    sha1 = 0x8004,
};

/// Note: This struct relies on the current packed struct layout rules.
/// Those may change in the future, which would break this.
pub const AssemblyFlags = packed struct {
    has_full_public_key: bool,
    __reserved0: u7 = 0,

    is_retargetable: bool,
    needs_windows_runtime: bool,
    __reserved1: u4 = 0,
    disable_jit_optimizer: bool,
    enable_jit_tracking: bool,

    __reserved2: u8 = 0,
    __reserved3: u8 = 0,
};

/// Note: This struct relies on the current packed struct layout rules.
/// Those may change in the future, which would break this.
pub const AssemblyAttributes = packed struct {
    __reserved0: u9 = 0,
    has_special_name: bool,
    has_rt_special_name: bool,
    __reserved1: u5 = 0,
};

/// Note: This struct relies on the current packed struct layout rules.
/// Those may change in the future, which would break this.
pub const EventAttributes = packed struct {
    __reserved0: u8 = 0,

    __reserved1: u1 = 0,
    has_special_name: bool,
    has_rt_special_name: bool,
    __reserved2: u5 = 0,
};

/// Note: This struct relies on the current packed struct layout rules.
/// Those may change in the future, which would break this.
pub const FieldAttributes = packed struct {
    comptime { if (@bitSizeOf(MemberAccess) != 3) @compileError("MemberAccess must be 3 bits"); }

    access: MemberAccess,
    __reserved0: u1 = 0,
    is_static: bool,
    is_init_only: bool,
    is_literal: bool,
    is_not_serialized: bool,

    has_field_rva: bool,
    has_special_name: bool,
    has_rt_special_name: bool,
    __reserved1: u1 = 0,
    has_field_marshal: bool,
    is_pinvoke_impl: bool,
    __reserved2: u1 = 0,
    has_default: bool,
};

/// Note: This struct relies on the current packed struct layout rules.
/// Those may change in the future, which would break this.
pub const FileAttributes = packed struct {
    has_no_metadata: bool,
    __reserved0: u7 = 0,

    __reserved1: u8 = 0,
};

/// Note: This struct relies on the current packed struct layout rules.
/// Those may change in the future, which would break this.
pub const GenericParameterAttributes = packed struct {
    variance: Variance, // 2 bits
    special_constraint: SpecialConstraint, // 3 bits
    __reserved0: u11 = 0,

    pub const Variance = enum (u2) {
        none = 0,
        covariant = 1,
        contravariant = 2,
        _,
    };

    // Note: Even though these are bits, this is not a mask.
    pub const SpecialConstraint = enum (u3) {
        reference_type_constraint = 1,
        not_nullable_value_type_constraint = 2,
        default_constructor_constraint = 4,
        _,
    };
};

pub const ManifestResourceAttributes = packed struct {
    visibility: enum (u3) {
        public = 1,
        private = 2,
        _,
    },
    __reserved0: u5 = 0,

    __reserved1: u8 = 0,
    __reserved2: u8 = 0,
    __reserved3: u8 = 0,
};

/// Note: This struct relies on the current packed struct layout rules.
/// Those may change in the future, which would break this.
pub const MethodAttributes = packed struct {
    comptime {
        if (@bitSizeOf(MemberAccess) != 3)
            @compileError("MemberAccess must be 3 bits");
        if (@bitSizeOf(VtableLayout) != 1)
            @compileError("VtableLayout must be 1 bit");
    }

    access: MemberAccess,
    is_unmanaged_export: bool,
    is_static: bool,
    is_final: bool,
    is_virtual: bool,
    is_hide_by_signature: bool,

    vtable_layout: VtableLayout,
    is_strict: bool,
    is_abstract: bool,
    is_special_name: bool,
    is_rt_special_name: bool,
    is_pinvoke_impl: bool,
    has_security: bool,
    is_require_sec_object: bool,
};

/// Note: This struct relies on the current packed struct layout rules.
/// Those may change in the future, which would break this.
pub const MethodImplAttributes = packed struct {
    comptime {
        if (@bitSizeOf(CodeType) != 2)
            @compileError("CodeType must be 2 bits");
        if (@bitSizeOf(Managed) != 1)
            @compileError("Managed must be 1 bit");
    }

    code_type: CodeType, // 2 bits
    managed: Managed, // 1 bit
    is_no_inline: bool,
    is_forward_ref: bool,
    is_synchronized: bool,
    is_no_optimization: bool,
    is_preserve_sig: bool,

    __reserved0: u4 = 0,
    is_internal_call: bool,
    __reserved1: u3 = 0,
};

/// Note: This struct relies on the current packed struct layout rules.
/// Those may change in the future, which would break this.
pub const MethodSemanticsAttributes = packed struct {
    is_setter: bool,
    is_getter: bool,
    is_other: bool,
    is_add_on: bool,
    is_remove_on: bool,
    is_fire: bool,
    __reserved0: u10 = 0,
};

/// Note: This struct relies on the current packed struct layout rules.
/// Those may change in the future, which would break this.
pub const ParamAttributes = packed struct {
    is_in: bool,
    is_out: bool,
    __reserved0: u2 = 0,
    is_optional: bool,
    __reserved1: u3 = 0,

    __reserved2: u4 = 0,
    has_default: bool,
    has_field_marshal: bool,
    __reserved3: u2 = 0,
};

pub const PInvokeAttributes = packed struct {
    is_no_mangle: bool,
    char_set: enum (u2) {
        not_specified = 0,
        ansi = 1,
        unicode = 2,
        auto = 3,
    },
    __reserved0: u2 = 0,
    supports_last_error: bool,
    __reserved1: u2 = 0,

    calling_convention: enum (u3) {
        platform_api = 1,
        cdecl = 2,
        stdcall = 3,
        thiscall = 4,
        fastcall = 5,
        _,
    },
    __reserved2: u5 = 0,
};

/// Note: This struct relies on the current packed struct layout rules.
/// Those may change in the future, which would break this.
pub const PropertyAttributes = packed struct {
    __reserved0: u8 = 0,

    __reserved1: u1 = 0,
    is_special_name: bool,
    is_rt_special_name: bool,
    __reserved2: u1 = 0,
    has_default: bool,
    __reserved3: u3 = 0,
};

/// Note: This struct relies on the current packed struct layout rules.
/// Those may change in the future, which would break this.
pub const TypeAttributes = packed struct {
    visibility: Visibility, // 3 bits
    layout: Layout, // 2 bits
    semantics: Semantics, // 1 bit
    __reserved0: u1 = 0,
    is_abstract: bool,

    is_sealed: bool,
    __reserved1: u1 = 0,
    is_special_name: bool,
    is_rt_special_name: bool,
    is_import: bool,
    is_serializable: bool,
    is_windows_runtime: bool,
    __reserved2: u1 = 0,

    string_format: StringFormat, // 4 bits
    is_before_field_init: bool,
    is_type_forwarder: bool,
    __reserved3: u2 = 0,

    __reserved4: u8 = 0,


    pub const Visibility = enum (u3) {
        not_public = 0,
        public = 1,
        nested_public = 2,
        nested_private = 3,
        nested_family = 4,
        nested_assembly = 5,
        nested_family_and_assembly = 6,
        nested_family_or_assembly = 7,
    };

    pub const Layout = enum (u2) {
        auto = 0,
        sequential = 1,
        explicit = 2,
        _,
    };

    pub const Semantics = enum (u1) {
        class = 0,
        interface = 1,
    };

    pub const StringFormat = packed struct {
        class: Class,
        custom_format: u2 = 0,

        pub const Class = enum (u2) {
            ansi = 0,
            unicode = 1,
            auto = 2,
            custom_format = 3,
        };
    };
    comptime {
        if (@bitSizeOf(StringFormat) != 4)
            @compileError("StringFormat must be 4 bits");
    }
};

const MAX_INDEX_COLUMNS = comptime blk: {
    var max_indices = 0;
    for (TableKind.values) |kind| {
        const Row = kind.RowType();
        var next_index = 0;
        for (@typeInfo(Row).Struct.fields) |field| {
            if (@typeInfo(field.field_type) == .Struct and @hasDecl(field.field_type, "index_column")) {
                const index = field.field_type.index_column;
                if (index != next_index) {
                    @compileError("In Row struct "++@typeName(Row)++" for kind "++@tagName(kind)++
                        ", index field "++field.name++" is out of order.");
                }
                next_index += 1;
            } else {
                if (next_index != 0) {
                    @compileError("In Row struct "++@typeName(Row)++" for kind "++@tagName(kind)++
                        ", field "++field.name++" comes after index fields, but is not an index.");
                }
            }
        }
        if (next_index > max_indices) {
            max_indices = next_index;
        }
    }
    assert(max_indices == 5);
    break :blk max_indices;
};

const IndexPosition = struct {
    offset: u8,
    size: u8,
};

pub const GenericTable = struct {
    data: ?[*]const u8,
    rows: u32,
    row_size: u32,
    indexes: [MAX_INDEX_COLUMNS]IndexPosition,

    fn at(self: GenericTable, comptime T: type, index: u32) *const T {
        assert(index < self.rows);
        return @ptrCast(*const T, @alignCast(@alignOf(T), self.data.? + index * self.row_size));
    }

    fn iterator(self: GenericTable) Iterator {
        return .{
            .next_row = self.data,
            .remaining_items = self.rows,
            .row_size = self.row_size,
        };
    }

    fn range(self: GenericTable, start: u32, end: u32) Iterator {
        return .{
            .next_row = if (start == 0) self.data else (self.data.? + start),
            .remaining_items = end - start,
            .row_size = self.row_size,
        };
    }

    pub const Iterator = struct {
        next_row: ?[*]const u8,
        remaining_items: usize,
        row_size: usize,

        pub fn next(self: *Iterator, comptime T: type) ?*const T {
            if (self.remaining_items == 0) return null;

            self.remaining_items -= 1;
            const next_row = self.next_row.?;
            self.next_row = next_row + row_size;
            return @ptrCast(*const T, next_row);
        }
    };

    pub fn as(self: GenericTable, comptime kind: TableKind) Table(kind) {
        return .{ .generic = self };
    }
};

pub fn Table(comptime kind: TableKind) type {
    return struct {
        pub const tag = kind;
        pub const Row = kind.RowType();

        generic: GenericTable,

        pub fn at(self: @This(), index: u32) *const Row {
            return self.generic.at(Row, index);
        }

        pub fn iterator(self: @This()) Iterator {
            return .{ .generic = self.generic.iterator() };
        }

        pub fn range(self: @This(), start: u32, end: u32) Iterator {
            return .{ .generic = self.generic.range(start, end) };
        }

        const Iterator = struct {
            generic: GenericTable.Iterator,

            pub fn next(self: *Iterator) ?*const Row {
                return self.generic.next(Row);
            }
        };
    };
}

const SizeInfo = struct {
    has_large_string_indexes: bool,
    has_large_guid_indexes: bool,
    has_large_blob_indexes: bool,
    database: *const Database,
};

pub const Database = struct {
    tables: [TableKind.num_valid_kinds]GenericTable,
    strings: []const u8,
    blobs: []const u8,
    guids: []const [16]u8,

    pub fn getTable(self: Database, comptime kind: TableKind) Table(kind) {
        return self.tables[@enumToInt(kind)].as(kind);
    }

    pub fn getString(self: Database, index: u32) [:0]const u8 {
        const rest = self.strings[index..];
        if (std.mem.indexOfScalar(u8, rest, 0)) |null_index| {
            return rest[0..null_index :0];
        } else {
            // TODO: Invalid files may hit this case.
            unreachable;
        }
    }

    pub fn getBlob(self: Database, index: u32) []const u8 {
        var rest = self.blobs[index..];
        const encoding = rest[0] >> 5;

        switch (encoding) {
            // top bit 0, one byte size
            0, 1, 2, 3 => {
                const len = rest[0] & 0x7f;
                return rest[1..][0..len];
            },
            // top bits 10, two bytes size
            4, 5 => {
                const len = std.mem.readIntLittle(u16, rest[0..2]) & 0x3FFF;
                return rest[2..][0..len];
            },
            // top bits 110, four bytes size
            6 => {
                const len = std.mem.readIntLittle(u32, rest[0..4]) & 0x1FFF_FFFF;
                return rest[4..][0..len];
            },
            // no other valid combinations
            else => {
                // TODO: Invalid files may hit this case
                unreachable;
            },
        }
    }

    pub fn getGuid(self: Database, index: u32) *const [16]u8 {
        return &self.guids[index];
    }

    pub fn initIndices(self: *Database) void {
        const sizing = SizeInfo{
            // TODO: Pull this out of the file header
            .has_large_string_indexes = true,
            .has_large_guid_indexes = true,
            .has_large_blob_indexes = true,
            .database = self,
        };
        inline for (TableKind.values) |kind| {
            const Row = kind.RowType();
            var byte_offset: u8 = 0;
            const gen_table = &self.tables[@enumToInt(kind)];
            inline for (@typeInfo(Row).Struct.fields) |field| {
                if (@typeInfo(field.field_type) == .Struct and
                    @hasDecl(field.field_type, "index_column"))
                {
                    const index: u8 = field.field_type.index_column;
                    const size: u8 = field.field_type.calculateSize(sizing);
                    // Every index is one byte because pointers to zero sized
                    // types don't work, so we need to subtract that here.
                    // This is the offset within a row from the pointer to
                    // the index struct to the actual data in the row.
                    gen_table.indexes[index] = .{
                        .offset = byte_offset - index,
                        .size = size,
                    };
                    byte_offset += size;
                }
            }
        }
    }
};

pub fn IndexMixin(comptime column: usize) type {
    return packed struct {
        pub const index_column = column;

        pub fn readIndex(self: *const @This(), source_table: GenericTable) u32 {
            const index_data = source_table.indexes[column];
            const byte_ptr = @ptrCast([*]const u8, self) + index_data.offset;
            return switch (index_data.size) {
                2 => std.mem.readIntLittle(u16, byte_ptr[0..2]),
                4 => std.mem.readIntLittle(u32, byte_ptr[0..4]),
                else => unreachable,
            };
        }

        self: u8,
    };
}

pub fn StringIndex(comptime column: usize) type {
    return packed struct {
        const Mixin = IndexMixin(column);
        pub usingnamespace Mixin;
        raw: Mixin,

        pub fn getString(self: *@This(), source_table: GenericTable, database: Database) [:0]const u8 {
            // TODO SAFETY: These strings may not be null terminated if the file is invalid :(
            const index = self.raw.readIndex(source_table);
            return database.getString(index);
        }

        fn calculateSize(sizing_info: SizeInfo) u8 {
            return if (sizing_info.has_large_string_indexes) 4 else 2;
        }
    };
}

pub fn BlobIndex(comptime column: usize) type {
    return packed struct {
        const Mixin = IndexMixin(column);
        pub usingnamespace Mixin;
        raw: Mixin,

        pub fn getBlob(self: *@This(), source_table: GenericTable, database: Database) []const u8 {
            const index = self.raw.readIndex(source_table);
            return database.getBlob(index);
        }

        fn calculateSize(sizing_info: SizeInfo) u8 {
            return if (sizing_info.has_large_blob_indexes) 4 else 2;
        }
    };
}

pub fn GuidIndex(comptime column: usize) type {
    return packed struct {
        const Mixin = IndexMixin(column);
        pub usingnamespace Mixin;
        raw: Mixin,

        pub fn getGuid(self: *@This(), source_table: GenericTable, database: Database) *const [16]u8 {
            const index = self.raw.readIndex(source_table);
            return database.getGuid(index);
        }

        fn calculateSize(sizing_info: SizeInfo) u8 {
            return if (sizing_info.has_large_guid_indexes) 4 else 2;
        }
    };
}

pub fn TableIndex(comptime kind: TableKind, comptime column: usize) type {
    return packed struct {
        const Mixin = IndexMixin(column);
        pub usingnamespace Mixin;
        raw: Mixin,

        // TODO SAFETY: Might need to return error or optional here if index is invalid.
        pub fn getRow(self: *@This(), source_table: GenericTable, database: Database) *const kind.RowType() {
            const index = self.raw.readIndex(source_table);
            const table = database.getTable(kind);
            return table.at(index);
        }

        fn calculateSize(sizing_info: SizeInfo) u8 {
            const rows = sizing_info.database.tables[@enumToInt(kind)].rows;
            return if (rows < 1<<16) 2 else 4;
        }
    };
}

pub fn ListIndex(comptime kind: TableKind, comptime column: usize) type {
    return packed struct {
        const Mixin = IndexMixin(column);
        pub usingnamespace Mixin;
        raw: Mixin,

        pub fn iterator(self: *const @This(), source_table: GenericTable, database: Database) Table(kind).Iterator {
            const start_index = self.raw.readIndex(source_table);
            // Check if we are the last entry in the source table
            const source_table_end = @ptrToInt(source_table.data.?) + source_table.rows * source_table.row_size;
            const next_entry = @ptrToInt(self) + source_table.row_size;
            if (next_entry < source_table_end) {
                // we are not the last entry
                const next_index = @intToPtr(*const @This(), next_entry);
                const end_index = next_index.raw.readIndex(source_table);
                return database.getTable(kind).range(start_index, end_index);
            } else {
                // we are the last entry
                const table = database.getTable(kind);
                return table.range(start_index, table.generic.rows);
            }
        }

        // TODO SAFETY: Might need to return error or optional here if index is invalid.
        pub fn firstRow(self: *@This(), source_table: GenericTable, database: Database) *const kind.RowType() {
            const index = self.raw.readIndex(source_table);
            const table = database.getTable(kind);
            return table.at(index);
        }

        fn calculateSize(sizing_info: SizeInfo) u8 {
            const rows = sizing_info.database.tables[@enumToInt(kind)].rows;
            return if (rows < 1<<16) 2 else 4;
        }
    };
}

pub fn CodedIndex(comptime Enum: type, comptime column: usize) type {
    return packed struct {
        const Mixin = IndexMixin(column);
        pub usingnamespace Mixin;
        raw: Mixin,

        pub fn getKind(self: *const @This(), source_table: GenericTable) Enum {
            const index = self.raw.readIndex(source_table);
            return Enum.decodeTable(index);
        }

        // TODO SAFETY: Might need to return error or optional here if index is invalid.
        pub fn getRow(self: *const @This(), comptime kind: Enum, source_table: GenericTable, database: Database) kind.toGeneric().RowType() {
            const index = self.raw.readIndex(source_table);
            assert(Enum.decodeTable(index) == kind);
            return database.getTable(kind.toGeneric()).at(index);
        }

        fn calculateSize(sizing_info: SizeInfo) u8 {
            const enum_info = @typeInfo(Enum).Enum;
            const large_index_size = 1<<(16 - @bitSizeOf(Enum));
            var needs_large_indices = false;
            inline for (enum_info.fields) |field| {
                const generic_tag = @field(TableKind, field.name);
                const rows = sizing_info.database.tables[@enumToInt(generic_tag)].rows;
                if (rows >= large_index_size) {
                    needs_large_indices = true;
                }
            }
            return if (needs_large_indices) 4 else 2;
        }
    };
}

// ---------------------- Tables ---------------------

fn RowMixin(comptime kind: @Type(.EnumLiteral), comptime Row: type) type {
    const typed_kind: TableKind = kind; // If this fails, you have misspelled the kind.

    if (@typeInfo(Row).Struct.layout != .Packed) {
        @compileError("Row structs must have packed layout, "++@typeName(Row)++" does not.");
    }
    if (@alignOf(Row) > 2) {
        @compileError("Row structs must be two byte aligned, "++@typeName(Row)++" is not.");
    }

    return struct {
        pub const tag = kind;
    };
}

const AssemblyRow = packed struct {
    pub usingnamespace RowMixin(.assembly, @This());

    hash_algorithm: AssemblyHashAlgorithm,
    major_version: u16,
    minor_version: u16,
    build_number: u16,
    revision_number: u16,
    flags: AssemblyFlags,

    public_key_index: BlobIndex(0),
    name_index: StringIndex(1),
    culture_index: StringIndex(2),
};

const AssemblyOsRow = packed struct {
    pub usingnamespace RowMixin(.assembly_os, @This());

    os_platform_id: u32,
    os_major_version: u32,
    os_minor_version: u32,
};

const AssemblyProcessorRow = packed struct {
    pub usingnamespace RowMixin(.assembly_processor, @This());

    processor: u32,
};

const AssemblyRefRow = packed struct {
    pub usingnamespace RowMixin(.assembly_ref, @This());

    major_version: u16,
    minor_version: u16,
    build_number: u16,
    revision_number: u16,
    flags: AssemblyFlags,

    public_key_or_token_index: BlobIndex(0),
    name: StringIndex(1),
    culture: StringIndex(2),
    hash_value: BlobIndex(3),
};

const AssemblyRefOsRow = packed struct {
    pub usingnamespace RowMixin(.assembly_ref_os, @This());

    os_platform_id: u32,
    os_major_version: u32,
    os_minor_version: u32,

    assembly_ref: TableIndex(.assembly_ref, 0),
};

const AssemblyRefProcessorRow = packed struct {
    pub usingnamespace RowMixin(.assembly_ref_processor, @This());

    processor: u32,

    assembly_ref: TableIndex(.assembly_ref, 0),
};

const ClassLayoutRow = packed struct {
    pub usingnamespace RowMixin(.class_layout, @This());

    // maximum field alignment.
    // If 0, use ABI alignment.
    packing_size: u16,

    // total size, 0 means it must be calculated
    // based on packing size and ABI alignment
    class_size: u32,

    parent: TableIndex(.type_def, 0),
};

const ConstantRow = packed struct {
    pub usingnamespace RowMixin(.constant, @This());

    type: ConstantType,
    __reserved0: u8 = 0,

    /// The scope in which the constant is declared
    parent: CodedIndex(HasConstant, 0),

    /// The constant value
    value: BlobIndex(1),
};

const CustomAttributeRow = packed struct {
    pub usingnamespace RowMixin(.custom_attribute, @This());

    parent: CodedIndex(HasCustomAttribute, 0),
    type: CodedIndex(CustomAttributeType, 1),
    value: BlobIndex(2),
};

const DeclSecurityRow = packed struct {
    pub usingnamespace RowMixin(.decl_security, @This());

    action: u16,

    parent: CodedIndex(HasDeclSecurity, 0),
    permission_set: BlobIndex(1),
};

const EventMapRow = packed struct {
    pub usingnamespace RowMixin(.event_map, @This());

    parent: TableIndex(.type_def, 0),

    events: ListIndex(.event, 1),
};

const EventRow = packed struct {
    pub usingnamespace RowMixin(.event, @This());

    flags: EventAttributes,

    name: StringIndex(0),

    /// This is the type of the event, not the
    /// type containing the event declaration.
    event_type: CodedIndex(TypeDefOrRef, 1),
};

const ExportedTypeRow = packed struct {
    pub usingnamespace RowMixin(.exported_type, @This());

    flags: TypeAttributes,

    /// Hint for the index into the type def table.
    /// This may be incorrect, and should be zero
    /// if flags.is_type_forwarder is true.
    type_def_hint: u32,

    type_name: StringIndex(0),
    type_namespace: StringIndex(1),
    
    /// Points to the location of the implementation.
    /// .file => the module containing the implementation,
    /// .exported_type => the type containing this type,
    /// .assembly_ref => the assembly containing the implementation,
    /// flags.is_type_forwarder must be set if this is .assembly_ref.
    implementation: CodedIndex(Implementation, 2),
};

const FieldRow = packed struct {
    pub usingnamespace RowMixin(.field, @This());

    flags: FieldAttributes,

    name: StringIndex(0),
    signature: BlobIndex(1),
};

const FieldLayoutRow = packed struct {
    pub usingnamespace RowMixin(.field_layout, @This());

    /// Offset into the struct
    offset: u32,

    field: TableIndex(.field, 0),
};

const FieldMarshalRow = packed struct {
    pub usingnamespace RowMixin(.field_marshal, @This());

    parent: CodedIndex(HasFieldMarshal, 0),
    native_type: BlobIndex(1),
};

const FieldRvaRow = packed struct {
    pub usingnamespace RowMixin(.field_rva, @This());

    rva: u32,
    field: TableIndex(.field, 0),
};

const FileRow = packed struct {
    pub usingnamespace RowMixin(.file, @This());

    flags: FileAttributes,

    name: StringIndex(0),
    hash: BlobIndex(1),
};

const GenericParamRow = packed struct {
    pub usingnamespace RowMixin(.generic_param, @This());

    /// Index of this parameter, starting at 0
    number: u16,
    flags: GenericParameterAttributes,

    owner: CodedIndex(TypeOrMethodDef, 0),
    name: StringIndex(1),
};

const GenericParamConstraintRow = packed struct {
    pub usingnamespace RowMixin(.generic_param_constraint, @This());

    owner: TableIndex(.generic_param, 0),
    constraint: CodedIndex(TypeDefOrRef, 1),
};

const ImplMapRow = packed struct {
    pub usingnamespace RowMixin(.impl_map, @This());

    flags: PInvokeAttributes,

    /// Can only actually index .method_def, because
    /// field export is not supported :(
    member_forwarded: CodedIndex(MemberForwarded, 0),
    import_name: StringIndex(1),
    import_scope: TableIndex(.module_ref, 2),
};

const InterfaceImplRow = packed struct {
    pub usingnamespace RowMixin(.interface_impl, @This());

    class: TableIndex(.type_def, 0),
    interface: CodedIndex(TypeDefOrRef, 1),
};

const ManifestResourceRow = packed struct {
    pub usingnamespace RowMixin(.manifest_resource, @This());

    offset: u32,
    flags: ManifestResourceAttributes,

    name: StringIndex(0),
    implementation: CodedIndex(Implementation, 1),
};

const MemberRefRow = packed struct {
    pub usingnamespace RowMixin(.member_ref, @This());

    class: CodedIndex(MemberRefParent, 0),
    name: StringIndex(1),
    signature: BlobIndex(2),
};

const MethodDefRow = packed struct {
    pub usingnamespace RowMixin(.method_def, @This());

    rva: u32,
    impl_flags: MethodImplAttributes,
    flags: MethodAttributes,

    name: StringIndex(0),
    signature: BlobIndex(1),
    param_list: ListIndex(.param, 2),
};

const MethodImplRow = packed struct {
    pub usingnamespace RowMixin(.method_impl, @This());

    class: TableIndex(.type_def, 0),
    method_body: CodedIndex(MethodDefOrRef, 1),
    method_declaration: CodedIndex(MethodDefOrRef, 2),
};

const MethodSemanticsRow = packed struct {
    pub usingnamespace RowMixin(.method_semantics, @This());

    semantics: MethodSemanticsAttributes,

    method: TableIndex(.method_def, 0),
    association: CodedIndex(HasSemantics, 1),
};

const MethodSpecRow = packed struct {
    pub usingnamespace RowMixin(.method_spec, @This());

    method: CodedIndex(MethodDefOrRef, 0),
    instantiation: BlobIndex(1),
};

const ModuleRow = packed struct {
    pub usingnamespace RowMixin(.module, @This());

    generation: u16 = 0,

    name: StringIndex(0),
    mvid: GuidIndex(1),
    enc_id: GuidIndex(2),
    enc_base_id: GuidIndex(3),
};

const ModuleRefRow = packed struct {
    pub usingnamespace RowMixin(.module_ref, @This());

    name: StringIndex(0),
};

const NestedClassRow = packed struct {
    pub usingnamespace RowMixin(.nested_class, @This());

    nested_class: TableIndex(.type_def, 0),
    enclosing_class: TableIndex(.type_def, 1),
};

const ParamRow = packed struct {
    pub usingnamespace RowMixin(.param, @This());

    flags: ParamAttributes,
    sequence: u16,
    
    name: StringIndex(0),
};

const PropertyRow = packed struct {
    pub usingnamespace RowMixin(.property, @This());

    flags: PropertyAttributes,

    name: StringIndex(0),
    type_signature: BlobIndex(1),
};

const PropertyMapRow = packed struct {
    pub usingnamespace RowMixin(.property_map, @This());

    parent: TableIndex(.type_def, 0),
    property_list: ListIndex(.property, 1),
};

const StandaloneSigRow = packed struct {
    pub usingnamespace RowMixin(.standalone_sig, @This());

    signature: BlobIndex(0),
};

const TypeDefRow = packed struct {
    pub usingnamespace RowMixin(.type_def, @This());

    flags: TypeAttributes,
    
    type_name: StringIndex(0),
    type_namespace: StringIndex(1),
    extends: CodedIndex(TypeDefOrRef, 2),
    field_list: ListIndex(.field, 3),
    method_list: ListIndex(.method_def, 4),
};

const TypeRefRow = packed struct {
    pub usingnamespace RowMixin(.type_ref, @This());

    resolution_scope: CodedIndex(ResolutionScope, 0),
    type_name: StringIndex(1),
    type_namespace: StringIndex(2),
};

const TypeSpecRow = packed struct {
    pub usingnamespace RowMixin(.type_spec, @This());

    signature: BlobIndex(0),
};

const all_row_types = [_]type{
    AssemblyRow,
    AssemblyOsRow,
    AssemblyProcessorRow,
    AssemblyRefRow,
    AssemblyRefOsRow,
    AssemblyRefProcessorRow,
    ClassLayoutRow,
    ConstantRow,
    CustomAttributeRow,
    DeclSecurityRow,
    EventMapRow,
    EventRow,
    ExportedTypeRow,
    FieldRow,
    FieldLayoutRow,
    FieldMarshalRow,
    FieldRvaRow,
    FileRow,
    GenericParamRow,
    ImplMapRow,
    InterfaceImplRow,
    ManifestResourceRow,
    MemberRefRow,
    MethodDefRow,
    MethodImplRow,
    MethodSemanticsRow,
    MethodSpecRow,
    ModuleRow,
    ModuleRefRow,
    NestedClassRow,
    ParamRow,
    PropertyRow,
    PropertyMapRow,
    StandaloneSigRow,
    TypeDefRow,
    TypeRefRow,
    TypeSpecRow,
};

// --------------------------------- Tests ---------------------------------

// mark Tests as referenced so its' tests get compiled.
comptime { _ = Tests; }

pub const runAllTests = Tests.runAll;
const Module = @This();


const Tests = struct {
    const testing = std.testing;
    const print = std.debug.print;

    fn runAll() void {
        comptime {
            @setEvalBranchQuota(100000);
            refAllDeclsRecursive(Module);
            for (TableKind.values) |kind| {
                refAllDeclsRecursive(Table(kind));
            }
            var i = 0;
            while (i < MAX_INDEX_COLUMNS) : (i += 1) {
                refAllDeclsRecursive(StringIndex(i));
                refAllDeclsRecursive(BlobIndex(i));
                refAllDeclsRecursive(GuidIndex(i));
                for (TableKind.values) |kind| {
                    refAllDeclsRecursive(TableIndex(kind, i));
                    refAllDeclsRecursive(ListIndex(kind, i));
                }
                for (all_coded_enums) |Code| {
                    refAllDeclsRecursive(CodedIndex(Code, i));
                }
            }
        }

        const tests = .{
            "initIndices"
        };

        print("Running tests...\n", .{});
        inline for (tests) |fn_name| {
            print("{}...\n", .{fn_name});
            @field(@This(), "test_"++fn_name)();
        }
        print("All {} tests passed.\n", .{tests.len});
    }

    test "initIndices" { test_initIndices(); }
    fn test_initIndices() void {
        var d: Database = undefined;
        d.initIndices();
    }

    fn refDeclsList(comptime T: type, comptime decls: []const std.builtin.TypeInfo.Declaration) void {
        for (decls) |decl| {
            if (decl.is_pub) {
                _ = @field(T, decl.name);
                switch (decl.data) {
                    .Type => |SubType| refAllDeclsRecursive(SubType),
                    .Var => |Type| {},
                    .Fn => |fn_decl| {},
                }
            }
        }
    }

    fn refAllDeclsRecursive(comptime T: type) void {
        comptime {
            switch (@typeInfo(T)) {
                .Struct => |info| refDeclsList(T, info.decls),
                .Union => |info| refDeclsList(T, info.decls),
                .Enum => |info| refDeclsList(T, info.decls),
                .Opaque => |info| refDeclsList(T, info.decls),
                else => {},
            }
        }
    }
};
