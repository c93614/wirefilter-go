package wirefilter

//#cgo linux LDFLAGS: -L${SRCDIR}/lib -Wl,-rpath,${SRCDIR}/lib -lwirefilter_ffi
//#cgo darwin LDFLAGS: -L${SRCDIR}/lib -Wl,-rpath,${SRCDIR}/lib -lwirefilter_ffi
//#cgo CFLAGS: -I${SRCDIR}/
//#include <stdbool.h>
//#include "wirefilter.h"
//typedef struct {
//	uint8_t _res2;
//	wirefilter_filter_ast_t *ast;
//} wirefilter_parsing_result_ok;
//typedef struct {
//	uint8_t _res1;
// 	wirefilter_rust_allocated_str_t msg;
//} wirefilter_parsing_result_err;
import "C"

import (
    "errors"
    "net"
    "unsafe"
)

type Type int

const (
    TYPE_IP    Type = C.WIREFILTER_TYPE_IP
    TYPE_BYTES Type = C.WIREFILTER_TYPE_BYTES
    TYPE_INT   Type = C.WIREFILTER_TYPE_INT
    TYPE_BOOL  Type = C.WIREFILTER_TYPE_BOOL
)

type Schema struct {
    ptr   *C.wirefilter_scheme_t
    rst   C.wirefilter_parsing_result_t
    types map[string]Type
}

func NewSchema() *Schema {
    r := C.wirefilter_create_scheme()
    //fmt.Printf("%T:%v\n", r, unsafe.Pointer(r))
    return &Schema{ptr: r,
        types: make(map[string]Type)}
}

func (s *Schema) AddField(name string, type_ Type) {
    cName := C.CString(name)
    cNameSizeT := C.size_t(len(name))
    defer C.free(unsafe.Pointer(cName))

    C.wirefilter_add_type_field_to_scheme(s.ptr,
        C.wirefilter_externally_allocated_str_t{
            data:   cName,
            length: cNameSizeT,
        }, C.wirefilter_type_t(type_)) // TODO: is this really safe?
    s.types[name] = type_
}

func (s *Schema) AddFields(fields map[string]Type) {
    for field, type_ := range fields {
        s.AddField(field, type_)
    }
}

func (s Schema) Parse(input string) (*Filter, error) {
    cInput := C.CString(input)
    cInputSizeT := C.size_t(len(input))
    defer C.free(unsafe.Pointer(cInput))

    parsingResult := C.wirefilter_parse_filter(s.ptr,
        C.wirefilter_externally_allocated_str_t{
            data:   cInput,
            length: cInputSizeT,
        })
    // fmt.Printf("%p\n", &parsingResult)

    parsingResultPtr := unsafe.Pointer(&parsingResult)

    success := (*(*C.uint8_t)(parsingResultPtr))
    if success > 0 {
        _ok := (*C.wirefilter_parsing_result_ok)(parsingResultPtr)
        return &Filter{
            ast: _ok.ast,
            rst: &parsingResult,
        }, nil
    } else {
        _err := (*C.wirefilter_parsing_result_err)(parsingResultPtr)
        s := C.wirefilter_rust_allocated_str_t(_err.msg)
        return nil, errors.New(string(C.GoBytes(unsafe.Pointer(s.data), C.int(s.length))))
    }
}

func (s *Schema) NewExecutionContext() *ExecutionContext {
    ctx := C.wirefilter_create_execution_context(s.ptr)
    return &ExecutionContext{
        ptr:    ctx,
        schema: s,
    }
}

func (s *Schema) Close() {
    C.wirefilter_free_scheme(s.ptr)
}

type Filter struct {
    ast *C.wirefilter_filter_ast_t
    rst *C.wirefilter_parsing_result_t
    compiled *C.wirefilter_filter_t
}

func (f *Filter) Compile() {
    f.compiled = C.wirefilter_compile_filter(f.ast)
}

func (f *Filter) Uses(name string) bool {
    if f.compiled != nil {
        panic("Uses() should not called after filter have been compiled")
    }

    cName := C.CString(name)
    cNameSizeT := C.size_t(len(name))
    defer C.free(unsafe.Pointer(cName))

    r := C.wirefilter_filter_uses(f.ast, C.wirefilter_externally_allocated_str_t{
        data:   cName,
        length: cNameSizeT,
    })
    //defer C.free(unsafe.Pointer(&r))
    return bool(r)
}

func (f *Filter) JSON() string {
    if f.compiled != nil {
        panic("JSON() should not called after filter have been compiled")
    }

    r := C.wirefilter_serialize_filter_to_json(f.ast)

    data := string(C.GoBytes(unsafe.Pointer(r.data), C.int(r.length)))
    C.wirefilter_free_string(r)
    return data
}

func (f *Filter) Hash() uint64 {
    if f.compiled != nil {
        panic("Hash() should not called after filter have been compiled")
    }

    r := C.wirefilter_get_filter_hash(f.ast)
    //defer C.free(unsafe.Pointer(&r))
    return uint64(r)
}

func (f *Filter) Close() {
    if f.compiled != nil {
        C.wirefilter_free_compiled_filter(f.compiled)
    } else {
        C.wirefilter_free_parsing_result(*f.rst)
    }
}


func (f *Filter) Execute(ctx *ExecutionContext) bool {
    r := C.wirefilter_match(f.compiled, ctx.ptr)
    return bool(r)
}

type ExecutionContext struct {
    ptr    *C.wirefilter_execution_context_t
    schema *Schema
}

func (ctx *ExecutionContext) SetFieldValue(name string, value interface{}) {
    _, ok := ctx.schema.types[name]

    if !ok {
        return
    }

    cName := C.CString(name)
    cNameSizeT := C.size_t(len(name))
    defer C.free(unsafe.Pointer(cName))

    strTName := C.wirefilter_externally_allocated_str_t{
        data:   cName,
        length: cNameSizeT,
    }

    switch value.(type) {
    case int:
        C.wirefilter_add_int_value_to_execution_context(
            ctx.ptr, strTName, C.int(value.(int)))
    case net.IP:
        ip := value.(net.IP)
        if ipv4 := ip.To4(); ipv4 != nil {
            C.wirefilter_add_ipv4_value_to_execution_context(
                ctx.ptr, strTName, (*C.uchar)(unsafe.Pointer(&ipv4[0])))
        } else {
            C.wirefilter_add_ipv6_value_to_execution_context(
                ctx.ptr, strTName, (*C.uchar)(unsafe.Pointer(&ip[0])))
        }
    case []byte:
        buf := value.([]byte)
        C.wirefilter_add_bytes_value_to_execution_context(
            ctx.ptr, strTName, C.wirefilter_externally_allocated_byte_arr_t{
                data:   (*C.uchar)(unsafe.Pointer(&buf[0])), // TODO: free here needed?
                length: C.size_t(len(buf)),
            })
    case string:
        buf := []byte(value.(string))
        ctx.SetFieldValue(name, buf)
        break
    case bool:
        C.wirefilter_add_bool_value_to_execution_context(
            ctx.ptr, strTName, C._Bool(value.(bool)))
        break
    }
}

func (ctx *ExecutionContext) Close() {
    C.wirefilter_free_execution_context(ctx.ptr)
}

func Version() string {
    versionResult := C.wirefilter_get_version()
    return string(C.GoBytes(unsafe.Pointer(versionResult.data), C.int(versionResult.length)))
}
