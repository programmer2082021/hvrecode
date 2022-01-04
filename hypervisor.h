#include <ntddk.h>
#include <ntimage.h>
#include <intrin.h>
#include <stdint.h>
#include <stdarg.h>
#include "ia32.h"

typedef struct __vmcs_t
{
    union
    {
        uint32_t all;
        struct
        {
            uint32_t revision_identifier : 31;
            uint32_t shadow_vmcs_indicator : 1;
        } bits;
    } header;

    uint32_t abort_indicator;
    uint8_t data[0x1000 - 2 * sizeof(uint32_t)];
} vmcs_t;

typedef struct __vmxon_t
{
    union
    {
        uint32_t all;
        struct
        {
            uint32_t revision_identifier : 31;
            uint32_t shadow_vmcs_indicator : 1;
        } bits;
    } header;

    uint32_t abort_indicator;
    uint8_t data[0x1000 - 2 * sizeof(uint32_t)];
} vmxon_t;

typedef struct __vcpu_t
{
    struct vmm_t* vmm;

    struct vmcs_t* vmcs;
    uint64_t vmcs_physical;

    struct vmxon_t* vmxon;
    uint64_t vmxon_physical;
} vcpu_t;

typedef struct __vmm_t
{
    struct vcpu_t* vcpu_array;
    uint32_t vcpu_count;

    void* stack;
} vmm_t;
