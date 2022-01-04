#include <ntddk.h>
#include <ntimage.h>
#include <intrin.h>
#include <stdint.h>
#include <stdarg.h>
#include "ia32.hpp"
#pragma comment(lib, "ntoskrnl.lib" )


union __cr_fixed_t
{
    struct
    {
        unsigned long low;
        long high;
    } split;
    struct
    {
        unsigned long low;
        long high;
    } u;
    long long all;
};

namespace log
{
    uint64_t count = 0;

    void success(const char* fmt, ...)
    {
        va_list args;
        va_start(args, fmt);
        vDbgPrintExWithPrefix("[SUCCESS] ", DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, fmt, args);
        va_end(args);

        count++;
    }

    void debug(const char* fmt, ...)
    {
        va_list args;
        va_start(args, fmt);
        vDbgPrintExWithPrefix("[DEBUG] ", DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, fmt, args);
        va_end(args);

        count++;
    }

    void error(const char* fmt, ...)
    {
        va_list args;
        va_start(args, fmt);
        vDbgPrintExWithPrefix("[ERROR] ", DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, fmt, args);
        va_end(args);

        count++;
    }
}

namespace utils
{
    void adjust_control_registers(void)
    {
        cr4 cr4 = { 0 };
        cr0 cr0 = { 0 };
        union __cr_fixed_t cr_fixed;
        
        cr_fixed.all = __readmsr(IA32_VMX_CR0_FIXED0);
        cr0.flags = __readcr0();
        cr0.flags |= cr_fixed.split.low;
        cr_fixed.all = __readmsr(IA32_VMX_CR0_FIXED1);
        cr0.flags &= cr_fixed.split.low;
        __writecr0(cr0.flags);

        cr_fixed.all = __readmsr(IA32_VMX_CR4_FIXED0);
        cr4.flags = __readcr4();
        cr4.flags |= cr_fixed.split.low;
        cr_fixed.all = __readmsr(IA32_VMX_CR4_FIXED1);
        cr4.flags &= cr_fixed.split.low;
        __writecr4(cr4.flags);
    }

    uint8_t supports_vmx_operation(void)
    {
        int cpuid[4];
        __cpuid(cpuid, 1);

        if (CPUID_FEATURE_INFORMATION_ECX_VIRTUAL_MACHINE_EXTENSIONS(cpuid[2]))
        {
            return TRUE;
        }

        return FALSE;
    }

    uint8_t enable_vmx_operation(void)
    {
        cr4 cr4 = { 0 };
        ia32_feature_control_register feature_control = { 0 };

        cr4.flags = __readcr4();
        cr4.vmx_enable = 1;

        __writecr4(cr4.flags);
        feature_control.flags = __readmsr(IA32_FEATURE_CONTROL);

        if (feature_control.lock_bit == 0)
        {
            feature_control.enable_vmx_outside_smx = 1;
            feature_control.lock_bit = 1;

            __writemsr(IA32_FEATURE_CONTROL, feature_control.flags);
            return TRUE;
        }
        return FALSE;
    }

    void disable_vmx_operation(void)
    {
        cr4 cr4 = { 0 };
        ia32_feature_control_register feature_control = { 0 };

        cr4.flags = __readcr4();
        cr4.vmx_enable = 0;

        __writecr4(cr4.flags);
        feature_control.flags = __readmsr(IA32_FEATURE_CONTROL);


        feature_control.enable_vmx_outside_smx = 0;
        feature_control.lock_bit = 0;

        __writemsr(IA32_FEATURE_CONTROL, feature_control.flags);
    }
}





namespace vcpu
{
    constexpr uint64_t stack_size = 4096 * 6;

    struct vcpu_t
    {
        struct vmm::vmm_t* vmm;

        struct vmcs::vmcs_t* vmcs;
        uint64_t vmcs_physical;

        struct vmxon::vmxon_t* vmxon;
        uint64_t vmxon_physical;
    };

}

namespace vmcs
{
    struct vmcs_t
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
    };

    uint8_t alloc(vcpu::vcpu_t* vcpu)
    {
        ia32_vmx_basic_register vmx_basic = { 0 };
        PHYSICAL_ADDRESS physical_max;
        vmx_basic.flags = __readmsr(IA32_VMX_BASIC);
        physical_max.QuadPart = ~0ULL;

        struct vmcs::vmcs_t* vmcs;
        vmx_basic.flags = __readmsr(IA32_VMX_BASIC);
        physical_max.QuadPart = ~0ULL;

        vcpu->vmcs = (vmcs::vmcs_t*)MmAllocateContiguousMemory(PAGE_SIZE, physical_max);
        if (!vcpu->vmcs)
        {
            log::error("Failed to allocate VMCS for vCPU %d", KeGetCurrentProcessorNumber());
            return FALSE;
        }

        vcpu->vmcs_physical = MmGetPhysicalAddress(vcpu->vmcs).QuadPart;
        RtlSecureZeroMemory(vcpu->vmcs, PAGE_SIZE);
        vmcs = vcpu->vmcs;
        vmcs->header.all = vmx_basic.vmcs_revision_id;
        vmcs->header.bits.shadow_vmcs_indicator = 0;

        return TRUE;
    }

    void free(vcpu::vcpu_t vcpu)
    {
        MmFreeContiguousMemory(vcpu.vmcs);
    }
}

namespace vmxon
{
    struct vmxon_t
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
    };

    uint8_t alloc(vcpu::vcpu_t* vcpu)
    {
        ia32_vmx_basic_register vmx_basic = { 0 };
        struct vmxon::vmxon_t* vmxon;
        PHYSICAL_ADDRESS physical_max;

        if (!vcpu)
        {
            log::error("VMXON region could not be allocated. vCPU was null.\n");
            return FALSE;
        }

        vmx_basic.flags = __readmsr(IA32_VMX_BASIC);
        physical_max.QuadPart = ~0ULL;

        if (vmx_basic.vmcs_size_in_bytes > PAGE_SIZE)
        {
            vcpu->vmxon = (vmxon::vmxon_t*)MmAllocateContiguousMemory(PAGE_SIZE, physical_max);
        }
        else
        {
            vcpu->vmxon = (vmxon::vmxon_t*)MmAllocateContiguousMemory(vmx_basic.vmcs_size_in_bytes, physical_max);
        }

        if (!vcpu->vmxon)
        {
            log::error("VMXON region couldn't be allocated.");
            MmFreeContiguousMemory(vcpu->vmxon);
            return FALSE;
        }

        vcpu->vmxon_physical = MmGetPhysicalAddress(vcpu->vmxon).QuadPart;

        vmxon = vcpu->vmxon;
        RtlSecureZeroMemory(vmxon, PAGE_SIZE);

        vmxon->header.all = vmx_basic.vmcs_revision_id;

        log::debug("VMXON for vcpu %d allocated:\n\t-> VA: %llX\n\t-> PA: %llX\n\t-> REV: %X\n",
            KeGetCurrentProcessorNumber(),
            vcpu->vmxon,
            vcpu->vmxon_physical,
            vcpu->vmxon->header.all);

        return TRUE;
    }

    void free(vcpu::vcpu_t* vcpu)
    {
        MmFreeContiguousMemory(vcpu->vmxon);
    }
}

namespace vmm
{
    struct vmm_t
    {
        struct vcpu::vcpu_t* vcpu_array;
        uint32_t vcpu_count;

        void* stack;
    };

    struct vmm_t* alloc(void)
    {
        struct vmm_t* vmm = (vmm_t*)ExAllocatePool(NonPagedPool, sizeof(struct vmm_t));

        if (!vmm)
        {
            log::error("The VMM could not be allocated.\n");
            return NULL;
        }

        vmm->vcpu_count = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

        vmm->vcpu_array = (vcpu::vcpu_t*)ExAllocatePool(NonPagedPool, sizeof(struct vcpu::vcpu_t*) * vmm->vcpu_count);
        if (!vmm->vcpu_array)
        {
            log::error("The vCPU array could not be allocated.\n");
            ExFreePool(vmm);
            return NULL;
        }

        vmm->stack = ExAllocatePool(NonPagedPool, vcpu::stack_size);
        if (!vmm->stack)
        {
            log::error("The VMM stack could not be allocated.\n");
            ExFreePool(vmm->vcpu_array);
            ExFreePool(vmm);
            return NULL;
        }

        memset(vmm->stack, 0xCC, vcpu::stack_size);
        
        log::success("VMM, VMXON, and VMCS allocated for processor %d:\n\t vCPU array: %llX\n\t VMM stack: %llX\n\t Processor count %X\n", KeGetCurrentProcessorNumber(), vmm, vmm->vcpu_array, vmm->stack, vmm->vcpu_count);

        // improper unwind actions
        for (uint32_t current_vcpu = 0; current_vcpu < vmm->vcpu_count; current_vcpu)
        {
            if (!vmcs::alloc(&vmm->vcpu_array[current_vcpu]))
            {
                log::error("Could not allocate VMCS for processor %d\n", (uint32_t)KeGetCurrentProcessorNumber());

                // free other VMCSes

                return NULL;
            }

            if (!vmxon::alloc(&vmm->vcpu_array[current_vcpu]))
            {
                log::error("Could not allocate VMXON for processor %d\n", (uint32_t)KeGetCurrentProcessorNumber());

                // free other VMXON regions

                return NULL;
            }
        }

        return vmm;
    }

    void free(vmm_t* vmm)
    {
        ExFreePool(vmm->vcpu_array);
        ExFreePool(vmm);
    }

    uint8_t vmxon_single_core(vmm::vmm_t* vmm)
    {
        int32_t processor_number = KeGetCurrentProcessorNumber();
        vcpu::vcpu_t vcpu = vmm->vcpu_array[processor_number];

        utils::adjust_control_registers();

        if(!utils::supports_vmx_operation())
        {
            log::error("VMX operation is not support on this processor.\n");
            free(vmm);
            return FALSE;
        }

        if(__vmx_on(&vcpu.vmxon_physical) != 0)
        {
            log::error("Failed to put vCPU %d into VMX operation", processor_number);
            free(vmm);
            return FALSE;
        }

        log::success("vCPU %d is now in VMX operation.\n", KeGetCurrentProcessorNumber());
        return TRUE;
    }

    uint8_t vmxon_per_core(vmm::vmm_t* vmm)
    {
        PROCESSOR_NUMBER processor_number;
        GROUP_AFFINITY affinity, old_affinity;
        KIRQL old_irql;

        for(uint32_t vcpu_index = 0; vcpu_index < vmm->vcpu_count; vcpu_index++)
        {
            KeGetProcessorNumberFromIndex(vcpu_index, &processor_number);
            RtlSecureZeroMemory(&affinity, sizeof(GROUP_AFFINITY));
            affinity.Group = processor_number.Group;
            affinity.Mask = (KAFFINITY)1 << processor_number.Number;
            KeSetSystemGroupAffinityThread(&affinity, &old_affinity);

            vmxon_single_core(vmm);

            KeRevertToUserGroupAffinityThread(&old_affinity);
        }

        return TRUE;
    }
}


NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path)
{
    vmm::vmm_t* test_vmm = vmm::alloc();
    if (!test_vmm)
    {
        log::error("Could not allocate VMM.\n");
    }

    vmm::vmxon_per_core(test_vmm);

    log::debug("Test finished.\n");
}
