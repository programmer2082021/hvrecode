#include "hypervisor.h"

static uint64_t count = 0;

void log_success(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vDbgPrintExWithPrefix("[SUCCESS] ", DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, fmt, args);
    va_end(args);

    count++;
}

void log_debug(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vDbgPrintExWithPrefix("[DEBUG] ", DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, fmt, args);
    va_end(args);

    count++;
}

void log_error(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vDbgPrintExWithPrefix("[ERROR] ", DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, fmt, args);
    va_end(args);

    count++;
}


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

void adjust_control_registers(void)
{
    CR4 cr4 = { 0 };
    CR0 cr0 = { 0 };
    union __cr_fixed_t cr_fixed;

    cr_fixed.all = __readmsr(IA32_VMX_CR0_FIXED0);
    cr0.Flags = __readcr0();
    cr0.Flags |= cr_fixed.split.low;
    cr_fixed.all = __readmsr(IA32_VMX_CR0_FIXED1);
    cr0.Flags &= cr_fixed.split.low;
    __writecr0(cr0.Flags);

    cr_fixed.all = __readmsr(IA32_VMX_CR4_FIXED0);
    cr4.Flags = __readcr4();
    cr4.Flags |= cr_fixed.split.low;
    cr_fixed.all = __readmsr(IA32_VMX_CR4_FIXED1);
    cr4.Flags &= cr_fixed.split.low;
    __writecr4(cr4.Flags);
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
    CR4 cr4 = { 0 };
    IA32_FEATURE_CONTROL_REGISTER feature_control = { 0 };

    cr4.Flags = __readcr4();
    cr4.VmxEnable = 1;

    __writecr4(cr4.Flags);
    feature_control.Flags = __readmsr(IA32_FEATURE_CONTROL);

    if (feature_control.LockBit == 0)
    {
        feature_control.EnableVmxOutsideSmx = 1;
        feature_control.LockBit = 1;

        __writemsr(IA32_FEATURE_CONTROL, feature_control.Flags);
        return TRUE;
    }
    return FALSE;
}

void disable_vmx_operation(void)
{
    CR4 cr4 = { 0 };
    IA32_FEATURE_CONTROL_REGISTER feature_control = { 0 };

    cr4.Flags = __readcr4();
    cr4.VmxEnable = 0;

    __writecr4(cr4.Flags);
    feature_control.Flags = __readmsr(IA32_FEATURE_CONTROL);


    feature_control.EnableVmxOutsideSmx = 0;
    feature_control.LockBit = 0;

    __writemsr(IA32_FEATURE_CONTROL, feature_control.Flags);
}



BOOLEAN alloc_vmcs(vcpu_t* vcpu)
{
    IA32_VMX_BASIC_REGISTER vmx_basic = { 0 };
    PHYSICAL_ADDRESS physical_max;
    vmx_basic.Flags = __readmsr(IA32_VMX_BASIC);
    physical_max.QuadPart = ~0ULL;

    vmx_basic.Flags = __readmsr(IA32_VMX_BASIC);
    physical_max.QuadPart = ~0ULL;

    vcpu->vmcs = (vmcs_t*)MmAllocateContiguousMemory(PAGE_SIZE, physical_max);
    if (!vcpu->vmcs)
    {
        log_error("Failed to allocate VMCS for vCPU %d.\n", KeGetCurrentProcessorNumber());
        return FALSE;
    }

    vcpu->vmcs_physical = MmGetPhysicalAddress(vcpu->vmcs).QuadPart;
    RtlSecureZeroMemory(vcpu->vmcs, PAGE_SIZE);
    
    vcpu->vmcs->header.all = vmx_basic.VmcsRevisionId;
    vcpu->vmcs->header.bits.shadow_vmcs_indicator = 0;

    return TRUE;
}