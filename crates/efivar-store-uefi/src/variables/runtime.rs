//! Relocatable EFI ABI readers. Installation patches the sole index pointer
//! before sealing the copied code; no entry references boot-services state.
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(include_str!("runtime_x86_64.S"));
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(include_str!("runtime_aarch64.S"));

unsafe extern "C" {
    /// First byte of the copied position-independent runtime code blob.
    pub static efivar_store_blob_start: u8;
    /// One past the last byte of the copied runtime code blob.
    pub static efivar_store_blob_end: u8;
    /// The blob slot holding the published index pointer.
    pub static efivar_store_index: u8;
    /// The `GetVariable` entry inside the blob.
    pub static efivar_store_get: u8;
    /// The `GetNextVariableName` entry inside the blob.
    pub static efivar_store_next: u8;
    /// The `SetVariable` entry inside the blob.
    pub static efivar_store_set: u8;
    /// The `QueryVariableInfo` entry inside the blob.
    pub static efivar_store_query: u8;
}
