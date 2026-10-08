//! Relocatable EFI ABI readers. Installation patches the sole index pointer
//! before sealing the copied code; no entry references boot-services state.
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(include_str!("runtime_x86_64.S"));
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(include_str!("runtime_aarch64.S"));

unsafe extern "C" {
    pub static efivar_store_blob_start: u8;
    pub static efivar_store_blob_end: u8;
    pub static efivar_store_index: u8;
    pub static efivar_store_get: u8;
    pub static efivar_store_next: u8;
    pub static efivar_store_set: u8;
    pub static efivar_store_query: u8;
}
