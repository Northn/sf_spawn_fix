use winapi::um::libloaderapi::GetModuleHandleA;
use winapi::um::memoryapi::VirtualProtect;
use winapi::shared::minwindef::{LPVOID, BOOL, DWORD};
use winapi::um::winnt::{PAGE_EXECUTE_READWRITE, LPCSTR};

static mut HOOK: Option<Box<rtdhook_rs::CallHook>> = None;

#[allow(non_snake_case)]
unsafe extern "fastcall" fn CScriptThread__SetCondResult(ecx: usize, local_player: usize, _a3: bool) {
    let ret: bool = *(local_player as *mut usize) != 0    // m_pPed
        && *((local_player + 0x141) as *mut BOOL) != 0    // m_bClearedToSpawn
        && *((local_player + 0x17B) as *mut BOOL) != 0;   // m_bHasSpawnInfo
    std::mem::transmute::<usize, extern "fastcall" fn(usize, usize, bool)>(HOOK.as_mut().unwrap().get_function_ptr())(ecx, local_player, ret);
}

pub fn init() {
    let handle = unsafe { GetModuleHandleA("SAMPFUNCS.asi".as_ptr() as LPCSTR) } as usize;
    if handle == 0 { panic!("SAMPFUNCS not detected"); }
    
    let trampoline: Box<[u8]> = Box::new([0x8B, 0xD0, 0xE9, 0x0, 0x0, 0x0, 0x0]);
    unsafe { *((trampoline.as_ptr() as usize + 3) as *mut usize) = (CScriptThread__SetCondResult as usize).wrapping_sub(trampoline.as_ptr() as usize + 2).wrapping_sub(5usize); }
    let trampoline = Box::leak(trampoline);

    let mut old_protection: DWORD = PAGE_EXECUTE_READWRITE;

    unsafe {
        VirtualProtect(trampoline.as_mut_ptr() as LPVOID, 2 + 5, PAGE_EXECUTE_READWRITE, &mut old_protection);

        HOOK = Some(Box::new(rtdhook_rs::CallHook::new(handle + 0x866F8, trampoline.as_ptr() as usize)));
        HOOK.as_mut().unwrap().install();
    }
}
