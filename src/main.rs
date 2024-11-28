use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::ptr;
use winapi::um::libloaderapi::{GetModuleFileNameW, GetModuleHandleExW};
use winapi::um::psapi::{EnumProcessModules, GetModuleFileNameExW};
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::shared::minwindef::{DWORD, HMODULE, MAX_PATH};
use winapi::shared::ntdef::NULL;

fn wide_to_string(wide: &[u16]) -> String {
    String::from_utf16_lossy(&wide.iter().take_while(|&c| *c != 0).cloned().collect::<Vec<_>>())
}

fn is_suspicious_path(path: &str) -> bool {
    let lower_path = path.to_ascii_lowercase();
    !(lower_path.starts_with("c:\\windows\\system32") || lower_path.starts_with("c:\\program files"))
}

fn log_suspicious_dll(path: &str, reason: &str) {
    let log_path = "suspicious_dlls.log";
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .expect("Failed to open log file");

    writeln!(file, "Suspicious DLL: {}\nReason: {}", path, reason)
        .expect("Failed to write to log file");
}

fn scan_dlls() {
    unsafe {
        let process = GetCurrentProcess();
        let mut modules: [HMODULE; 1024] = [ptr::null_mut(); 1024];
        let mut cb_needed: DWORD = 0;

        // Enumerate all modules (DLLs) loaded in the process
        if EnumProcessModules(
            process,
            modules.as_mut_ptr(),
            std::mem::size_of_val(&modules) as DWORD,
            &mut cb_needed,
        ) != 0
        {
            let module_count = (cb_needed / std::mem::size_of::<HMODULE>() as DWORD) as usize;
            for i in 0..module_count {
                let mut buffer: [u16; MAX_PATH] = [0; MAX_PATH];
                if GetModuleFileNameW(
                    modules[i],
                    buffer.as_mut_ptr(),
                    MAX_PATH as DWORD,
                ) > 0
                {
                    let dll_path = wide_to_string(&buffer);
                    println!("Found DLL: {}", dll_path);

                    // Check if the DLL is suspicious
                    if is_suspicious_path(&dll_path) {
                        println!("Suspicious DLL: {}", dll_path);
                        log_suspicious_dll(&dll_path, "Loaded from an unusual directory");
                    }
                }
            }
        } else {
            eprintln!("Failed to enumerate process modules.");
        }
    }
}

fn main() {
    println!("Scanning loaded DLLs...");
    scan_dlls();
    println!("Scan complete. Results logged to 'suspicious_dlls.log'.");
}
