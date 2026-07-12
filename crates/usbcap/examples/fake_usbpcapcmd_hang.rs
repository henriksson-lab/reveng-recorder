//! A stand-in for `USBPcapCMD.exe` in *enumeration* mode that prints a device tree and
//! then blocks (as some builds do at the selection prompt), to exercise the list_devices
//! watchdog timeout. Set `USBPCAPCMD` to this binary and run `reveng-rec devices`.
use std::io::Write;

fn main() {
    let mut out = std::io::stdout();
    let _ = writeln!(out, "Following filter control devices are available:");
    let _ = writeln!(out, "1 \\\\.\\USBPcap1");
    let _ = writeln!(out, "  [Port 5] USB Composite Device VID_1234&PID_ABCD : \"Acme Widget\"");
    let _ = out.flush();
    // Block "forever" (well past the 5s watchdog).
    std::thread::sleep(std::time::Duration::from_secs(120));
}
