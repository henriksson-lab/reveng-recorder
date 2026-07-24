//! Drive a control in a window via UI Automation — for automated RE data collection (set an
//! app to precise, known values while recording the wire).
//!
//! Usage:
//!   uia-set <window-substr> <control-name-substr> range  <value>
//!   uia-set <window-substr> <control-name-substr> toggle <on|off>
//!   uia-set <window-substr> <control-name-substr> invoke
//!
//! Example: uia-set "My App" "Exposure Time" range 40

use anyhow::{bail, Result};

fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.len() < 3 {
        bail!("usage: uia-set <window> <control-name> range <v> | toggle <on|off> | invoke");
    }
    let (win, name, action) = (&a[0], &a[1], a[2].as_str());
    match action {
        "range" => {
            let v: f64 = a.get(3).context_val()?;
            match reveng_winui::set_range(win, name, v)? {
                Some(actual) => println!("range {name:?} := {v} -> actual {actual}"),
                None => bail!("no Slider/Spinner named {name:?} in a {win:?} window"),
            }
        }
        "toggle" => {
            let on = matches!(a.get(3).map(|s| s.as_str()), Some("on" | "1" | "true"));
            match reveng_winui::set_toggle(win, name, on)? {
                Some(state) => println!("toggle {name:?} := {on} -> now {state}"),
                None => bail!("no CheckBox/toggle named {name:?} in a {win:?} window"),
            }
        }
        "invoke" => {
            if reveng_winui::invoke(win, name)? {
                println!("invoked {name:?}");
            } else {
                bail!("no invokable control named {name:?} in a {win:?} window");
            }
        }
        _ => bail!("action must be range | toggle | invoke"),
    }
    Ok(())
}

trait ParseArg {
    fn context_val(self) -> Result<f64>;
}
impl ParseArg for Option<&String> {
    fn context_val(self) -> Result<f64> {
        match self {
            Some(s) => Ok(s.parse()?),
            None => bail!("range needs a numeric value"),
        }
    }
}
