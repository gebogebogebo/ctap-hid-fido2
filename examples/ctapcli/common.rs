use anyhow::Result;

pub fn get_input() -> Result<String> {
    let mut word = String::new();
    std::io::stdin().read_line(&mut word)?;
    Ok(word.trim().to_string())
}

pub fn get_input_with_message(message: &str) -> Result<String> {
    println!("{}", message);
    let input = get_input()?;
    println!();
    Ok(input)
}

/// Read a secret line such as a PIN.
/// When stdin is a terminal the input is not echoed. When stdin is piped,
/// it is read from stdin as before, so scripts that pipe the value keep working.
pub fn get_secret_input() -> Result<String> {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        let secret = rpassword::read_password()?;
        Ok(secret.trim().to_string())
    } else {
        get_input()
    }
}

pub fn get_pin() -> Result<String> {
    let pin = rpassword::prompt_password("PIN: ")?;
    println!();
    Ok(pin)
}

/// Escape control characters (C0, DEL and C1, e.g. ESC / CSI / OSC) in a
/// device-returned string so it cannot inject terminal escape sequences when
/// printed. Other characters, including non-ASCII text, are kept as-is.
pub fn escape_control_chars(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control() {
                c.escape_default().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}
