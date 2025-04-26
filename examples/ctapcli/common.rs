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

pub fn get_pin() -> Result<String> {
    let pin = rpassword::prompt_password("PIN: ")?;
    println!();
    Ok(pin)
}
