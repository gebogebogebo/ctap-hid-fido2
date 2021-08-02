
use rpassword;

pub fn get_input() -> String {
    let mut word = String::new();
    std::io::stdin().read_line(&mut word).ok();
    return word.trim().to_string();
}

pub fn get_pin() -> String {
    let pin = rpassword::prompt_password_stdout("PIN: ").unwrap();
    pin
    //println!("Your password is {}", pass);
}
