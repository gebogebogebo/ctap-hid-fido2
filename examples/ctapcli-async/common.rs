use anyhow::Result;
use tokio::io::AsyncBufReadExt as _;

pub async fn get_input() -> Result<String> {
    let mut word = String::new();
    let stdin = tokio::io::stdin();
    let mut reader = tokio::io::BufReader::new(stdin);
    reader.read_line(&mut word).await?;
    Ok(word.trim().to_string())
}

pub async fn get_input_with_message(message: &str) -> Result<String> {
    println!("{}", message);
    let input = get_input().await?;
    println!();
    Ok(input)
}

pub async fn get_pin() -> Result<String> {
    tokio::task::spawn_blocking(||{
        let pin = rpassword::prompt_password("PIN: ")?;
        println!();
        Ok(pin)
    }).await.map_err(anyhow::Error::msg)?
}
