use dotenv;

use openssl::rsa::{Padding, Rsa};

use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicKeyRequest {
    app_id: String,
    locale: String,
    device_id: String,
    sdk_version: String,
}

impl PublicKeyRequest {
    fn new(email: &str) -> Self {
        PublicKeyRequest {
            app_id: "MazdaApp".to_owned(),
            locale: "en-US".to_owned(),
            device_id: format!(
                "{}{}",
                "ACCT",
                i32::from_str_radix(&sha256::digest(email)[0..8], 16).unwrap()
            ),
            sdk_version: "11.2.0400.001".to_owned(),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicKeyResponseData {
    encryption_algorithm: String,
    key_type: String,
    public_key: String,
    version_prefix: String,
}

#[derive(Deserialize)]
struct PublicKeyResponse {
    data: PublicKeyResponseData,
}

fn encrypt_password(
    password: &str,
    public_key: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // Make an RSA instance from the provided public key
    let rsa = Rsa::public_key_from_der(&base64::decode(public_key)?)?;

    // Allocate a buffer to store the encrypted password
    let mut buf = vec![0; rsa.size() as usize];

    // Use the RSA instance, backed by the public key, to encrypt the provided password
    rsa.public_encrypt(
        &format!(
            "{}:{}",
            password,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs()
        )
        .as_bytes(),
        &mut buf,
        Padding::PKCS1,
    )?;

    // Return the encrypted password as a base64 encoded string
    Ok(base64::encode(&buf))
}

async fn get_public_key(email: &str) -> Result<String, Box<dyn std::error::Error>> {
    // API endpoint
    let url = "https://ptznwbh8.mazda.com/appapi/v1/system/encryptionKey";

    // Query the Mazda API for a public key
    let response = Client::new()
        .get(url)
        .header("User-Agent", "MyMazda/8.3.0 (iPhone Xr; IOS 15.6)")
        .query(&PublicKeyRequest::new(email))
        .send()
        .await?
        .json::<PublicKeyResponse>()
        .await?
        .data;

    // Return the public key
    Ok(response.public_key)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load credentials
    let email = dotenv::var("EMAIL").unwrap();
    let password = dotenv::var("PASSWORD").unwrap();

    // Get a public encryption key from the API
    let public_key = get_public_key(&email).await?;

    // Use the public key to encrypt the password
    let encrypted_password = encrypt_password(&password, &public_key)?;

    // Print the encrypted password
    println!("Encrypted password:: {}", encrypted_password);

    Ok(())
}
