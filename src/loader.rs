use base64::engine::general_purpose;
use base64::Engine;
use bytes::Bytes;
use image::ImageReader;
use std::fs;
use std::io::{Cursor, Read};

pub async fn resolve_image_b64(text: &String) -> Result<String, Box<dyn std::error::Error>> {
    let image_b64_res = if text.starts_with("http://") || text.starts_with("https://") {
        let response = reqwest::get(text).await?;

        // Ensure that the request was successful.
        if !response.status().is_success() {
            println!(
                "Failed to fetch the image. HTTP Status: {}",
                response.status()
            );
            return Err(Box::new(std::io::Error::other("Failed to fetch the image")));
        }

        // Collect the image bytes.
        let img_bytes = response.bytes().await?;

        encode_image_bytes_to_png_base64(img_bytes)
    } else if text.starts_with("data:image/") {
        text.split_once(',')
            .map(|(_, b64_data)| b64_data.to_string())
            .ok_or("No base64 data found.".into())
    } else {
        let mut file = fs::File::open(text)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        encode_image_bytes_to_png_base64(Bytes::from(buffer))
    };
    image_b64_res
}

pub fn encode_image_bytes_to_png_base64(
    image_bytes: Bytes,
) -> Result<String, Box<dyn std::error::Error>> {
    let img = ImageReader::new(std::io::Cursor::new(image_bytes))
        .with_guessed_format()
        .expect("Failed to guess image format")
        .decode()?;
    let mut buffer = Cursor::new(Vec::new());
    img.write_to(&mut buffer, image::ImageFormat::Png)?;
    let encoded = general_purpose::STANDARD.encode(buffer.get_ref());
    Ok(encoded)
}
