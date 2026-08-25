use base64::Engine;
use base64::engine::general_purpose;
use bytes::Bytes;
use image::ImageReader;
use image::imageops::FilterType;
use std::fs;
use std::io::{Cursor, Read};

const THUMBNAIL_MAX_DIM: u32 = 512;

/// Resolve `text` (URL, data URI, or file path) into a PNG base64 string.
///
/// If `thumbnail_512px` is true, the image is downscaled to fit within a
/// 512x512 bounding box (preserving aspect ratio, never upscaling).
pub async fn resolve_image_b64(
    text: &str,
    thumbnail_512px: bool,
) -> Result<(String, (u32, u32)), Box<dyn std::error::Error>> {
    if text.starts_with("http://") || text.starts_with("https://") {
        let response = reqwest::get(text).await?;

        // Ensure that the request was successful.
        if !response.status().is_success() {
            return Err(Box::new(std::io::Error::other(format!(
                "Failed to fetch the image. HTTP Status: {}",
                response.status()
            ))));
        }

        let img_bytes = response.bytes().await?;
        encode_image_bytes_to_png_base64(img_bytes, thumbnail_512px)
    } else if text.starts_with("data:image/") {
        let b64_data = text
            .split_once(',')
            .map(|(_, b64)| b64)
            .ok_or("No base64 data found.")?;

        // Decode the embedded base64, resize, then re-encode.
        let raw = general_purpose::STANDARD.decode(b64_data)?;
        encode_image_bytes_to_png_base64(Bytes::from(raw), thumbnail_512px)
    } else {
        let mut file = fs::File::open(text)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        encode_image_bytes_to_png_base64(Bytes::from(buffer), thumbnail_512px)
    }
}

pub fn encode_data_uri_to_png_base64(
    data_uri: &str,
    thumbnail_512px: bool,
) -> Result<(String, (u32, u32)), Box<dyn std::error::Error>> {
    if data_uri.starts_with("data:image/") {
        let b64_data = data_uri
            .split_once(',')
            .map(|(_, b64)| b64)
            .ok_or("No base64 data found.")?;

        // Decode the embedded base64, resize, then re-encode.
        let raw = general_purpose::STANDARD.decode(b64_data)?;
        encode_image_bytes_to_png_base64(Bytes::from(raw), thumbnail_512px)
    } else {
        Err(Box::new(std::io::Error::other("Not a valid data URI.")))
    }
}

/// Decode arbitrary image bytes and re-encode as PNG base64.
///
/// If `thumbnail_512px` is true, downscale to fit within 512x512 first.
pub fn encode_image_bytes_to_png_base64(
    image_bytes: Bytes,
    thumbnail_512px: bool,
) -> Result<(String, (u32, u32)), Box<dyn std::error::Error>> {
    let mut img = ImageReader::new(Cursor::new(image_bytes))
        .with_guessed_format()?
        .decode()?;

    if thumbnail_512px && (img.width() > THUMBNAIL_MAX_DIM || img.height() > THUMBNAIL_MAX_DIM) {
        img = img.resize(THUMBNAIL_MAX_DIM, THUMBNAIL_MAX_DIM, FilterType::Lanczos3);
    }
    let dim = (img.width(), img.height());

    let mut buffer = Cursor::new(Vec::new());
    img.write_to(&mut buffer, image::ImageFormat::Png)?;
    Ok((general_purpose::STANDARD.encode(buffer.get_ref()), dim))
}
