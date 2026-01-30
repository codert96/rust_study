use mime_guess::mime;

pub fn mime_type(filename: &str) -> String {
    filename
        .rsplit_once(".")
        .and_then(|(_, ext)| mime_guess::from_ext(ext).first())
        .unwrap_or(mime::APPLICATION_OCTET_STREAM)
        .to_string()
}
