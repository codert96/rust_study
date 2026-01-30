use axum::extract::multipart::Field;
use std::io::{Error, ErrorKind};
use tempfile::NamedTempFile;
use tokio::fs::File;
use tokio::io::{AsyncWriteExt, BufWriter};

pub type MultipartTempFile = NamedTempFile;
pub trait AsTempFile {
    fn as_temp_file(&mut self) -> impl Future<Output = Result<MultipartTempFile, Error>>;
}

impl AsTempFile for Field<'_> {
    async fn as_temp_file(&mut self) -> Result<MultipartTempFile, Error> {
        let file_name = self
            .file_name()
            .ok_or_else(|| Error::new(ErrorKind::InvalidFilename, "缺少文件名！"))?;
        let named_temp_file = NamedTempFile::with_suffix(file_name)?;
        let temp_file = named_temp_file.reopen()?;
        async move {
            let mut temp_file = File::from_std(temp_file);
            let mut buf_writer = BufWriter::new(&mut temp_file);
            while let Some(chunk) = self
                .chunk()
                .await
                .map_err(|e| Error::new(ErrorKind::BrokenPipe, e))?
            {
                buf_writer.write_all(&chunk).await?;
            }
            buf_writer.flush().await
        }
        .await?;
        Ok(named_temp_file)
    }
}
