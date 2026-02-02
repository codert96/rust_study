use axum::extract::multipart::Field;
use std::env;
use std::io::{Error, ErrorKind};
use std::ops::Deref;
use std::path::Path;
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::{AsyncWriteExt, BufWriter};

struct Inner(Box<Path>);

#[derive(Clone)]
pub struct TempFile(Arc<Inner>);
impl Drop for Inner {
    fn drop(&mut self) {
        let path = self.0.clone();
        tokio::task::spawn(async move { tokio::fs::remove_file(path).await });
    }
}
impl Deref for TempFile {
    type Target = Path;
    fn deref(&self) -> &Self::Target {
        &self.0.0
    }
}
impl TempFile {
    pub fn new() -> Self {
        Self::with_suffix(".tmp")
    }

    pub fn with_suffix(suffix: &str) -> Self {
        let mut tmp_file = env::temp_dir();
        tmp_file.push(uuid::Uuid::new_v4().to_string());
        tmp_file.add_extension(suffix);
        Self(Arc::new(Inner(tmp_file.into_boxed_path())))
    }

    pub async fn open(&self) -> tokio::io::Result<File> {
        File::create(self.deref()).await
    }
}
impl Default for TempFile {
    fn default() -> Self {
        Self::new()
    }
}

pub trait AsTempFile {
    fn as_temp_file(&mut self) -> impl Future<Output = Result<TempFile, Error>>;
}

impl AsTempFile for Field<'_> {
    async fn as_temp_file(&mut self) -> Result<TempFile, Error> {
        let file_name = self
            .file_name()
            .ok_or_else(|| Error::new(ErrorKind::InvalidFilename, "缺少文件名！"))?;
        let multipart_temp_file = TempFile::with_suffix(file_name);
        let mut temp_file = multipart_temp_file.open().await?;
        async move {
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
        Ok(multipart_temp_file)
    }
}
