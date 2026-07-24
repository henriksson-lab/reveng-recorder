//! On-device OCR of screenshots via the built-in **Windows.Media.Ocr** engine.
//!
//! No Tesseract, no model download, no network — the OCR language pack ships with Windows.
//! Input is PNG bytes (what the recorder already saves); output is recognized words with
//! their pixel bounding boxes, plus the reconstructed line/full text.
//!
//! Windows-only; a stub returns an error elsewhere so the workspace still builds cross-platform.

use serde::{Deserialize, Serialize};

/// One recognized word and its bounding box, in **image pixels** (origin = top-left of the PNG).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Word {
    pub text: String,
    pub x: f32,
    pub y: f32,
    pub w: f32,
    pub h: f32,
}

impl Word {
    pub fn center(&self) -> (f32, f32) {
        (self.x + self.w / 2.0, self.y + self.h / 2.0)
    }
}

/// The full OCR result for one screenshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ocr {
    pub words: Vec<Word>,
    /// Text of each recognized line (top-to-bottom, as the engine grouped them).
    pub lines: Vec<String>,
    /// All recognized text (space/newline joined by the engine).
    pub text: String,
    /// Angle the engine thinks the text is skewed by, in degrees (0 if unknown).
    pub text_angle: f64,
}

/// Recognize text in a PNG image (bytes). Windows-only.
pub fn ocr_png(png: &[u8]) -> anyhow::Result<Ocr> {
    #[cfg(windows)]
    {
        imp::ocr_png(png)
    }
    #[cfg(not(windows))]
    {
        let _ = png;
        anyhow::bail!("OCR requires Windows (Windows.Media.Ocr)")
    }
}

#[cfg(windows)]
mod imp {
    use super::{Ocr, Word};
    use anyhow::{Context, Result};
    use windows::core::RuntimeType;
    use windows::Graphics::Imaging::BitmapDecoder;
    use windows::Media::Ocr::OcrEngine;
    use windows::Storage::Streams::{DataWriter, InMemoryRandomAccessStream};
    use windows::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED};
    use windows_future::{AsyncStatus, IAsyncOperation};

    /// Block on a WinRT async operation via its public `Status()`/`GetResults()` methods.
    /// (windows-future's blocking `join()` lives on a private trait, so we poll instead —
    /// the ops complete on WinRT thread-pool threads, no message pump required.)
    fn wait<T: RuntimeType>(op: IAsyncOperation<T>) -> Result<T> {
        loop {
            match op.Status()? {
                AsyncStatus::Completed => return Ok(op.GetResults()?),
                AsyncStatus::Started => std::thread::sleep(std::time::Duration::from_millis(1)),
                other => anyhow::bail!("WinRT async op did not complete: {other:?}"),
            }
        }
    }

    pub fn ocr_png(png: &[u8]) -> Result<Ocr> {
        // WinRT activation needs an initialized apartment (MTA). Harmless if already initialized
        // (S_FALSE / RPC_E_CHANGED_MODE), which we ignore.
        unsafe {
            let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        }

        // Copy the PNG bytes into a WinRT in-memory stream so BitmapDecoder can read them.
        let stream = InMemoryRandomAccessStream::new()?;
        let writer = DataWriter::CreateDataWriter(&stream.GetOutputStreamAt(0)?)?;
        writer.WriteBytes(png)?;
        wait(writer.StoreAsync()?)?;
        wait(writer.FlushAsync()?)?;
        stream.Seek(0)?;

        let decoder = wait(BitmapDecoder::CreateAsync(&stream)?).context("PNG decode failed")?;
        let bitmap = wait(decoder.GetSoftwareBitmapAsync()?)?;

        let engine = OcrEngine::TryCreateFromUserProfileLanguages().context(
            "no OCR engine available — add a Windows OCR language pack \
             (Settings > Time & Language > Language, add a language with the OCR feature)",
        )?;

        let result = wait(engine.RecognizeAsync(&bitmap)?)?;

        let mut words = Vec::new();
        let mut lines = Vec::new();
        for line in result.Lines()? {
            if let Ok(t) = line.Text() {
                lines.push(t.to_string_lossy());
            }
            for word in line.Words()? {
                let r = word.BoundingRect()?;
                words.push(Word {
                    text: word.Text()?.to_string_lossy(),
                    x: r.X,
                    y: r.Y,
                    w: r.Width,
                    h: r.Height,
                });
            }
        }
        let text = result.Text()?.to_string_lossy();
        let text_angle = result.TextAngle().and_then(|a| a.Value()).unwrap_or(0.0);

        Ok(Ocr { words, lines, text, text_angle })
    }
}
