//! PII Review desktop shell.
//!
//! Starts the bundled engine (`python -I -m pii_review.desktop`: the page,
//! Presidio, and Xberg), shows a splash screen while it loads, then points the
//! window at the page on 127.0.0.1 with this run's token in the URL fragment.
//!
//! The engine reports on its stdout, one JSON object per line (see
//! app/pii_review/desktop.py). Closing its stdin tells it to stop, which also
//! happens if this process dies.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Deserialize;
use tauri::webview::DownloadEvent;
use tauri::{AppHandle, Manager, RunEvent, Url, WebviewUrl, WebviewWindow, WebviewWindowBuilder};

const WINDOW: &str = "main";
const SETTINGS_TEMPLATE: &str = include_str!("../settings.env.template");

/// One line from the engine. Exactly one field is set.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EngineMessage {
    status: Option<String>,
    error: Option<String>,
    port: Option<u16>,
    token: Option<String>,
}

/// The engine process and the pipe whose closing stops it.
#[derive(Default)]
struct Engine {
    child: Mutex<Option<Child>>,
    stdin: Mutex<Option<ChildStdin>>,
}

impl Engine {
    fn stop(&self) {
        // Closing stdin asks the engine to stop Xberg and exit.
        if let Ok(mut stdin) = self.stdin.lock() {
            stdin.take();
        }
        let Ok(mut guard) = self.child.lock() else { return };
        let Some(mut child) = guard.take() else { return };
        let deadline = Instant::now() + Duration::from_secs(8);
        while Instant::now() < deadline {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => std::thread::sleep(Duration::from_millis(100)),
                Err(_) => break,
            }
        }
        let _ = child.kill();
        let _ = child.wait();
    }
}

struct Paths {
    resources: PathBuf,
    interpreter: PathBuf,
    settings: PathBuf,
    log: PathBuf,
    /// Where the engine downloads its GPU pack on a computer with an NVIDIA GPU.
    gpu: PathBuf,
}

fn paths(app: &AppHandle) -> tauri::Result<Paths> {
    let resources = app.path().resource_dir()?.join("resources");
    let interpreter = if cfg!(windows) {
        resources.join("python").join("python.exe")
    } else {
        resources.join("python").join("bin").join("python3.12")
    };
    let config_dir = app.path().app_config_dir()?;
    let log_dir = app.path().app_log_dir()?;
    fs::create_dir_all(&config_dir)?;
    fs::create_dir_all(&log_dir)?;
    Ok(Paths {
        resources,
        interpreter,
        settings: config_dir.join("settings.env"),
        log: log_dir.join("engine.log"),
        gpu: app.path().app_local_data_dir()?.join("gpu"),
    })
}

fn spawn_engine(paths: &Paths) -> std::io::Result<Child> {
    if !paths.settings.exists() {
        fs::write(&paths.settings, SETTINGS_TEMPLATE)?;
    }
    // The engine logs no content (see desktop.py); a new log each run.
    let log = File::create(&paths.log)?;
    let mut command = Command::new(&paths.interpreter);
    command
        .arg("-I")
        .args(["-m", "pii_review.desktop", "--resources"])
        .arg(&paths.resources)
        .arg("--settings")
        .arg(&paths.settings)
        .arg("--gpu-dir")
        .arg(&paths.gpu)
        .env_remove("PYTHONHOME")
        .env_remove("PYTHONPATH")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::from(log));
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    command.spawn()
}

/// Run a splash-screen function with a JSON-encoded string argument.
fn splash(window: &WebviewWindow, function: &str, message: &str) {
    let argument = serde_json::to_string(message).unwrap_or_else(|_| "\"\"".to_owned());
    let script = format!(
        "window.piiReviewSplash ? window.piiReviewSplash.{function}({argument}) \
         : (window.piiReviewPending = [\"{function}\", {argument}]);"
    );
    let _ = window.eval(script);
}

fn show_error(window: &WebviewWindow, splash_url: &Url, message: &str, log: &Path) {
    let text = format!("{message}\n\nLog: {}", log.display());
    let mut url = splash_url.clone();
    url.set_fragment(None);
    url.query_pairs_mut().clear().append_pair("error", &text);
    let _ = window.navigate(url);
}

/// Follow the engine's messages until it is ready, then keep watching for it to exit.
fn watch_engine(window: WebviewWindow, stdout: impl std::io::Read, page_port: Arc<AtomicU16>, splash_url: Url, log: PathBuf) {
    let mut ready = false;
    for line in BufReader::new(stdout).lines() {
        let Ok(line) = line else { break };
        let Ok(message) = serde_json::from_str::<EngineMessage>(&line) else { continue };
        if let Some(status) = message.status {
            splash(&window, "status", &status);
        } else if let Some(error) = message.error {
            show_error(&window, &splash_url, &error, &log);
            return;
        } else if let (Some(port), Some(token)) = (message.port, message.token) {
            page_port.store(port, Ordering::SeqCst);
            let Ok(mut url) = Url::parse(&format!("http://127.0.0.1:{port}/")) else { return };
            if !token.is_empty() {
                url.set_fragment(Some(&format!("token={token}")));
            }
            ready = true;
            if window.navigate(url).is_err() {
                show_error(&window, &splash_url, "The page could not be opened.", &log);
                return;
            }
        }
    }
    page_port.store(0, Ordering::SeqCst);
    let message = if ready {
        "PII Review's engine stopped unexpectedly. Restart the app."
    } else {
        "PII Review's engine could not start."
    };
    show_error(&window, &splash_url, message, &log);
}

/// Only the splash screen and this run's page may load in the window, plus
/// the page's own blob: URLs (its "Download .txt").
fn allowed_navigation(url: &Url, page_port: &AtomicU16) -> bool {
    let port = page_port.load(Ordering::SeqCst);
    let is_page = |url: &Url| {
        port != 0 && url.scheme() == "http" && url.host_str() == Some("127.0.0.1") && url.port() == Some(port)
    };
    match (url.scheme(), url.host_str()) {
        ("tauri", Some("localhost")) => true,
        ("http" | "https", Some("tauri.localhost")) => true,
        ("blob", _) => Url::parse(url.path()).is_ok_and(|inner| is_page(&inner)),
        _ => is_page(url),
    }
}

/// Save a download (the masked .txt) in the Downloads folder without overwriting.
fn download_destination(app: &AppHandle, suggested: &Path) -> Option<PathBuf> {
    let folder = app.path().download_dir().ok()?;
    let name = suggested
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("masked.txt");
    let (stem, extension) = match name.rsplit_once('.') {
        Some((stem, extension)) if !stem.is_empty() => (stem.to_owned(), format!(".{extension}")),
        _ => (name.to_owned(), String::new()),
    };
    let mut candidate = folder.join(name);
    let mut counter = 1u32;
    while candidate.exists() && counter < 1000 {
        candidate = folder.join(format!("{stem} ({counter}){extension}"));
        counter += 1;
    }
    Some(candidate)
}

fn setup(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    let handle = app.handle().clone();
    let paths = paths(&handle)?;
    let page_port = Arc::new(AtomicU16::new(0));

    let navigation_port = page_port.clone();
    let download_handle = handle.clone();
    let window = WebviewWindowBuilder::new(app, WINDOW, WebviewUrl::App("index.html".into()))
        .title("PII Review")
        .inner_size(1100.0, 860.0)
        .min_inner_size(640.0, 480.0)
        .on_navigation(move |url| allowed_navigation(url, &navigation_port))
        .on_download(move |_webview, event| match event {
            DownloadEvent::Requested { destination, .. } => {
                match download_destination(&download_handle, destination) {
                    Some(path) => {
                        *destination = path;
                        true
                    }
                    None => false,
                }
            }
            _ => true,
        })
        .build()?;
    let splash_url = window.url()?;

    let engine = Engine::default();
    match spawn_engine(&paths) {
        Ok(mut child) => {
            let stdout = child.stdout.take();
            if let Ok(mut slot) = engine.stdin.lock() {
                *slot = child.stdin.take();
            }
            if let Ok(mut slot) = engine.child.lock() {
                *slot = Some(child);
            }
            if let Some(stdout) = stdout {
                let log = paths.log.clone();
                std::thread::spawn(move || watch_engine(window, stdout, page_port, splash_url, log));
            }
        }
        Err(error) => {
            let message = format!("PII Review's engine could not be started ({error}).");
            show_error(&window, &splash_url, &message, &paths.log);
        }
    }
    app.manage(engine);
    Ok(())
}

fn main() {
    let app = match tauri::Builder::default()
        .setup(setup)
        .build(tauri::generate_context!())
    {
        Ok(app) => app,
        Err(error) => {
            eprintln!("PII Review could not start: {error}");
            std::process::exit(1);
        }
    };
    app.run(|handle, event| {
        if let RunEvent::Exit = event {
            if let Some(engine) = handle.try_state::<Engine>() {
                engine.stop();
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed(url: &str, port: u16) -> bool {
        allowed_navigation(&Url::parse(url).expect("test URL"), &AtomicU16::new(port))
    }

    #[test]
    fn navigation_is_limited_to_the_app_and_this_runs_page() {
        assert!(allowed("tauri://localhost/index.html?error=x", 0));
        assert!(allowed("http://tauri.localhost/index.html", 0));
        assert!(allowed("http://127.0.0.1:5000/#token=abc", 5000));
        assert!(allowed("blob:http://127.0.0.1:5000/2f1c-11", 5000));
        assert!(!allowed("http://127.0.0.1:5000/", 0));
        assert!(!allowed("http://127.0.0.1:5001/", 5000));
        assert!(!allowed("http://localhost:5000/", 5000));
        assert!(!allowed("https://example.com/", 5000));
        assert!(!allowed("blob:https://example.com/2f1c-11", 5000));
        assert!(!allowed("file:///etc/passwd", 5000));
    }

    #[test]
    fn engine_messages_reject_unknown_fields() {
        assert!(serde_json::from_str::<EngineMessage>(r#"{"status":"x"}"#).is_ok());
        assert!(serde_json::from_str::<EngineMessage>(r#"{"port":1,"token":"t"}"#).is_ok());
        assert!(serde_json::from_str::<EngineMessage>(r#"{"navigate":"https://example.com"}"#).is_err());
    }
}
