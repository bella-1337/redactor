//! PII Review desktop shell.
//!
//! Starts the bundled engine (`python -I -m pii_review.desktop`: the page,
//! Presidio, and Xberg), shows a splash screen while it loads, then points the
//! window at the page on 127.0.0.1 with this run's token in the URL fragment.
//!
//! The engine reports on its stdout, one JSON object per line (see
//! app/pii_review/desktop.py). Closing its stdin tells it to stop, which also
//! happens if this process dies.
//!
//! The Settings menu in the native menu bar changes settings.env and restarts
//! the engine; the page itself has no settings.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod settings;

use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Deserialize;
use tauri::menu::{CheckMenuItem, IsMenuItem, Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::webview::DownloadEvent;
use tauri::{AppHandle, Manager, RunEvent, Url, WebviewUrl, WebviewWindow, WebviewWindowBuilder, WindowEvent, Wry};

const WINDOW: &str = "main";
const SETTINGS_TEMPLATE: &str = include_str!("../settings.env.template");

const LANGUAGE: &str = "PII_REVIEW_LANGUAGE";
const ANALYZER_URL: &str = "PII_REVIEW_ANALYZER_URL";
/// A Presidio analyzer container on this computer, on the port Presidio's
/// own documentation uses (docker run -p 5002:3000).
const LOCAL_ANALYZER: &str = "http://127.0.0.1:5002";
const DEVICE: &str = "PII_REVIEW_DEVICE";
const ASSIST_URL: &str = "PII_REVIEW_ASSIST_URL";
const ASSIST_MODEL: &str = "PII_REVIEW_ASSIST_MODEL";
const ASSIST_KEY: &str = "PII_REVIEW_ASSIST_KEY";
/// The template's example of a local model: Ollama on this computer.
const OLLAMA_URL: &str = "http://127.0.0.1:11434/v1";
const OLLAMA_MODEL: &str = "qwen3.5:4b";
const LANGUAGES: [(&str, &str); 3] = [("en", "English"), ("de", "German"), ("fr", "French")];
const DEVICES: [(&str, &str); 2] = [("auto", "GPU When Available"), ("cpu", "CPU Only")];

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

/// What the app keeps for the life of the window: enough to restart the engine.
struct Shell {
    paths: Paths,
    window: WebviewWindow,
    splash_url: Url,
    page_port: Arc<AtomicU16>,
    engine: Engine,
    /// Counts engine starts; the watcher of an engine that was restarted
    /// away stays quiet instead of reporting it as stopped.
    generation: AtomicU64,
    /// One restart at a time.
    restarting: Mutex<()>,
    /// The settings file as the running engine read it, to tell whether it
    /// has changed since.
    applied: Mutex<String>,
    menu: SettingsMenu,
}

/// Follow the engine's messages until it is ready, then keep watching for it to exit.
fn watch_engine(app: AppHandle, generation: u64, stdout: impl std::io::Read) {
    let shell = app.state::<Shell>();
    let current = || shell.generation.load(Ordering::SeqCst) == generation;
    let mut ready = false;
    for line in BufReader::new(stdout).lines() {
        let Ok(line) = line else { break };
        if !current() {
            return;
        }
        let Ok(message) = serde_json::from_str::<EngineMessage>(&line) else { continue };
        if let Some(status) = message.status {
            splash(&shell.window, "status", &status);
        } else if let Some(error) = message.error {
            show_error(&shell.window, &shell.splash_url, &error, &shell.paths.log);
            return;
        } else if let (Some(port), Some(token)) = (message.port, message.token) {
            shell.page_port.store(port, Ordering::SeqCst);
            let Ok(mut url) = Url::parse(&format!("http://127.0.0.1:{port}/")) else { return };
            if !token.is_empty() {
                url.set_fragment(Some(&format!("token={token}")));
            }
            ready = true;
            if shell.window.navigate(url).is_err() {
                show_error(&shell.window, &shell.splash_url, "The page could not be opened.", &shell.paths.log);
                return;
            }
        }
    }
    if !current() {
        return;
    }
    shell.page_port.store(0, Ordering::SeqCst);
    let message = if ready {
        "PII Review's engine stopped unexpectedly. Choose Settings > Restart Engine, or restart the app."
    } else {
        "PII Review's engine could not start. Check the settings (Settings > Edit Settings File), then choose Settings > Restart Engine."
    };
    show_error(&shell.window, &shell.splash_url, message, &shell.paths.log);
}

/// Start the engine and follow it in a thread of its own.
fn start_engine(app: &AppHandle) {
    let shell = app.state::<Shell>();
    let generation = shell.generation.load(Ordering::SeqCst);
    match spawn_engine(&shell.paths) {
        Ok(mut child) => {
            if let Ok(mut applied) = shell.applied.lock() {
                *applied = fs::read_to_string(&shell.paths.settings).unwrap_or_default();
            }
            let stdout = child.stdout.take();
            if let Ok(mut slot) = shell.engine.stdin.lock() {
                *slot = child.stdin.take();
            }
            if let Ok(mut slot) = shell.engine.child.lock() {
                *slot = Some(child);
            }
            if let Some(stdout) = stdout {
                let app = app.clone();
                std::thread::spawn(move || watch_engine(app, generation, stdout));
            }
        }
        Err(error) => {
            let message = format!("PII Review's engine could not be started ({error}).");
            show_error(&shell.window, &shell.splash_url, &message, &shell.paths.log);
        }
    }
    refresh_menu(app);
}

/// Stop the engine and start it again with the settings as they are now. The
/// window shows the splash screen meanwhile; the text being reviewed is lost.
fn restart_engine(app: &AppHandle) {
    let app = app.clone();
    std::thread::spawn(move || {
        let shell = app.state::<Shell>();
        let Ok(_one_at_a_time) = shell.restarting.lock() else { return };
        shell.generation.fetch_add(1, Ordering::SeqCst);
        shell.page_port.store(0, Ordering::SeqCst);
        // The splash screen and its spinner at once, with the status in its
        // URL: a status sent by script could reach the old page instead.
        let _ = shell.window.navigate(splash_with_status(&shell.splash_url, "Stopping the engine…"));
        shell.engine.stop();
        splash(&shell.window, "status", "Starting the engine with the new settings…");
        start_engine(&app);
    });
}

// ---------------------------------------------------------------------------
// The Settings menu
// ---------------------------------------------------------------------------

/// The menu items whose ticks and labels follow the settings file.
struct SettingsMenu {
    engine_builtin: CheckMenuItem<Wry>,
    engine_local: CheckMenuItem<Wry>,
    engine_other: CheckMenuItem<Wry>,
    languages: Vec<(&'static str, CheckMenuItem<Wry>)>,
    assist_off: CheckMenuItem<Wry>,
    assist_ollama: CheckMenuItem<Wry>,
    assist_other: CheckMenuItem<Wry>,
    devices: Vec<(&'static str, CheckMenuItem<Wry>)>,
    restart: MenuItem<Wry>,
}

/// The default menu of the platform (with Edit's copy and paste), plus Settings:
///
/// Settings
///   Detection Engine      > Built-in spaCy / Presidio Analyzer on This Computer / Other (in the Settings File)
///   Detection Language    > English / German / French
///   Local Model           > Off / Ollama on This Computer / Other (in the Settings File)
///   Run Language Models   > GPU When Available / CPU Only       (Windows and Linux)
///   Edit Settings File…   Ctrl/Cmd+,
///   Show Engine Log
///   Reset Settings to Defaults
///   Restart Engine        Ctrl/Cmd+Shift+R
fn build_menu(app: &AppHandle) -> tauri::Result<SettingsMenu> {
    let check = |id: &str, text: &str| CheckMenuItem::with_id(app, id, text, true, false, None::<&str>);
    let engine_builtin = check("engine-builtin", "Built-in spaCy")?;
    let engine_local = check("engine-local", "Presidio Analyzer on This Computer (Port 5002)")?;
    // Shows that the settings file names another analyzer; chosen there, not here.
    let engine_other = CheckMenuItem::with_id(app, "engine-other", "Other (in the Settings File)", false, false, None::<&str>)?;
    let languages = LANGUAGES
        .iter()
        .map(|(code, name)| Ok((*code, check(&format!("language-{code}"), name)?)))
        .collect::<tauri::Result<Vec<_>>>()?;
    let assist_off = check("assist-off", "Off")?;
    let assist_ollama = check("assist-ollama", &format!("Ollama on This Computer ({OLLAMA_MODEL})"))?;
    // Shows that the settings file names another model; chosen there, not here.
    let assist_other = CheckMenuItem::with_id(app, "assist-other", "Other (in the Settings File)", false, false, None::<&str>)?;
    let devices = DEVICES
        .iter()
        .map(|(value, name)| Ok((*value, check(&format!("device-{value}"), name)?)))
        .collect::<tauri::Result<Vec<_>>>()?;
    let restart = MenuItem::with_id(app, "engine-restart", "Restart Engine", true, Some("CmdOrCtrl+Shift+R"))?;

    let engine_menu = Submenu::with_items(app, "Detection Engine", true, &[&engine_builtin, &engine_local, &engine_other])?;
    let language_items: Vec<&dyn IsMenuItem<Wry>> = languages.iter().map(|(_, item)| item as &dyn IsMenuItem<Wry>).collect();
    let language_menu = Submenu::with_items(app, "Detection Language", true, &language_items)?;
    let assist_menu = Submenu::with_items(app, "Local Model", true, &[&assist_off, &assist_ollama, &assist_other])?;
    let device_items: Vec<&dyn IsMenuItem<Wry>> = devices.iter().map(|(_, item)| item as &dyn IsMenuItem<Wry>).collect();
    let device_menu = Submenu::with_items(app, "Run Language Models On", true, &device_items)?;
    let edit = MenuItem::with_id(app, "settings-edit", "Edit Settings File…", true, Some("CmdOrCtrl+,"))?;
    let log = MenuItem::with_id(app, "engine-log", "Show Engine Log", true, None::<&str>)?;
    let reset = MenuItem::with_id(app, "settings-reset", "Reset Settings to Defaults", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let separator_2 = PredefinedMenuItem::separator(app)?;

    let mut items: Vec<&dyn IsMenuItem<Wry>> = vec![&engine_menu, &language_menu, &assist_menu];
    // GPU support exists only for NVIDIA GPUs on Windows and Linux x64.
    if cfg!(not(target_os = "macos")) {
        items.push(&device_menu);
    }
    items.extend([&separator as &dyn IsMenuItem<Wry>, &edit, &log, &reset, &separator_2, &restart]);
    let settings_menu = Submenu::with_items(app, "Settings", true, &items)?;

    let menu = Menu::default(app)?;
    let window_menu = menu.items()?.iter().position(|item| {
        item.as_submenu().and_then(|submenu| submenu.text().ok()).as_deref() == Some("Window")
    });
    match window_menu {
        Some(position) => menu.insert(&settings_menu, position)?,
        None => menu.append(&settings_menu)?,
    }
    app.set_menu(menu)?;
    Ok(SettingsMenu { engine_builtin, engine_local, engine_other, languages, assist_off, assist_ollama, assist_other, devices, restart })
}

fn read_settings(paths: &Paths) -> String {
    fs::read_to_string(&paths.settings).unwrap_or_else(|_| SETTINGS_TEMPLATE.to_owned())
}

/// Tick what the settings file says, and say when the engine runs with older settings.
fn refresh_menu(app: &AppHandle) {
    let Some(shell) = app.try_state::<Shell>() else { return };
    let content = read_settings(&shell.paths);
    let menu = &shell.menu;
    let analyzer = settings::get(&content, ANALYZER_URL).map(|value| value.trim_end_matches('/').to_owned()).filter(|value| !value.is_empty());
    let _ = menu.engine_builtin.set_checked(analyzer.is_none());
    let _ = menu.engine_local.set_checked(analyzer.as_deref() == Some(LOCAL_ANALYZER));
    let _ = menu.engine_other.set_checked(analyzer.as_deref().is_some_and(|url| url != LOCAL_ANALYZER));
    let language = settings::get(&content, LANGUAGE).filter(|value| !value.is_empty()).unwrap_or_else(|| "en".into());
    for (code, item) in &menu.languages {
        let _ = item.set_checked(language.eq_ignore_ascii_case(code));
    }
    let url = settings::get(&content, ASSIST_URL).filter(|value| !value.is_empty());
    let model = settings::get(&content, ASSIST_MODEL).filter(|value| !value.is_empty());
    let key = settings::get(&content, ASSIST_KEY).filter(|value| !value.is_empty());
    let ollama = url.as_deref() == Some(OLLAMA_URL) && model.as_deref() == Some(OLLAMA_MODEL) && key.is_none();
    let _ = menu.assist_off.set_checked(url.is_none());
    let _ = menu.assist_ollama.set_checked(ollama);
    let _ = menu.assist_other.set_checked(url.is_some() && !ollama);
    let device = settings::get(&content, DEVICE).filter(|value| !value.is_empty()).unwrap_or_else(|| "auto".into());
    for (value, item) in &menu.devices {
        let _ = item.set_checked(device.eq_ignore_ascii_case(value));
    }
    let changed = shell.applied.lock().map(|applied| *applied != content).unwrap_or(false);
    let _ = menu
        .restart
        .set_text(if changed { "Restart Engine to Apply Changes" } else { "Restart Engine" });
}

/// Set settings in the file; they apply when the engine restarts.
fn change_settings(app: &AppHandle, updates: &[(&str, Option<&str>)]) {
    let shell = app.state::<Shell>();
    let mut content = read_settings(&shell.paths);
    for (key, value) in updates {
        content = settings::set(&content, key, *value);
    }
    if let Err(error) = fs::write(&shell.paths.settings, content) {
        eprintln!("PII Review could not save its settings: {error}");
    }
    refresh_menu(app);
}

/// Open a file in the system's text editor. The path goes to the program as
/// one argument, never through a shell.
fn open_in_editor(path: &Path) {
    #[cfg(target_os = "macos")]
    let child = Command::new("open").arg("-t").arg(path).spawn();
    #[cfg(windows)]
    let child = Command::new("notepad.exe").arg(path).spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let child = Command::new("xdg-open").arg(path).spawn();
    match child {
        // Wait for it in the background, so it leaves no zombie process.
        Ok(mut child) => drop(std::thread::spawn(move || child.wait())),
        Err(error) => eprintln!("PII Review could not open {}: {error}", path.display()),
    }
}

/// Back up the settings file as settings.env.bak and start again from the template.
fn reset_settings(app: &AppHandle) {
    let shell = app.state::<Shell>();
    let backup = shell.paths.settings.with_extension("env.bak");
    if shell.paths.settings.exists() {
        if let Err(error) = fs::rename(&shell.paths.settings, &backup) {
            eprintln!("PII Review could not back up its settings: {error}");
            return;
        }
    }
    if let Err(error) = fs::write(&shell.paths.settings, SETTINGS_TEMPLATE) {
        eprintln!("PII Review could not reset its settings: {error}");
    }
    refresh_menu(app);
}

fn on_menu(app: &AppHandle, id: &str) {
    if let Some(code) = id.strip_prefix("language-") {
        if let Some((code, _)) = LANGUAGES.iter().find(|(each, _)| *each == code) {
            change_settings(app, &[(LANGUAGE, Some(code))]);
        }
        return;
    }
    if let Some(value) = id.strip_prefix("device-") {
        if let Some((value, _)) = DEVICES.iter().find(|(each, _)| *each == value) {
            change_settings(app, &[(DEVICE, Some(value))]);
        }
        return;
    }
    match id {
        "engine-builtin" => change_settings(app, &[(ANALYZER_URL, None)]),
        "engine-local" => change_settings(app, &[(ANALYZER_URL, Some(LOCAL_ANALYZER))]),
        "assist-off" => change_settings(app, &[(ASSIST_URL, None), (ASSIST_MODEL, None), (ASSIST_KEY, None)]),
        "assist-ollama" => change_settings(app, &[(ASSIST_URL, Some(OLLAMA_URL)), (ASSIST_MODEL, Some(OLLAMA_MODEL)), (ASSIST_KEY, None)]),
        "settings-edit" => {
            let shell = app.state::<Shell>();
            if !shell.paths.settings.exists() {
                let _ = fs::write(&shell.paths.settings, SETTINGS_TEMPLATE);
            }
            open_in_editor(&shell.paths.settings);
        }
        "engine-log" => open_in_editor(&app.state::<Shell>().paths.log),
        "settings-reset" => reset_settings(app),
        "engine-restart" => restart_engine(app),
        // A click on a tick that cannot change (Other) puts the ticks back.
        _ => refresh_menu(app),
    }
}

/// Only the splash screen and this run's page may load in the window, plus
/// the page's own blob: URLs (its "Download .txt"). `dev_origin` is where
/// `tauri dev` serves the splash screen (its dev server); built apps have none.
fn allowed_navigation(url: &Url, page_port: &AtomicU16, dev_origin: Option<&Url>) -> bool {
    let port = page_port.load(Ordering::SeqCst);
    let is_page = |url: &Url| {
        port != 0 && url.scheme() == "http" && url.host_str() == Some("127.0.0.1") && url.port() == Some(port)
    };
    if dev_origin.is_some_and(|dev| dev.origin() == url.origin()) {
        return true;
    }
    match (url.scheme(), url.host_str()) {
        ("tauri", Some("localhost")) => true,
        ("http" | "https", Some("tauri.localhost")) => true,
        ("blob", _) => Url::parse(url.path()).is_ok_and(|inner| is_page(&inner)),
        _ => is_page(url),
    }
}

/// The splash screen, saying `status` from the start (it reads ?status=).
fn splash_with_status(splash_url: &Url, status: &str) -> Url {
    let mut url = splash_url.clone();
    url.set_fragment(None);
    url.query_pairs_mut().clear().append_pair("status", status);
    url
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
    // Before the window, so it gets the menu bar on Windows and Linux too.
    let menu = build_menu(&handle)?;

    let navigation_port = page_port.clone();
    let dev_origin = if tauri::is_dev() { handle.config().build.dev_url.clone() } else { None };
    let download_handle = handle.clone();
    let window = WebviewWindowBuilder::new(app, WINDOW, WebviewUrl::App("index.html".into()))
        .title("PII Review")
        // The review shows three panes side by side on a monitor: open the
        // window maximized, at 1440 x 900 when it is restored.
        .inner_size(1440.0, 900.0)
        .min_inner_size(640.0, 480.0)
        .maximized(true)
        .on_navigation(move |url| allowed_navigation(url, &navigation_port, dev_origin.as_ref()))
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
    // The settings file may have been edited elsewhere: update the ticks
    // whenever the window comes back to the front.
    let focus_handle = handle.clone();
    window.on_window_event(move |event| {
        if let WindowEvent::Focused(true) = event {
            refresh_menu(&focus_handle);
        }
    });

    app.manage(Shell {
        paths,
        window,
        splash_url,
        page_port,
        engine: Engine::default(),
        generation: AtomicU64::new(0),
        restarting: Mutex::new(()),
        applied: Mutex::new(String::new()),
        menu,
    });
    start_engine(&handle);
    Ok(())
}

fn main() {
    let app = match tauri::Builder::default()
        .setup(setup)
        .on_menu_event(|app, event| on_menu(app, event.id().as_ref()))
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
            if let Some(shell) = handle.try_state::<Shell>() {
                // The watcher must not report this stop as a failure.
                shell.generation.fetch_add(1, Ordering::SeqCst);
                shell.engine.stop();
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed(url: &str, port: u16) -> bool {
        allowed_navigation(&Url::parse(url).expect("test URL"), &AtomicU16::new(port), None)
    }

    #[test]
    fn tauri_dev_may_load_the_splash_screen_from_its_dev_server() {
        let dev = Url::parse("http://127.0.0.1:1430/").expect("test URL");
        let port = AtomicU16::new(0);
        let allowed = |url: &str| allowed_navigation(&Url::parse(url).expect("test URL"), &port, Some(&dev));
        assert!(allowed("http://127.0.0.1:1430/?status=Stopping"));
        assert!(!allowed("http://127.0.0.1:1431/"));
        assert!(!allowed("https://127.0.0.1:1430/"));
        // Built apps have no dev server.
        assert!(!allowed_navigation(&dev, &port, None));
    }

    #[test]
    fn the_splash_screen_can_open_with_a_status() {
        let splash = Url::parse("tauri://localhost/index.html?error=old#x").expect("test URL");
        assert_eq!(
            splash_with_status(&splash, "Stopping the engine…").as_str(),
            "tauri://localhost/index.html?status=Stopping+the+engine%E2%80%A6"
        );
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
