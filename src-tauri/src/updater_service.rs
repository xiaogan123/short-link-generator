//! Bounded download before an exclusive, verified installation. No account
//! credential is read here. Updater 2.14 verifies again inside `Update::install`.
use super::{json, lock_backend, AppState, Duration, Value};
use futures_util::StreamExt;
use reqwest::{header, redirect, Client, Url};
use std::sync::Mutex as StdMutex;
use tauri::{Emitter, Manager};
use tauri_plugin_updater::{Update, Updater, UpdaterExt};
use tokio::sync::{watch, Mutex, MutexGuard};

#[derive(Clone, Copy)]
struct DownloadPolicy {
    total: Duration,
    idle: Duration,
    max_bytes: usize,
}
const POLICY: DownloadPolicy = DownloadPolicy {
    total: Duration::from_secs(600),
    idle: Duration::from_secs(30),
    max_bytes: 256 * 1024 * 1024,
};
const MANIFEST_POLICY: DownloadPolicy = DownloadPolicy {
    total: Duration::from_secs(30),
    idle: Duration::from_secs(10),
    max_bytes: 1024 * 1024,
};
const CANCELLED: &str = "更新下载已取消，可以稍后重试";
const DOWNLOAD_ERROR: &str = "更新请求失败，请检查网络后重试";

struct Channel {
    updater: Updater,
    endpoint: Url,
}

#[derive(Default)]
pub(super) struct Service {
    gate: Mutex<()>,
    active: StdMutex<Option<Active>>,
}
struct Active {
    cancel: watch::Sender<bool>,
    installing: bool,
}
struct Attempt<'a> {
    service: &'a Service,
    _gate: MutexGuard<'a, ()>,
    cancelled: watch::Receiver<bool>,
}
impl Service {
    fn start(&self) -> Result<Attempt<'_>, String> {
        let guard = self
            .gate
            .try_lock()
            .map_err(|_| "更新操作仍在进行，无需重复点击".to_string())?;
        let (cancel, cancelled) = watch::channel(false);
        *self.active.lock().map_err(|_| "更新状态不可用")? = Some(Active {
            cancel,
            installing: false,
        });
        Ok(Attempt {
            service: self,
            _gate: guard,
            cancelled,
        })
    }
    pub(super) fn cancel(&self) -> Result<Value, String> {
        let active = self.active.lock().map_err(|_| "更新状态不可用")?;
        if let Some(active) = active.as_ref() {
            if active.installing {
                return Err("安装已开始，请等待完成，不能在此阶段取消".into());
            }
            let _ = active.cancel.send(true);
        }
        Ok(json!({"status":"cancel_requested","message":"已请求取消更新下载"}))
    }
}
impl Attempt<'_> {
    async fn downloading<T>(
        &mut self,
        future: impl std::future::Future<Output = Result<T, String>>,
    ) -> Result<T, String> {
        if *self.cancelled.borrow() {
            return Err(CANCELLED.into());
        }
        tokio::select! {
            biased;
            _ = self.cancelled.changed() => Err(CANCELLED.into()),
            result = future => result,
        }
    }
    fn begin_install(&self) -> Result<(), String> {
        // Atomic relative to cancel(): after this transition cancellation cannot
        // interrupt filesystem installation, including a second signature check.
        let mut active = self.service.active.lock().map_err(|_| "更新状态不可用")?;
        let active = active.as_mut().ok_or("更新状态已结束")?;
        if *active.cancel.borrow() {
            return Err(CANCELLED.into());
        }
        active.installing = true;
        Ok(())
    }
}
impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        if let Ok(mut active) = self.service.active.lock() {
            *active = None;
        }
    }
}

fn updater(app: &tauri::AppHandle) -> Result<Option<Channel>, String> {
    let (Some(key), Some(endpoint)) = (
        option_env!("SLG_UPDATER_PUBLIC_KEY"),
        option_env!("SLG_UPDATER_ENDPOINT"),
    ) else {
        return Ok(None);
    };
    if key.is_empty() {
        return Ok(None);
    }
    let endpoint: Url = endpoint.parse().map_err(|_| "更新地址配置无效")?;
    require_https(&endpoint)?;
    let endpoint = manifest_endpoint(&endpoint, &app.package_info().version.to_string())?;
    let updater = app
        .updater_builder()
        .endpoints(vec![endpoint.clone()])
        .map_err(|_| "更新通道配置无效")?
        .timeout(Duration::from_secs(30))
        .configure_client(|client| client.https_only(true))
        .build()
        .map_err(|_| "更新服务不可用")?;
    Ok(Some(Channel { updater, endpoint }))
}

fn manifest_endpoint(endpoint: &Url, version: &str) -> Result<Url, String> {
    use tauri::utils::{config::BundleType, platform::bundle_type};
    // These are the endpoint substitutions of tauri-plugin-updater 2.14.1.
    // Platform/installer selection from the response remains in restore_update.
    let target = match std::env::consts::OS {
        "macos" => "darwin",
        "windows" => "windows",
        "linux" => "linux",
        _ => return Err("当前系统不支持更新".into()),
    };
    let arch = match std::env::consts::ARCH {
        "x86" => "i686",
        "arm" => "armv7",
        "x86_64" | "aarch64" | "riscv64" => std::env::consts::ARCH,
        _ => return Err("当前架构不支持更新".into()),
    };
    let installer = match bundle_type() {
        Some(BundleType::Deb) => "deb",
        Some(BundleType::Rpm) => "rpm",
        Some(BundleType::AppImage) => "appimage",
        Some(BundleType::Msi) => "msi",
        Some(BundleType::Nsis) => "nsis",
        Some(BundleType::App) => "app",
        _ => "unknown",
    };
    expand_endpoint(endpoint, version, target, arch, installer)
}

fn expand_endpoint(
    endpoint: &Url,
    version: &str,
    target: &str,
    arch: &str,
    installer: &str,
) -> Result<Url, String> {
    // Semver has no controls; '+' is the only character the upstream endpoint
    // encoder additionally escapes (build metadata must not become a query space).
    let version = version.replace('+', "%2B");
    let mut expanded = endpoint.to_string();
    for (name, value) in [
        ("current_version", version.as_str()),
        ("target", target),
        ("arch", arch),
        ("bundle_type", installer),
    ] {
        expanded = expanded
            .replace(&format!("%7B%7B{name}%7D%7D"), value)
            .replace(&format!("{{{{{name}}}}}"), value);
    }
    let endpoint = expanded.parse().map_err(|_| "更新地址配置无效")?;
    require_https(&endpoint)?;
    Ok(endpoint)
}
fn unavailable() -> Value {
    json!({"status":"unavailable","currentVersion":env!("CARGO_PKG_VERSION"),"message":"此版本未配置更新通道"})
}
fn current() -> Value {
    json!({"status":"up_to_date","currentVersion":env!("CARGO_PKG_VERSION"),"message":"当前已是最新版本"})
}
async fn available(channel: &Channel) -> Result<Option<Update>, String> {
    // The application configures exactly one compile-time endpoint and no
    // custom headers, proxy or target. Preserve the plugin's request headers;
    // never call check() after this read (it buffers JSON without a byte limit).
    let client = https_client()
        .user_agent("tauri-plugin-updater/2.14.1")
        .build()
        .map_err(|_| DOWNLOAD_ERROR)?;
    available_from_request(
        &channel.updater,
        manifest_request(&client, channel.endpoint.clone()),
        MANIFEST_POLICY,
    )
    .await
}

fn manifest_request(client: &Client, endpoint: Url) -> reqwest::RequestBuilder {
    client
        .get(endpoint)
        .header(header::ACCEPT, "application/json")
}

async fn available_from_request(
    updater: &Updater,
    request: reqwest::RequestBuilder,
    policy: DownloadPolicy,
) -> Result<Option<Update>, String> {
    let Some(bytes) = read_response_bounded(request, policy, true).await? else {
        return Ok(None);
    };
    let manifest = serde_json::from_slice(&bytes).map_err(|_| "更新清单格式无效，请稍后重试")?;
    // Public restore_update keeps the official version comparator, platform
    // selection, runtime key and installation path, and forces signed-version
    // binding. Only bounded server metadata reaches it, never IPC input.
    updater
        .restore_update(manifest)
        .map_err(|_| "更新信息无效，请稍后重试".into())
}
pub(super) async fn check(app: &tauri::AppHandle) -> Result<Value, String> {
    let Some(updater) = updater(app)? else {
        return Ok(unavailable());
    };
    let Some(update) = available(&updater).await? else {
        return Ok(current());
    };
    Ok(
        json!({"status":"available","currentVersion":env!("CARGO_PKG_VERSION"),"version":update.version,"notes":update.body,"message":"发现新版本"}),
    )
}
pub(super) async fn install(app: &tauri::AppHandle, state: &AppState) -> Result<Value, String> {
    let service = app.state::<Service>();
    let mut attempt = service.start()?;
    let Some(updater) = updater(app)? else {
        return Ok(unavailable());
    };
    let _ = app.emit("update-progress", json!({"phase":"checking"}));
    let Some(update) = attempt.downloading(available(&updater)).await? else {
        return Ok(current());
    };
    let _ = app.emit("update-progress", json!({"phase":"downloading"}));
    let bytes = attempt.downloading(download(&update, POLICY)).await?;
    let _ = app.emit("update-progress", json!({"phase":"verifying"}));
    update
        .verify(&bytes)
        .map_err(|_| "更新签名或版本验证失败，未安装任何更新")?;
    attempt.begin_install()?;
    install_exclusively(state, || {
        let _ = app.emit("update-progress", json!({"phase":"installing"}));
        update.install(&bytes).map_err(|_| "更新安装失败，请稍后重试".to_string())?;
        Ok(json!({"status":"installed","currentVersion":env!("CARGO_PKG_VERSION"),"version":update.version,"message":"更新已安装，请重新启动应用"}))
    }).await
}
async fn install_exclusively<T>(
    state: &AppState,
    install: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let _backend_guard = lock_backend(state, "install_update").await?;
    install()
}
fn require_https(url: &Url) -> Result<(), String> {
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return Err("更新地址必须使用不含账号信息的 HTTPS 地址".into());
    }
    Ok(())
}
fn validate_redirect(url: &Url, previous: usize) -> Result<(), String> {
    if previous >= 5 {
        return Err("更新下载重定向次数过多".into());
    }
    require_https(url)
}
fn redirect_policy() -> redirect::Policy {
    redirect::Policy::custom(|attempt| {
        if validate_redirect(attempt.url(), attempt.previous().len()).is_err() {
            attempt.error("unsafe update redirect")
        } else {
            attempt.follow()
        }
    })
}
fn https_client() -> reqwest::ClientBuilder {
    Client::builder()
        .https_only(true)
        .redirect(redirect_policy())
        .connect_timeout(Duration::from_secs(15))
}
async fn download(update: &Update, policy: DownloadPolicy) -> Result<Vec<u8>, String> {
    require_https(&update.download_url)?;
    let mut client = https_client().user_agent("short-link-generator-updater");
    if update.no_proxy {
        client = client.no_proxy();
    } else if let Some(proxy) = update.proxy.as_ref() {
        client = client.proxy(reqwest::Proxy::all(proxy.as_str()).map_err(|_| DOWNLOAD_ERROR)?);
    }
    let client = client.build().map_err(|_| DOWNLOAD_ERROR)?;
    read_bounded(
        client
            .get(update.download_url.clone())
            .headers(update.headers.clone())
            .header(header::ACCEPT, "application/octet-stream"),
        policy,
    )
    .await
}
async fn read_bounded(
    request: reqwest::RequestBuilder,
    policy: DownloadPolicy,
) -> Result<Vec<u8>, String> {
    read_response_bounded(request, policy, false)
        .await?
        .ok_or_else(|| DOWNLOAD_ERROR.into())
}
async fn read_response_bounded(
    request: reqwest::RequestBuilder,
    policy: DownloadPolicy,
    manifest: bool,
) -> Result<Option<Vec<u8>>, String> {
    tokio::time::timeout(policy.total, async {
        let response = tokio::time::timeout(policy.idle, request.send())
            .await
            .map_err(|_| "更新响应等待超时，可以稍后重试")?
            .map_err(|_| DOWNLOAD_ERROR)?;
        if manifest && response.status() == reqwest::StatusCode::NO_CONTENT {
            return Ok(None);
        }
        if !(response.status() == reqwest::StatusCode::OK
            || manifest && response.status().is_success())
        {
            return Err(DOWNLOAD_ERROR.into());
        }
        let expected = response
            .headers()
            .get(header::CONTENT_LENGTH)
            .map(|value| {
                value
                    .to_str()
                    .ok()
                    .and_then(|v| v.parse::<u64>().ok())
                    .ok_or("更新响应长度无效")
            })
            .transpose()?;
        if expected.is_some_and(|n| n > policy.max_bytes as u64) {
            return Err("更新响应超过允许大小，未安装任何更新".into());
        }
        let mut stream = response.bytes_stream();
        let mut bytes = Vec::new();
        loop {
            let chunk = tokio::time::timeout(policy.idle, stream.next())
                .await
                .map_err(|_| "更新响应停滞超时，可以稍后重试")?;
            let Some(chunk) = chunk else {
                break;
            };
            let chunk = chunk.map_err(|_| DOWNLOAD_ERROR)?;
            let length = bytes
                .len()
                .checked_add(chunk.len())
                .filter(|n| *n <= policy.max_bytes)
                .ok_or("更新响应超过允许大小，未安装任何更新")?;
            if expected.is_some_and(|n| length as u64 > n) {
                return Err("更新响应长度不一致".into());
            }
            if length > bytes.capacity() {
                let capacity = length
                    .max(bytes.capacity().saturating_mul(2))
                    .min(policy.max_bytes);
                bytes
                    .try_reserve_exact(capacity - bytes.len())
                    .map_err(|_| "没有足够内存读取更新")?;
            }
            bytes.extend_from_slice(&chunk);
        }
        if bytes.is_empty() || expected.is_some_and(|n| n != bytes.len() as u64) {
            return Err("更新响应长度不一致".into());
        }
        Ok(Some(bytes))
    })
    .await
    .map_err(|_| "更新读取总时限已到，可以稍后重试".to_string())?
}

#[cfg(test)]
mod tests;
