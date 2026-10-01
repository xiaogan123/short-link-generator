use crate::local_check::DnsMode;
use reqwest::{multipart, Client, Method, StatusCode};
use serde_json::{json, Value};
use std::time::Duration;

const BASE: &str = "https://api.cloudflare.com/client/v4/";
const MAX_PAGES: u32 = 100;
const PROBE_TIMEOUT: Duration = Duration::from_secs(30);

fn probe_timeout() -> CloudError {
    CloudError::new(
        "路径检查超时，尚未确认此目录的响应，请检查网络后重试",
        false,
    )
}

fn probe_transport_error(error: reqwest::Error) -> CloudError {
    if error.is_timeout() {
        probe_timeout()
    } else if error.is_connect() {
        CloudError::new(
            "连接或 TLS 验证失败；请检查代理/VPN，以及此主机名的边缘证书是否已生效",
            false,
        )
    } else {
        CloudError::new("路径网络请求失败，尚未确认此目录的响应", false)
    }
}

async fn probe_response(
    client: &Client,
    url: reqwest::Url,
    header: Option<&str>,
) -> CloudResult<(u16, Option<String>)> {
    let mut req = client.head(url.clone());
    if let Some(h) = header {
        req = req.header("X-Selftest", h);
    }
    let mut response = req.send().await.map_err(probe_transport_error)?;
    if response.status() == StatusCode::METHOD_NOT_ALLOWED {
        // Do not consume either response body. A compliant server also honors Range.
        let mut req = client.get(url).header(reqwest::header::RANGE, "bytes=0-0");
        if let Some(h) = header {
            req = req.header("X-Selftest", h);
        }
        response = req.send().await.map_err(probe_transport_error)?;
    }
    let location = response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    Ok((response.status().as_u16(), location))
}

fn uncertain_write_status(status: StatusCode) -> bool {
    status.is_server_error() || status == StatusCode::REQUEST_TIMEOUT || status.is_redirection()
}

#[derive(Debug)]
pub struct CloudError {
    pub message: String,
    pub uncertain: bool,
}

impl CloudError {
    fn new(message: impl Into<String>, uncertain: bool) -> Self {
        Self {
            message: message.into(),
            uncertain,
        }
    }
}

pub type CloudResult<T> = Result<T, CloudError>;

#[derive(Clone)]
pub struct Cloud {
    client: Client,
    base: reqwest::Url,
}

impl Cloud {
    pub async fn schedules(&self, token: &str, account: &str, script: &str) -> CloudResult<Value> {
        self.get(
            token,
            &format!("accounts/{account}/workers/scripts/{script}/schedules"),
        )
        .await
    }

    pub async fn set_schedules(
        &self,
        token: &str,
        account: &str,
        script: &str,
        enabled: bool,
    ) -> CloudResult<()> {
        let body = if enabled {
            json!([{"cron":"*/15 * * * *"}])
        } else {
            json!([])
        };
        self.put(
            token,
            &format!("accounts/{account}/workers/scripts/{script}/schedules"),
            body,
        )
        .await
        .map(|_| ())
    }

    pub async fn set_probe_secret(
        &self,
        token: &str,
        account: &str,
        script: &str,
        secret: &str,
    ) -> CloudResult<()> {
        self.put(
            token,
            &format!("accounts/{account}/workers/scripts/{script}/secrets"),
            json!({"name":"PROBE_KEY","text":secret,"type":"secret_text"}),
        )
        .await
        .map(|_| ())
    }

    pub async fn delete_probe_secret(
        &self,
        token: &str,
        account: &str,
        script: &str,
    ) -> CloudResult<()> {
        self.delete(
            token,
            &format!("accounts/{account}/workers/scripts/{script}/secrets/PROBE_KEY"),
        )
        .await
        .map(|_| ())
    }
    pub fn new() -> Result<Self, String> {
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .https_only(true)
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|_| "网络客户端初始化失败".to_string())?;
        Ok(Self {
            client,
            base: reqwest::Url::parse(BASE).expect("fixed Cloudflare API URL"),
        })
    }

    #[cfg(test)]
    pub fn for_test(base: &str) -> Self {
        Self {
            client: Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(2))
                .build()
                .expect("test client"),
            base: reqwest::Url::parse(base).expect("test URL"),
        }
    }

    fn url(&self, path: &str) -> CloudResult<reqwest::Url> {
        let url = self
            .base
            .join(path)
            .map_err(|_| CloudError::new("请求路径无效", false))?;
        if url.origin() != self.base.origin() {
            return Err(CloudError::new("请求地址不被允许", false));
        }
        #[cfg(not(test))]
        if url.scheme() != "https" || url.host_str() != Some("api.cloudflare.com") {
            return Err(CloudError::new("请求地址不被允许", false));
        }
        Ok(url)
    }

    async fn send(
        &self,
        token: &str,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> CloudResult<Value> {
        let url = self.url(path)?;
        let write = method != Method::GET && method != Method::HEAD;
        for attempt in 0..=3 {
            let mut req = self
                .client
                .request(method.clone(), url.clone())
                .bearer_auth(token);
            if let Some(value) = &body {
                req = req.json(value);
            }
            let response = req.send().await.map_err(|_| {
                CloudError::new(
                    if write {
                        "云端写入结果不确定，请检查操作记录"
                    } else {
                        "连接云端失败，请检查网络"
                    },
                    write,
                )
            })?;
            if response.status() == StatusCode::TOO_MANY_REQUESTS && attempt < 3 {
                let delay = response
                    .headers()
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(1 << attempt)
                    .min(8);
                tokio::time::sleep(Duration::from_secs(delay)).await;
                continue;
            }
            if response.status().is_redirection() {
                return Err(CloudError::new("云端返回意外跳转", write));
            }
            let status = response.status();
            if !status.is_success() {
                return Err(CloudError::new(
                    format!(
                        "云端请求失败（HTTP {}），请检查令牌权限与资源状态",
                        status.as_u16()
                    ),
                    write && uncertain_write_status(status),
                ));
            }
            let value: Value = response
                .json()
                .await
                .map_err(|_| CloudError::new("云端响应格式无效", write))?;
            if value.get("success").and_then(Value::as_bool) != Some(true) {
                let code = value["errors"]
                    .as_array()
                    .and_then(|items| items.first())
                    .and_then(|item| item["code"].as_i64())
                    .unwrap_or_default();
                return Err(CloudError::new(
                    format!("云端拒绝请求（错误码 {code}），请检查权限与资源状态"),
                    false,
                ));
            }
            return Ok(value);
        }
        Err(CloudError::new("请求过于频繁，请稍后再试", false))
    }

    pub async fn get(&self, token: &str, path: &str) -> CloudResult<Value> {
        self.send(token, Method::GET, path, None).await
    }

    pub async fn post(&self, token: &str, path: &str, body: Value) -> CloudResult<Value> {
        self.send(token, Method::POST, path, Some(body)).await
    }

    pub async fn put(&self, token: &str, path: &str, body: Value) -> CloudResult<Value> {
        self.send(token, Method::PUT, path, Some(body)).await
    }

    pub async fn patch(&self, token: &str, path: &str, body: Value) -> CloudResult<Value> {
        self.send(token, Method::PATCH, path, Some(body)).await
    }

    pub async fn delete(&self, token: &str, path: &str) -> CloudResult<Value> {
        self.send(token, Method::DELETE, path, None).await
    }

    pub async fn list_pages(&self, token: &str, path: &str) -> CloudResult<Vec<Value>> {
        let mut all = Vec::new();
        for page in 1..=MAX_PAGES {
            let separator = if path.contains('?') { '&' } else { '?' };
            let value = self
                .get(token, &format!("{path}{separator}per_page=50&page={page}"))
                .await?;
            let batch = value["result"]
                .as_array()
                .ok_or_else(|| CloudError::new("云端列表格式无效", false))?;
            all.extend(batch.iter().cloned());
            let pages = value["result_info"]["total_pages"].as_u64();
            if pages.is_some_and(|p| page as u64 >= p) || (pages.is_none() && batch.len() < 50) {
                return Ok(all);
            }
        }
        Err(CloudError::new("云端列表超过安全分页上限", false))
    }

    pub async fn list_keys(
        &self,
        token: &str,
        account: &str,
        namespace: &str,
        prefix: &str,
    ) -> CloudResult<Vec<String>> {
        let mut all = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let mut url = format!(
                "accounts/{account}/storage/kv/namespaces/{namespace}/keys?limit=1000&prefix={}",
                encode(prefix)
            );
            if let Some(c) = &cursor {
                url.push_str("&cursor=");
                url.push_str(&encode(c));
            }
            let value = self.get(token, &url).await?;
            let list = value["result"]
                .as_array()
                .ok_or_else(|| CloudError::new("键列表格式无效", false))?;
            for item in list {
                let name = item["name"]
                    .as_str()
                    .ok_or_else(|| CloudError::new("键列表格式无效", false))?;
                all.push(name.to_string());
            }
            let next = value["result_info"]["cursor"]
                .as_str()
                .filter(|s| !s.is_empty());
            if let Some(next) = next {
                if cursor.as_deref() == Some(next) {
                    return Err(CloudError::new("云端分页游标重复", false));
                }
                cursor = Some(next.to_string());
            } else {
                return Ok(all);
            }
        }
        Err(CloudError::new("键列表超过安全分页上限", false))
    }

    pub async fn read_value(
        &self,
        token: &str,
        account: &str,
        namespace: &str,
        key: &str,
    ) -> CloudResult<Option<String>> {
        let path = format!(
            "accounts/{account}/storage/kv/namespaces/{namespace}/values/{}",
            encode(key)
        );
        let url = self.url(&path)?;
        for attempt in 0..=3 {
            let response = self
                .client
                .get(url.clone())
                .bearer_auth(token)
                .send()
                .await
                .map_err(|_| CloudError::new("读取云端配置失败", false))?;
            if response.status() == StatusCode::TOO_MANY_REQUESTS && attempt < 3 {
                tokio::time::sleep(Duration::from_secs(1 << attempt)).await;
                continue;
            }
            if response.status() == StatusCode::NOT_FOUND {
                return Ok(None);
            }
            if !response.status().is_success() {
                return Err(CloudError::new(
                    format!("读取云端配置失败（HTTP {}）", response.status().as_u16()),
                    false,
                ));
            }
            return response
                .text()
                .await
                .map(Some)
                .map_err(|_| CloudError::new("读取云端配置失败", false));
        }
        Err(CloudError::new("请求过于频繁，请稍后再试", false))
    }

    pub async fn write_value(
        &self,
        token: &str,
        account: &str,
        namespace: &str,
        key: &str,
        value: &str,
    ) -> CloudResult<()> {
        let path = format!(
            "accounts/{account}/storage/kv/namespaces/{namespace}/values/{}",
            encode(key)
        );
        let url = self.url(&path)?;
        for attempt in 0..=3 {
            let response = self
                .client
                .put(url.clone())
                .bearer_auth(token)
                .body(value.to_owned())
                .header("content-type", "application/json")
                .send()
                .await
                .map_err(|_| CloudError::new("云端写入结果不确定，请检查操作记录", true))?;
            if response.status() == StatusCode::TOO_MANY_REQUESTS && attempt < 3 {
                tokio::time::sleep(Duration::from_secs(1 << attempt)).await;
                continue;
            }
            if !response.status().is_success() {
                return Err(CloudError::new(
                    format!("写入云端记录失败（HTTP {}）", response.status().as_u16()),
                    uncertain_write_status(response.status()),
                ));
            }
            return Ok(());
        }
        Err(CloudError::new("请求过于频繁，请稍后再试", false))
    }

    pub async fn delete_value(
        &self,
        token: &str,
        account: &str,
        namespace: &str,
        key: &str,
    ) -> CloudResult<()> {
        self.delete(
            token,
            &format!(
                "accounts/{account}/storage/kv/namespaces/{namespace}/values/{}",
                encode(key)
            ),
        )
        .await
        .map(|_| ())
    }

    pub async fn upload_script(
        &self,
        token: &str,
        account: &str,
        script: &str,
        namespace: &str,
        key_hex: &str,
    ) -> CloudResult<()> {
        let metadata = json!({
            "main_module": "worker.mjs",
            "compatibility_date": "2025-01-01",
            "bindings": [
                {"type":"kv_namespace","name":"LINKS","namespace_id":namespace},
                {"type":"secret_text","name":"SELFTEST_KEY","text":key_hex}
            ]
        });
        let url = self.url(&format!("accounts/{account}/workers/scripts/{script}"))?;
        for attempt in 0..=3 {
            let form = multipart::Form::new()
                .part(
                    "metadata",
                    multipart::Part::text(metadata.to_string())
                        .mime_str("application/json")
                        .map_err(|_| CloudError::new("Worker 元数据无效", false))?,
                )
                .part(
                    "worker.mjs",
                    multipart::Part::text(include_str!("../../edge/worker.mjs"))
                        .file_name("worker.mjs")
                        .mime_str("application/javascript+module")
                        .map_err(|_| CloudError::new("Worker 脚本格式无效", false))?,
                );
            let response = self
                .client
                .put(url.clone())
                .bearer_auth(token)
                .multipart(form)
                .send()
                .await
                .map_err(|_| CloudError::new("Worker 上传结果不确定，请检查操作记录", true))?;
            if response.status() == StatusCode::TOO_MANY_REQUESTS && attempt < 3 {
                tokio::time::sleep(Duration::from_secs(1 << attempt)).await;
                continue;
            }
            if !response.status().is_success() {
                return Err(CloudError::new(
                    format!("Worker 上传失败（HTTP {}）", response.status().as_u16()),
                    uncertain_write_status(response.status()),
                ));
            }
            let value: Value = response
                .json()
                .await
                .map_err(|_| CloudError::new("Worker 响应格式无效", true))?;
            if value["success"] != true {
                return Err(CloudError::new("Worker 上传被云端拒绝", false));
            }
            return Ok(());
        }
        Err(CloudError::new("请求过于频繁，请稍后再试", false))
    }

    pub async fn script_settings(
        &self,
        token: &str,
        account: &str,
        script: &str,
    ) -> CloudResult<Value> {
        self.get(
            token,
            &format!("accounts/{account}/workers/scripts/{script}/settings"),
        )
        .await
    }

    pub async fn script_content(
        &self,
        token: &str,
        account: &str,
        script: &str,
    ) -> CloudResult<Vec<u8>> {
        let url = self.url(&format!(
            "accounts/{account}/workers/scripts/{script}/content/v2"
        ))?;
        for attempt in 0..=3 {
            let response = self
                .client
                .get(url.clone())
                .bearer_auth(token)
                .send()
                .await
                .map_err(|_| CloudError::new("无法读取 Worker 内容", false))?;
            if response.status() == StatusCode::TOO_MANY_REQUESTS && attempt < 3 {
                tokio::time::sleep(Duration::from_secs(1 << attempt)).await;
                continue;
            }
            if !response.status().is_success() {
                return Err(CloudError::new(
                    format!(
                        "读取 Worker 内容失败（HTTP {}）",
                        response.status().as_u16()
                    ),
                    false,
                ));
            }
            let content_type = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let body = response
                .bytes()
                .await
                .map_err(|_| CloudError::new("Worker 内容读取失败", false))?;
            if body.len() > 10_000_000 {
                return Err(CloudError::new("Worker 内容超过安全上限", false));
            }
            if content_type.to_ascii_lowercase().starts_with("multipart/") {
                let boundary = multer::parse_boundary(&content_type)
                    .map_err(|_| CloudError::new("Worker 多部分响应边界无效", false))?;
                let stream =
                    futures_util::stream::once(async move { Ok::<_, std::io::Error>(body) });
                let mut parts = multer::Multipart::new(stream, boundary);
                let mut module = None;
                while let Some(field) = parts
                    .next_field()
                    .await
                    .map_err(|_| CloudError::new("Worker 多部分响应无效", false))?
                {
                    let name = field.name().unwrap_or("");
                    if name == "worker.mjs" {
                        if module.is_some() {
                            return Err(CloudError::new("Worker 模块重复", false));
                        }
                        module = Some(
                            field
                                .bytes()
                                .await
                                .map_err(|_| CloudError::new("Worker 模块读取失败", false))?
                                .to_vec(),
                        );
                    } else if name != "metadata" {
                        return Err(CloudError::new("Worker 含有额外模块，停止操作", false));
                    }
                }
                return module.ok_or_else(|| CloudError::new("Worker 主模块缺失", false));
            }
            let kind = content_type.to_ascii_lowercase();
            if kind.starts_with("application/javascript") || kind.starts_with("text/javascript") {
                return Ok(body.to_vec());
            }
            return Err(CloudError::new("Worker 内容类型无法验证", false));
        }
        Err(CloudError::new("请求过于频繁，请稍后再试", false))
    }

    pub async fn probe(
        &self,
        input: &str,
        header: Option<String>,
    ) -> CloudResult<(u16, Option<String>)> {
        self.probe_with_mode(input, header, DnsMode::System).await
    }

    pub async fn probe_with_mode(
        &self,
        input: &str,
        header: Option<String>,
        mode: DnsMode,
    ) -> CloudResult<(u16, Option<String>)> {
        let url = reqwest::Url::parse(input).map_err(|_| CloudError::new("探测地址无效", false))?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(CloudError::new(
                "只允许不含登录信息的 HTTPS 探测地址",
                false,
            ));
        }
        // One budget includes resolution and the optional HEAD -> GET fallback.
        // The authenticated API client and its proxy policy remain unchanged.
        tokio::time::timeout(PROBE_TIMEOUT, async {
            #[cfg(not(test))]
            let client = crate::local_check::client_for_probe(&url, mode, PROBE_TIMEOUT)
                .await
                .map_err(|message| CloudError::new(message, false))?;
            #[cfg(test)]
            let (client, url) = {
                // Existing integration fixtures use a local wiremock API server.
                // Production never bypasses the guarded resolver above.
                let _ = mode;
                let url = self
                    .base
                    .join(&format!(
                        "probe/{}{}",
                        url.host_str().unwrap_or_default(),
                        url.path()
                    ))
                    .map_err(|_| CloudError::new("测试探测地址无效", false))?;
                (self.client.clone(), url)
            };
            probe_response(&client, url, header.as_deref()).await
        })
        .await
        .map_err(|_| probe_timeout())?
    }

    pub async fn rotate_secret(
        &self,
        token: &str,
        account: &str,
        script: &str,
        key_hex: &str,
    ) -> CloudResult<()> {
        self.put(
            token,
            &format!("accounts/{account}/workers/scripts/{script}/secrets"),
            json!({"name":"SELFTEST_KEY","text":key_hex,"type":"secret_text"}),
        )
        .await
        .map(|_| ())
    }
}

pub fn encode(input: &str) -> String {
    url::form_urlencoded::byte_serialize(input.as_bytes()).collect()
}

#[cfg(test)]
#[path = "cloud_probe_tests.rs"]
mod cloud_probe_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_paths_cannot_escape_fixed_origin() {
        let cloud = Cloud::new().unwrap();
        assert_eq!(
            cloud.url("zones/abc").unwrap().host_str(),
            Some("api.cloudflare.com")
        );
        assert!(cloud.url("https://example.org/").is_err());
        assert!(cloud.url("//example.org/").is_err());
    }

    #[test]
    fn kv_keys_are_encoded_for_path_segments() {
        assert_eq!(encode("l:example.com:a/b"), "l%3Aexample.com%3Aa%2Fb");
    }
}
