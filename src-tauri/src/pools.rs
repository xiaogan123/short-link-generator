use crate::model::{Pool, PoolCandidate, Template};
use serde_json::{json, Value};

pub fn valid_code(code: &str) -> bool {
    (1..=128).contains(&code.len())
        && code
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

pub fn valid_id(id: &str) -> bool {
    valid_code(id)
}

pub fn compose(template: &Template, code: &str) -> Result<String, String> {
    if !valid_code(code) {
        return Err("邀请码需为 1–128 位字母、数字、下划线或连字符".into());
    }
    if template.prefix.len() + template.suffix.len() > 1900
        || template
            .prefix
            .bytes()
            .any(|b| b <= 32 || b == 127 || b == b'\\')
        || template
            .suffix
            .bytes()
            .any(|b| b <= 32 || b == 127 || b == b'\\')
    {
        return Err("平台地址模板含有不允许的字符或过长".into());
    }
    let rest = template
        .prefix
        .strip_prefix("https://")
        .ok_or("平台地址模板必须包含完整的 HTTPS 主机名")?;
    let authority_end = rest
        .find(['/', '?'])
        .ok_or("邀请码只能放在网址的路径或查询部分")?;
    if authority_end == 0
        || rest[..authority_end].contains(['#', '@'])
        || template.prefix.contains('#')
    {
        return Err("平台地址模板的主机名或片段无效".into());
    }
    let prefix_url = url::Url::parse(&template.prefix).map_err(|_| "平台地址模板前半段无效")?;
    let target = format!("{}{}{}", template.prefix, code, template.suffix);
    let url = url::Url::parse(&target).map_err(|_| "平台地址模板生成的网址无效".to_string())?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.port() == Some(0)
        || target.len() > 2048
        || url.as_str().len() > 2048
        || url.origin() != prefix_url.origin()
    {
        return Err("平台地址模板必须生成不含账号信息或片段的完整 HTTPS 网址".into());
    }
    Ok(url.to_string())
}

pub fn validate_pool(pool: &Pool) -> Result<(), String> {
    if !valid_id(&pool.id) {
        return Err("平台地址 ID 无效".into());
    }
    if pool.name.trim().is_empty() || pool.name.chars().count() > 64 {
        return Err("平台地址名称需为 1–64 个字符".into());
    }
    if chrono::DateTime::parse_from_rfc3339(&pool.updated).is_err() {
        return Err("平台地址修订时间无效".into());
    }
    compose(&pool.official, "probe")?;
    if url::Url::parse(&compose(&pool.official, "probe")?)
        .unwrap()
        .origin()
        != url::Url::parse(&compose(&pool.official, "sample2")?)
            .unwrap()
            .origin()
    {
        return Err("邀请码不得改变主机".into());
    }
    if pool.candidates.is_empty() || pool.candidates.len() > 10 {
        return Err("大陆备用地址需为 1–10 个".into());
    }
    let mut ids = std::collections::HashSet::new();
    let mut enabled = false;
    for candidate in &pool.candidates {
        if !valid_id(&candidate.id) || !ids.insert(&candidate.id) {
            return Err("大陆备用地址 ID 无效或重复".into());
        }
        compose(&Template::from(candidate), "probe")?;
        compose(&Template::from(candidate), "sample2")?;
        enabled |= candidate.enabled;
    }
    if !enabled {
        return Err("至少启用一个大陆备用地址".into());
    }
    if pool.account_ids.len() > 100 {
        return Err("关联账号超过上限".into());
    }
    let mut accounts = std::collections::HashSet::new();
    for id in &pool.account_ids {
        if !valid_id(id) || !accounts.insert(id) {
            return Err("关联账号标识无效或重复".into());
        }
    }
    if cloud_value(pool).to_string().len() > 16_384 {
        return Err("这组平台地址的云端配置超过 16 KiB 上限".into());
    }
    Ok(())
}

pub fn valid_health(value: &Value) -> bool {
    const SAFE: i64 = 9_007_199_254_740_991;
    let safe_int = |v: &Value| v.as_i64().is_some_and(|n| (-SAFE..=SAFE).contains(&n));
    let Some(obj) = value.as_object() else {
        return false;
    };
    if obj.get("revision").and_then(Value::as_str).is_none()
        || !obj.get("checkedAt").is_some_and(safe_int)
    {
        return false;
    }
    let Some(targets) = obj.get("targets").and_then(Value::as_object) else {
        return false;
    };
    targets.iter().all(|(id, target)| {
        valid_id(id)
            && target.is_object()
            && matches!(
                target["state"].as_str(),
                Some("healthy" | "unhealthy" | "unknown")
            )
            && target["failures"]
                .as_i64()
                .is_some_and(|n| (0..=SAFE).contains(&n))
            && target["successes"]
                .as_i64()
                .is_some_and(|n| (0..=SAFE).contains(&n))
            && safe_int(&target["checkedAt"])
    })
}

impl From<&PoolCandidate> for Template {
    fn from(c: &PoolCandidate) -> Self {
        Self {
            prefix: c.prefix.clone(),
            suffix: c.suffix.clone(),
        }
    }
}

pub fn cloud_value(pool: &Pool) -> Value {
    json!({"version":1,"official":pool.official,
        "candidates":pool.candidates,"revision":pool.updated})
}

pub fn matching_cloud_value(pool: &Pool, remote: &Value) -> bool {
    remote == &cloud_value(pool)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unusable_port_and_oversized_canonical_destinations() {
        for prefix in [
            "https://example.org:0/join/".to_string(),
            format!("https://example.org/{}", "值".repeat(230)),
        ] {
            assert!(compose(
                &Template {
                    prefix,
                    suffix: String::new()
                },
                "CODE"
            )
            .is_err());
        }
        assert!(compose(
            &Template {
                prefix: "https://example.org:8443/join/".into(),
                suffix: String::new(),
            },
            "CODE"
        )
        .is_ok());
    }
    #[test]
    fn preserves_template_query_and_encodes_host() {
        let t = Template {
            prefix: "https://例子.example/path/".into(),
            suffix: "?source=one".into(),
        };
        assert_eq!(
            compose(&t, "abc_1").unwrap(),
            "https://xn--fsqu00a.example/path/abc_1?source=one"
        );
    }
    #[test]
    fn blocks_credentials_and_controls() {
        let t = Template {
            prefix: "https://user@example.com/".into(),
            suffix: "".into(),
        };
        assert!(compose(&t, "probe").is_err());
        let t = Template {
            prefix: "https://".into(),
            suffix: ".example.org/path".into(),
        };
        assert!(compose(&t, "probe").is_err());
        let t = Template {
            prefix: "https://example.org:8".into(),
            suffix: "443/path".into(),
        };
        assert!(compose(&t, "probe").is_err());
        let t = Template {
            prefix: "https://example.com/".into(),
            suffix: "\n".into(),
        };
        assert!(compose(&t, "probe").is_err());
    }

    #[test]
    fn rejects_pool_payload_larger_than_worker_limit() {
        let candidate = PoolCandidate {
            id: "candidate".into(),
            prefix: format!("https://example.com/{}", "a".repeat(1600)),
            suffix: "/".into(),
            enabled: true,
        };
        let mut pool = Pool {
            id: "pool".into(),
            name: "Pool".into(),
            official: Template {
                prefix: "https://official.example/".into(),
                suffix: "".into(),
            },
            candidates: (0..10)
                .map(|i| PoolCandidate {
                    id: format!("candidate{i}"),
                    ..candidate.clone()
                })
                .collect(),
            updated: "2026-09-28T00:00:00Z".into(),
            account_ids: vec![],
            sync_status: vec![],
        };
        assert!(cloud_value(&pool).to_string().len() > 16_384);
        assert!(validate_pool(&pool).is_err());
        pool.candidates.truncate(2);
        assert!(validate_pool(&pool).is_ok());
    }
}
