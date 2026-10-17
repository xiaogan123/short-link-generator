use super::*;

pub(super) const LIMITER: &str = "CLICK_RATE_LIMITER";
pub(super) const DISABLED: &str = "CLICK_GUARD_DISABLED";

pub(super) fn binding(namespace: &str) -> Value {
    // Stable, account-local namespace without exposing an identifier in public
    // source. The per-request key also isolates the owned Worker and host.
    let digest = Sha256::digest(namespace.as_bytes());
    let id = digest[..6]
        .iter()
        .fold(0_u64, |id, byte| (id << 8) | u64::from(*byte))
        + 1;
    json!({"name":LIMITER,"type":"ratelimit","namespace_id":id.to_string(),"simple":{"limit":100,"period":10}})
}

pub(super) fn normalize(value: &Value, namespace: &str) -> Option<Value> {
    let mut candidate = value.clone();
    // The provider may explicitly return the default (no extra mitigation).
    if candidate["simple"]["mitigation_timeout"] == 0 {
        candidate["simple"]
            .as_object_mut()?
            .remove("mitigation_timeout");
    }
    let expected = binding(namespace);
    if candidate == expected {
        Some(expected)
    } else if value == &json!({"name":DISABLED,"type":"plain_text","text":"1"}) {
        Some(value.clone())
    } else {
        None
    }
}

pub(super) fn configure(
    settings: &mut Value,
    namespace: &str,
    enabled: Option<bool>,
) -> Result<(), String> {
    let bindings = settings["bindings"]
        .as_array_mut()
        .ok_or("Worker 绑定格式无效")?;
    if enabled == Some(false) {
        if !bindings.iter().any(|b| b["name"] == DISABLED) {
            bindings.push(json!({"name":DISABLED,"type":"plain_text","text":"1"}));
        }
    } else {
        if !bindings.iter().any(|b| b["name"] == LIMITER) {
            bindings.push(binding(namespace));
        }
        if enabled == Some(true) {
            bindings.retain(|b| b["name"] != DISABLED);
        }
    }
    bindings.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    Ok(())
}

impl Backend {
    pub(super) async fn get_click_protection(&self, payload: &Value) -> Result<Value, String> {
        let account_id = field(payload, "accountId")?;
        self.require_credentials(account_id)?;
        self.require_no_worker_upgrade(account_id)?;
        let resources = self
            .account(account_id)?
            .resources
            .as_ref()
            .ok_or("此账户尚无云端短链接服务")?;
        let token = Zeroizing::new(keyring_get(account_id, "token")?);
        self.verify_resource_source(&token, account_id, resources)
            .await?;
        let settings = self
            .cloud
            .script_settings(&token, account_id, &resources.script)
            .await
            .map_err(problem)?;
        let normalized =
            worker_upgrade::normalized_settings(&settings["result"], &resources.namespace)?;
        let bindings = normalized["bindings"]
            .as_array()
            .ok_or("Worker 绑定格式无效")?;
        let status = if bindings
            .iter()
            .any(|b| b["name"] == DISABLED && normalize(b, &resources.namespace).is_some())
        {
            "disabled"
        } else if bindings
            .iter()
            .any(|b| b["name"] == LIMITER && normalize(b, &resources.namespace).is_some())
        {
            "enabled"
        } else {
            "upgrade_required"
        };
        Ok(
            json!({"accountId":account_id,"status":status,"limit":100,"periodSeconds":10,"checkedAt":now()}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bindings_are_owned_and_bounded() {
        let expected = binding("ns1");
        assert!(
            expected["namespace_id"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap()
                > 0
        );
        assert_ne!(expected, binding("ns2"));
        assert_eq!(normalize(&expected, "ns1"), Some(expected.clone()));
        let mut provider = expected.clone();
        provider["simple"]["mitigation_timeout"] = json!(0);
        assert_eq!(normalize(&provider, "ns1"), Some(expected.clone()));
        provider["simple"]["mitigation_timeout"] = json!(60);
        assert!(normalize(&provider, "ns1").is_none());
        assert!(normalize(&expected, "ns2").is_none());
    }

    #[test]
    fn defaults_enable_and_explicit_disable_survives_upgrade() {
        let mut settings = json!({"bindings":[]});
        configure(&mut settings, "ns1", None).unwrap();
        assert_eq!(settings["bindings"], json!([binding("ns1")]));
        configure(&mut settings, "ns1", Some(false)).unwrap();
        let disabled = settings.clone();
        configure(&mut settings, "ns1", None).unwrap();
        assert_eq!(settings, disabled);
        configure(&mut settings, "ns1", Some(true)).unwrap();
        assert_eq!(settings["bindings"], json!([binding("ns1")]));
    }
}
