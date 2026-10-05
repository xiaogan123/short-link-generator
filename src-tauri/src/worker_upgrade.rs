use super::*;
use serde_json::Map;

fn empty_default(value: &Value) -> bool {
    value.is_null()
        || value == false
        || value == 0
        || value == ""
        || value.as_array().is_some_and(Vec::is_empty)
        || value.as_object().is_some_and(Map::is_empty)
}

/// Normalize only safe settings. Values of secret bindings are never accepted,
/// copied into a journal, or included in upload metadata.
fn normalized_settings(raw: &Value, namespace: &str) -> Result<Value, String> {
    let object = raw.as_object().ok_or("Worker 设置格式无效")?;
    for (key, value) in object {
        let safe = match key.as_str() {
            "bindings" | "compatibility_date" | "compatibility_flags" | "main_module" => true,
            "created_on" | "modified_on" | "etag" | "id" | "last_deployed_from" | "has_modules"
            | "handlers" => true,
            "usage_model" => value.is_null() || value == "standard",
            "placement" => empty_default(value) || value == &json!({"mode":"off"}),
            "observability" => {
                empty_default(value)
                    || value == &json!({"enabled":false})
                    || value == &json!({"enabled":false,"head_sampling_rate":1})
            }
            _ => empty_default(value),
        };
        if !safe {
            return Err("Worker 含有本版本不能安全保留的非默认设置，停止升级".into());
        }
    }
    let date = raw["compatibility_date"]
        .as_str()
        .ok_or("Worker 缺少兼容日期，停止升级")?;
    if chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d").is_err() {
        return Err("Worker 兼容日期无效".into());
    }
    if raw.get("main_module").is_some_and(|v| v != "worker.mjs") {
        return Err("Worker 主模块不是预期的 worker.mjs，停止升级".into());
    }
    let mut flags = match raw.get("compatibility_flags") {
        None | Some(Value::Null) => vec![],
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| {
                let flag = v.as_str().ok_or("Worker 兼容标记无效")?;
                if flag.is_empty()
                    || flag.len() > 128
                    || !flag.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                {
                    return Err("Worker 兼容标记无效");
                }
                Ok(flag.to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => return Err("Worker 兼容标记无效".into()),
    };
    flags.sort();
    if flags.windows(2).any(|v| v[0] == v[1]) {
        return Err("Worker 兼容标记重复".into());
    }
    let bindings = raw["bindings"].as_array().ok_or("Worker 绑定格式无效")?;
    let mut names = HashSet::new();
    let mut normalized = Vec::new();
    for binding in bindings {
        let b = binding.as_object().ok_or("Worker 绑定格式无效")?;
        let name = binding["name"].as_str().ok_or("Worker 绑定名称无效")?;
        if !names.insert(name) {
            return Err("Worker 绑定重复".into());
        }
        match (name, binding["type"].as_str()) {
            ("LINKS", Some("kv_namespace"))
                if binding["namespace_id"] == namespace
                    && b.keys()
                        .all(|k| ["type", "name", "namespace_id"].contains(&k.as_str())) =>
            {
                normalized
                    .push(json!({"name":"LINKS","type":"kv_namespace","namespace_id":namespace}));
            }
            ("SELFTEST_KEY" | "PROBE_KEY", Some("secret_text"))
                if b.keys().all(|k| ["type", "name"].contains(&k.as_str())) =>
            {
                normalized.push(json!({"name":name,"type":"secret_text"}));
            }
            _ => return Err("Worker 绑定无法安全保留，停止升级".into()),
        }
    }
    if !names.contains("LINKS") {
        return Err("Worker 缺少预期 LINKS 绑定".into());
    }
    normalized.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    Ok(
        json!({"main_module":"worker.mjs","compatibility_date":date,"compatibility_flags":flags,"bindings":normalized}),
    )
}

fn normalized_schedules(raw: &Value) -> Result<Value, String> {
    let schedules = raw["result"]["schedules"]
        .as_array()
        .ok_or("Worker 计划任务列表无效")?;
    let mut crons = Vec::new();
    for item in schedules {
        let cron = item["cron"].as_str().ok_or("Worker 计划任务格式无效")?;
        if cron.is_empty()
            || cron.len() > 128
            || !cron.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
        {
            return Err("Worker 计划任务格式无效".into());
        }
        if item.as_object().is_none_or(|o| {
            o.keys()
                .any(|k| !["cron", "created_on", "modified_on"].contains(&k.as_str()))
        }) {
            return Err("Worker 计划任务含有未知配置，停止升级".into());
        }
        crons.push(cron.to_owned());
    }
    crons.sort();
    if crons.windows(2).any(|v| v[0] == v[1]) {
        return Err("Worker 计划任务重复".into());
    }
    Ok(json!(crons))
}

fn validated_manifest(raw: &str, account_id: &str, resources: &Resources) -> Result<Value, String> {
    let value: Value = serde_json::from_str(raw).map_err(|_| "云端资源清单损坏")?;
    if value.as_object().is_none_or(|o| {
        o.len() != 5
            || o.keys().any(|k| {
                !["schema", "accountId", "script", "namespace", "sourceHash"].contains(&k.as_str())
            })
    }) || value["schema"] != SCHEMA
        || value["accountId"] != account_id
        || value["script"] != resources.script
        || value["namespace"] != resources.namespace
        || value["sourceHash"]
            .as_str()
            .is_none_or(|h| h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err("云端资源清单归属或字段无效，停止升级".into());
    }
    Ok(value)
}

impl Backend {
    pub(super) fn require_no_worker_upgrade(&self, account_id: &str) -> Result<(), String> {
        if self
            .db
            .pending_worker_upgrades
            .iter()
            .any(|p| p.account_id == account_id)
        {
            Err(
                "此账户的 Worker 升级尚未核对，请从待处理操作恢复；云端未确认前不会执行其他变更"
                    .into(),
            )
        } else {
            Ok(())
        }
    }

    pub(super) fn resolve_link_name(
        &self,
        domain_id: &str,
        slug: &str,
        create_only: bool,
    ) -> Result<(String, bool), String> {
        validate_slug(slug)?;
        let exact = self
            .db
            .links
            .iter()
            .any(|l| l.domain_id == domain_id && l.slug == slug);
        if create_only && exact
            || !exact
                && self
                    .db
                    .links
                    .iter()
                    .any(|l| l.domain_id == domain_id && l.slug.eq_ignore_ascii_case(slug))
        {
            return Err(
                "此域名下已存在同名链接（大小写视为同名），请换一个名称；已有链接未修改".into(),
            );
        }
        Ok((
            if exact {
                slug.to_owned()
            } else {
                slug.to_ascii_lowercase()
            },
            exact,
        ))
    }

    fn require_upgrade_start(&self, account_id: &str) -> Result<(), String> {
        self.require_credentials(account_id)?;
        self.require_no_worker_upgrade(account_id)?;
        // Unknown and legacy journals are blockers too. A fresh upgrade must not
        // overlap any unfinished operation that may change remote settings.
        if !self.db.pending_operations.is_empty()
            || !self.db.pending_pool_changes.is_empty()
            || !self.db.pending_monitor_changes.is_empty()
            || !self.db.pending_selftest_rotations.is_empty()
        {
            return Err("请先完成其他待处理操作，再升级 Worker".into());
        }
        Ok(())
    }

    pub(super) fn prepare_worker_upgrade(
        &mut self,
        kind: &str,
        account_id: &str,
    ) -> Result<Value, String> {
        if kind == "dismiss_worker_upgrade" {
            self.local_worker_upgrade_pending(account_id)?;
            return serde_json::to_value(self.make_plan(
                "解除本机升级记录",
                vec!["仅删除这次升级的本机待处理记录，云端内容、设置、密钥与计划任务保持当前状态".into()],
                vec!["应先核对云端实际状态；解除后仍要求源码与资源清单一致，外部改动不会被覆盖。需要时重新找回或重建资源".into()],
                PlanKind::DismissWorkerUpgrade { account_id: account_id.into() },
            )).map_err(|_| "无法建立升级计划".into());
        }
        self.require_credentials(account_id)?;
        let resources = self
            .account(account_id)?
            .resources
            .as_ref()
            .ok_or("此账户没有已登记的 Worker/KV")?;
        let domains: Vec<_> = self
            .db
            .domains
            .iter()
            .filter(|d| d.account_id == account_id)
            .map(|d| format!("{} /{}/", d.host, d.prefix))
            .collect();
        let (title, plan_kind, steps, warnings) = match kind {
            "upgrade_worker" => {
                self.require_upgrade_start(account_id)?;
                ("启用名称大小写兼容", PlanKind::UpgradeWorker { account_id: account_id.into(), target_hash: bundled_source_hash() },
                    vec![format!("升级此账户的转发程序 {}，影响全部已导入域名：{}", resources.script, if domains.is_empty() { "无".into() } else { domains.join("、") }),
                        "先核对云端归属、源码、设置与计划任务，保留检测密钥绑定；应用更新不会自动执行此升级".into()],
                    vec!["旧名称保留精确匹配；其他大小写先匹配小写名称，再匹配唯一旧名称。目录前缀与跳转目标不变".into(),
                        "上传或核对失败会保留恢复记录；仅在明确确认计划后执行，恢复不会重新上传".into()])
            }
            "resume_worker_upgrade" => {
                self.worker_upgrade_pending(account_id)?;
                ("核对名称兼容升级", PlanKind::ResumeWorkerUpgrade { account_id: account_id.into() },
                        vec!["只回读 Worker 内容、设置与计划任务；目标版本验证通过时仅修复资源清单".into(),
                            "仍读到原版本时保留待处理记录，稍后再次核对；结束记录需单独确认本机解除计划".into()],
                        vec!["不会重新上传脚本、读取或轮换密钥；未知源码停止写入，请人工核对后解除本机升级记录".into()])
            }
            _ => return Err("不支持此升级操作".into()),
        };
        serde_json::to_value(self.make_plan(title, steps, warnings, plan_kind))
            .map_err(|_| "无法建立升级计划".into())
    }

    fn worker_upgrade_pending(&self, account_id: &str) -> Result<PendingWorkerUpgrade, String> {
        let p = self.local_worker_upgrade_pending(account_id)?;
        let r = self
            .account(account_id)?
            .resources
            .as_ref()
            .ok_or("账户资源未登记")?;
        if r.script != p.resources.script || r.namespace != p.resources.namespace {
            return Err("本机资源身份已变化，停止升级恢复".into());
        }
        Ok(p)
    }

    fn local_worker_upgrade_pending(
        &self,
        account_id: &str,
    ) -> Result<PendingWorkerUpgrade, String> {
        self.account(account_id)?;
        let p = self
            .db
            .pending_worker_upgrades
            .iter()
            .find(|p| p.account_id == account_id)
            .ok_or("此账户没有待处理升级")?;
        Ok(p.clone())
    }

    fn upgrade_note(
        &mut self,
        account_id: &str,
        phase: WorkerUpgradePhase,
        note: &str,
    ) -> Result<(), String> {
        self.persist_rotation_mutation(|db| {
            let p = db
                .pending_worker_upgrades
                .iter_mut()
                .find(|p| p.account_id == account_id)
                .ok_or("升级记录不存在")?;
            p.phase = phase;
            let journal = p.journal.clone();
            set_journal_note(&mut db.pending_operations, &journal, note)?;
            Ok(())
        })
    }

    pub(super) fn dismiss_worker_upgrade(&mut self, account_id: &str) -> Result<(), String> {
        let p = self.local_worker_upgrade_pending(account_id)?;
        self.persist_rotation_mutation(|db| {
            db.pending_worker_upgrades
                .retain(|v| v.account_id != account_id);
            clear_journal(&mut db.pending_operations, &p.journal)
        })
    }

    async fn read_upgrade_manifest(
        &self,
        token: &str,
        account_id: &str,
        resources: &Resources,
    ) -> Result<Value, String> {
        let raw = self
            .cloud
            .read_value(token, account_id, &resources.namespace, MANIFEST_KEY)
            .await
            .map_err(problem)?
            .ok_or("云端资源清单缺失")?;
        validated_manifest(&raw, account_id, resources)
    }

    async fn read_upgrade_settings(
        &self,
        token: &str,
        account_id: &str,
        resources: &Resources,
    ) -> Result<Value, String> {
        let raw = self
            .cloud
            .script_settings(token, account_id, &resources.script)
            .await
            .map_err(problem)?;
        normalized_settings(&raw["result"], &resources.namespace)
    }

    async fn read_upgrade_schedules(
        &self,
        token: &str,
        account_id: &str,
        resources: &Resources,
    ) -> Result<Value, String> {
        normalized_schedules(
            &self
                .cloud
                .schedules(token, account_id, &resources.script)
                .await
                .map_err(problem)?,
        )
    }

    pub(super) async fn apply_worker_upgrade(
        &mut self,
        account_id: &str,
        target_hash: &str,
    ) -> Result<(), String> {
        self.require_upgrade_start(account_id)?;
        if target_hash != bundled_source_hash() {
            return Err("应用目标版本已变化，请重新准备升级计划".into());
        }
        let resources = self
            .account(account_id)?
            .resources
            .clone()
            .ok_or("账户资源未登记")?;
        let token = Zeroizing::new(keyring_get(account_id, "token")?);
        self.verify_resource_source(&token, account_id, &resources)
            .await?;
        let manifest = self
            .read_upgrade_manifest(&token, account_id, &resources)
            .await?;
        let settings = self
            .read_upgrade_settings(&token, account_id, &resources)
            .await?;
        let schedules = self
            .read_upgrade_schedules(&token, account_id, &resources)
            .await?;
        let source = self
            .cloud
            .script_content(&token, account_id, &resources.script)
            .await
            .map_err(problem)?;
        let previous_hash = hex::encode(Sha256::digest(source));
        if manifest["sourceHash"] != previous_hash {
            return Err("Worker 与清单已变化，停止升级".into());
        }
        if previous_hash == target_hash {
            return Ok(());
        }
        // Re-read the complete preflight immediately before creating durable
        // intent. This detects changes between independent discovery requests.
        if self
            .read_upgrade_manifest(&token, account_id, &resources)
            .await?
            != manifest
            || self
                .read_upgrade_settings(&token, account_id, &resources)
                .await?
                != settings
            || self
                .read_upgrade_schedules(&token, account_id, &resources)
                .await?
                != schedules
        {
            return Err("Worker 设置、计划任务或清单已变化，停止升级".into());
        }
        let latest_source = self
            .cloud
            .script_content(&token, account_id, &resources.script)
            .await
            .map_err(problem)?;
        if hex::encode(Sha256::digest(latest_source)) != previous_hash {
            return Err("Worker 源码在预检期间变化，停止升级".into());
        }
        let journal = format!("升级 Worker {} ({})", account_id, random_id());
        self.persist_rotation_mutation(|db| {
            db.pending_operations.push(journal.clone());
            db.pending_worker_upgrades.push(PendingWorkerUpgrade {
                account_id: account_id.into(),
                resources: resources.clone(),
                previous_hash,
                target_hash: target_hash.into(),
                manifest,
                settings: settings.clone(),
                schedules,
                journal,
                phase: WorkerUpgradePhase::Prepared,
            });
            Ok(())
        })?;
        if let Err(error) = self
            .cloud
            .upload_worker_upgrade(
                &token,
                account_id,
                &resources.script,
                &resources.namespace,
                &settings,
            )
            .await
        {
            self.upgrade_note(
                account_id,
                if error.uncertain {
                    WorkerUpgradePhase::UploadUncertain
                } else {
                    WorkerUpgradePhase::Prepared
                },
                "上传未确认；请从待处理操作核对，禁止重复上传",
            )?;
            return Err(error.message);
        }
        self.resume_worker_upgrade(account_id).await
    }

    pub(super) async fn resume_worker_upgrade(&mut self, account_id: &str) -> Result<(), String> {
        self.require_credentials(account_id)?;
        let pending = self.worker_upgrade_pending(account_id)?;
        let token = Zeroizing::new(keyring_get(account_id, "token")?);
        let result = self.finish_worker_upgrade(&pending, &token).await;
        if let Err(error) = &result {
            let phase = self.worker_upgrade_pending(account_id)?.phase;
            self.upgrade_note(
                account_id,
                if phase == WorkerUpgradePhase::ManifestUncertain {
                    phase
                } else {
                    WorkerUpgradePhase::VerificationFailed
                },
                "升级核对尚未完成；保留记录，不重新上传",
            )?;
            return Err(format!(
                "{error}；请从待处理操作核对，必要时明确确认解除本机升级记录"
            ));
        }
        result
    }

    async fn finish_worker_upgrade(
        &mut self,
        p: &PendingWorkerUpgrade,
        token: &str,
    ) -> Result<(), String> {
        let content = self
            .cloud
            .script_content(token, &p.account_id, &p.resources.script)
            .await
            .map_err(problem)?;
        let hash = hex::encode(Sha256::digest(content));
        if hash != p.previous_hash && hash != p.target_hash {
            return Err("Worker 为未知外部版本，禁止任何云端写入；请人工核对后使用解除本机升级记录，再按现有流程找回或重建".into());
        }
        if hash == p.previous_hash {
            // A stale content read, including after a crash or a confirmed
            // resume, cannot prove an upload never took effect. Only a separate
            // explicit local dismissal may abandon this recovery record.
            return Err("当前仍读取到旧版本，可能尚未同步或上传尚未完成；保留升级记录，请稍后确认恢复计划核对，尚未写入资源清单；结束记录需单独确认本机解除计划".into());
        }
        let manifest = self
            .read_upgrade_manifest(token, &p.account_id, &p.resources)
            .await?;
        let settings = self
            .read_upgrade_settings(token, &p.account_id, &p.resources)
            .await?;
        let schedules = self
            .read_upgrade_schedules(token, &p.account_id, &p.resources)
            .await?;
        if schedules != p.schedules {
            return Err("Worker 计划任务已变化，停止修复清单".into());
        }
        let mut target_manifest = p.manifest.clone();
        target_manifest["sourceHash"] = json!(p.target_hash);
        if manifest != p.manifest && manifest != target_manifest {
            return Err("资源清单已被外部修改，停止修复".into());
        }
        // Missing secret bindings have an explicit safe terminal state. No
        // secret is read or recreated here; existing repair flows handle them.
        let mut without_bindings = settings.clone();
        without_bindings["bindings"] = p.settings["bindings"].clone();
        if without_bindings != p.settings {
            return Err("Worker 非秘密设置已变化，停止修复清单".into());
        }
        let original = p.settings["bindings"]
            .as_array()
            .ok_or("升级绑定快照无效")?;
        let actual = settings["bindings"].as_array().ok_or("升级绑定快照无效")?;
        if actual.iter().any(|v| !original.contains(v))
            || original
                .iter()
                .filter(|v| !actual.contains(v))
                .any(|v| v["type"] != "secret_text")
        {
            return Err("Worker 绑定已变化，停止修复清单".into());
        }
        let missing_selftest = original
            .iter()
            .any(|v| v["name"] == "SELFTEST_KEY" && !actual.contains(v));
        let missing_probe = original
            .iter()
            .any(|v| v["name"] == "PROBE_KEY" && !actual.contains(v));
        if manifest != target_manifest {
            self.upgrade_note(
                &p.account_id,
                WorkerUpgradePhase::ManifestUncertain,
                "目标脚本已核对，正在修复资源清单",
            )?;
            self.cloud
                .write_value(
                    token,
                    &p.account_id,
                    &p.resources.namespace,
                    MANIFEST_KEY,
                    &target_manifest.to_string(),
                )
                .await
                .map_err(problem)?;
        }
        if self
            .read_upgrade_manifest(token, &p.account_id, &p.resources)
            .await?
            != target_manifest
        {
            return Err("资源清单写后核对失败".into());
        }
        self.persist_rotation_mutation(|db| {
            let account = db
                .accounts
                .iter_mut()
                .find(|a| a.id == p.account_id)
                .ok_or("账户不存在")?;
            account.needs_selftest_key |= missing_selftest;
            account.needs_monitor_key |= missing_probe;
            db.pending_worker_upgrades
                .retain(|v| v.account_id != p.account_id);
            clear_journal(&mut db.pending_operations, &p.journal)
        })
    }
}
