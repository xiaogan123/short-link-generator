export type Account = { id: string; label: string; zoneCount: number; checkedAt: string | null; hasResources: boolean; needsSelftestKey: boolean; needsMonitorKey?:boolean; monitorEnabled?: boolean; monitorEndpoint?: string };
export type Domain = { id: string; accountId: string; zoneId: string; host: string; prefix: string; routeId: string };
export type Link = { domainId: string; slug: string; cnUrl: string; defaultUrl: string; updated: string; poolId?: string; code?: string };
export type PendingAction = {kind:'resume_pool_sync'|'delete_pool'|'resume_monitor';poolId:string|null;accountId:string|null;label:string};
export type State = { accounts: Account[]; domains: Domain[]; links: Link[]; pendingOperations: string[]; pendingActions:PendingAction[]; pools?: Pool[] };
export type Plan = { id: string; title: string; steps: string[]; warnings: string[]; expiresAt: string; domainTakeoverConfirmation?: string };
export type Check = { label: string; ok: boolean; message: string };
export type DomainCheck = Check & { level?: 'pass' | 'warning' | 'error' };
export type DomainPreparation = { host: string; prefix: string; candidates: { accountId: string; label: string; zoneId: string; status: string }[]; checks: DomainCheck[]; canApply: boolean; plan?: Plan };
export type Selftest = { status: 'passed' | 'pending' | 'failed' | 'key_missing'; message: string; checks: Check[] };
export type UpdateStatus = { status: 'unavailable' | 'up_to_date' | 'available'; version?: string; notes?: string };
export type Action = 'get_state' | 'token_template' | 'import_token' | 'rename_account' | 'remove_account' | 'refresh_accounts' | 'prepare_domain' | 'prepare_change' | 'apply_plan' | 'selftest_link' | 'export_config' | 'import_config' | 'check_update' | 'install_update' | 'prepare_monitor' | 'disable_monitor' | 'resume_monitor' | 'check_link_targets' | 'check_pool_health';

export type TargetTemplate = {prefix:string;suffix:string};
export type PoolCandidate = TargetTemplate & {id:string;enabled:boolean};
export type Pool = {id:string;name:string;official:TargetTemplate;candidates:PoolCandidate[];updated:string;accountIds:string[];syncStatus?:{accountId:string;status:string;message:string}[]};
export type TargetReport = {checkedAt:string;checks:{label:string;status:'passed'|'failed'|'unknown';message:string;checkedAt:string;source:'local';url:string}[]};
export type PoolHealth = {poolId:string;accounts:{accountId:string;source:'mainland_provider'|'unconfigured'|'unknown';checkedAt:string|null;status:'healthy'|'unhealthy'|'unknown';candidates:{id:string;status:'healthy'|'unhealthy'|'unknown';checkedAt:string|null;message:string}[]}[]};
