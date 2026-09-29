# Desktop UI design

The interface retains an evergreen sidebar and warm off-white canvas. This is a daily management tool: short page titles, compact summaries and clear actions give working data priority over decorative slogans. System fonts and Phosphor icons avoid remote asset requests.

## Navigation and workflows

- **短链接** groups links by domain. Search and domain filtering stay close to the list. Copy, check and edit actions use visible Chinese labels. Forms use concrete terms such as 邀请码 and 跳转网址.
- **平台地址** keeps one other-region address and several mainland backup addresses together. Links reference the platform and retain their individual invitation codes. Editing an address updates associated links after cloud propagation. Forms distinguish the part before the invitation code from optional trailing parameters.
- **域名管理** shows ownership and link counts. Adding a domain checks existing configuration and asks the user to confirm the exact scope before making changes. The bare host and `www` remain separate.
- **Cloudflare 账户** handles API token import, local names, backups and account-level service settings. Destructive cloud cleanup remains separate from local removal.
- **更新** is checked on request. An unconfigured channel is explicitly unavailable; an available update requires confirmation before installation.

## States and accessibility

Definite failures use red plus text, inconclusive results amber, and untested or stale results gray. Each check retains its source and time. Local checks do not imply mainland accessibility. Detailed technical explanations belong next to the relevant result or inside an expandable section.

Dialogs keep keyboard focus inside, restore focus on close, and provide visible labels. Destructive actions explain whether they affect local records, individual cloud records, or shared services. Empty, pending, loading and error states must each give a useful next action.

The target window range starts at 840×600, with the standard desktop window at 1120×760. Long addresses and dense forms must remain readable through wrapping and internal scrolling. Browser previews use visibly marked neutral data and never cloud writes. Native verification is separate from browser layout testing.

## Preserved behavior

Remote writes still pass through backend preparation followed by explicit confirmation. The UI presents the exact affected domain, addresses and accounts. Saving a link begins its check; unknown or stale results cannot appear as success. Changes remain compatible with existing local configuration, with no routing or storage migration in this UI revision.
