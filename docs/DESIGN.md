# Desktop UI design

The reference image informed the interface's spatial structure: an evergreen sidebar, warm ivory canvas, small uppercase section labels, a serif Chinese headline, thin dividers, and restrained tables. The implementation uses original text, icons from Phosphor, and no copied screenshot or production data.

## Navigation and workflows

- **短链接** groups links by exact domain. Search covers slug, host, and destinations. A domain filter narrows the table. Creating or editing a link validates the slug and HTTPS targets before requesting a backend plan. Copy uses the system clipboard, and route selftest presents the backend's precise status and checks.
- **地址池** stores shared regional templates and their priority. Links reference the pool and preserve an individual code; changing a pool updates all referencing links. Confirmation states affected accounts and links. Definite target failures are red, inconclusive results amber, and untested or stale results gray. Local target results do not claim mainland reachability.
- **域名** shows domain ownership and the number of links. Adding one starts with backend preflight checks and an explicit candidate choice when ownership is ambiguous. The user sees the returned plan before applying. `www` remains distinct from the bare host.
- **账户** offers a system-browser token template, local rename and removal, and planned recovery, key rotation, and remote cleanup. Clipboard text is inspected only after the token field receives focus and never filled without a separate click. Export/import use native file dialogs.
- **更新** checks only on user request. An available version opens a confirmation dialog before installation; an unconfigured channel is shown as unavailable.

Remote writes pass through `prepare_domain` or `prepare_change`, then `apply_plan`. The backend's plan text and expiry are presented alongside the selected target. Saving a link automatically begins the backend selftest and displays its result. Preview data activates only through `?preview=1`, stays in memory, and is visibly labeled. Ordinary browser launch without that query calls the real Tauri bridge and reports an error if unavailable.

The layout is optimized for 1180×780 and scales down to 960×700. Dialogs trap focus, close with Escape, and restore focus to the invoking element. Empty, loading, pending, failure, and success states have distinct copy. System font stacks avoid network font requests.
