# Desktop design QA

final result: passed

Scope: the approved desktop design direction and locally exercised interface states. This is not cloud, operating-system compatibility or release approval.

## Evidence and comparison

The source is the privately supplied desktop dashboard screenshot. Its actual path and image are deliberately excluded from this public repository under the project privacy rule. The private evidence manifest records the exact source and capture locations.

Source image: 3840×1984 physical pixels, including browser chrome. The likely desktop CSS size is about half that; that density is an inference, not measured page metadata. The final implementation was inspected at 1180×780 CSS pixels and the minimum 840×600 window. Browser captures exclude scrollbar/host-frame edges (approximately 1165×770 and 825×589 image pixels). Source and implementation were presented in the same comparison input; no pixel-perfect claim is made between different window sizes and changed product data. A wide-viewport stitched browser capture was unreliable and excluded from the acceptance evidence.

Full-view evidence: private captures `links-1180-latest.jpg`, `pools-1180-final.png`, `accounts-1180-final.png`. Focused evidence: `pool-editor-1180.png`, `pool-editor-840.png`, `monitor-1180-final.png`, `detection-1180-final.jpg`. All captured app data uses neutral example domains; no screenshot is bundled in the repository.

## Findings closed

- Pool-plan Back initially discarded the draft. The editor now keeps its values until successful application. Browser recheck confirmed the changed prefix survived Back and the plan displayed both candidate addresses and the affected link count.
- Monitor secret copy could imply that the credential never leaves the machine. The displayed note now explains system credential storage and Worker storage after confirmation, without exposing the value.
- Stale health and late responses could retain obsolete green/red status. Timestamp and configuration-generation checks were added, with UI regression fixtures; this issue is also covered by the separate code audit.

## Required visual surfaces

- Typography: Chinese serif display headings, compact system sans-serif body text, uppercase spaced section labels and bold primary actions preserve the source hierarchy. Native fonts avoid external font requests. Dense URLs truncate where appropriate and remain available in the editor/details.
- Layout: evergreen sidebar, warm canvas, thin bordered metrics, full-width explanation band and rounded table panel retain the source structure. The desktop app deliberately uses four task pages and three counters. At the minimum window size, content scrolls and dialog footers remain visible and clickable; no horizontal page overflow was observed.
- Color: green primary actions and muted neutral surfaces follow the reference. Red failure, amber uncertainty and gray untested/expired status also use visible text, so color is not the sole signal.
- Assets: Phosphor icons remain sharp at desktop sizes; the app icon uses the same library. No photographic or illustrative assets were required. The original screenshot, its content and its branding were not copied.
- Copy: original neutral Chinese UI labels describe accounts, domains, pools and targets. Preview state is visibly identified. Detection separates redirect correctness from target access and labels its direct local source and time. Target checks bypass system proxies for DNS pinning; the interface explains that distinction. Local success is not presented as a mainland availability guarantee.

## Interaction evidence

Browser checks exercised navigation, new pool with multiple candidates, pool-backed link with a separate code, plan review/back, pool-prefix editing, disabled deletion while referenced, unknown provider status, target-result dialog and row status, and monitor configuration/cancel. Browser console inspection returned no warnings or errors for the exercised states. Automated UI fixtures separately exercise definite failure, uncertainty, local success, expiry and stale-response ordering.

Remaining validation is outside this visual result: native Windows/Intel rendering, real credential storage, live cloud propagation, actual regional monitoring and signed update installation. Those must be reported separately rather than inferred from preview screenshots.
