import type { FormEvent, RefObject } from "react";
import type { Domain, Pool } from "./types";
import { FieldError, fieldProps, type FieldErrors } from "./FormFeedback";

export type LinkDraft = {
  domainId: string;
  slug: string;
  cnUrl: string;
  defaultUrl: string;
  poolId: string;
  code: string;
};

type Props = {
  linkDraft: LinkDraft;
  originalSlug: string | null;
  copySource: { domainId: string; slug: string } | null;
  domains: Domain[];
  pools: Pool[];
  busy: boolean;
  formErrors: FieldErrors;
  slugInput: RefObject<HTMLInputElement | null>;
  saveLink: (event: FormEvent) => Promise<void>;
  updateLinkDraft: (fields: Partial<LinkDraft>) => void;
  useNewLinkName: () => void;
};

// The draft and asynchronous lifecycle stay in App; this component owns the form.
export default function LinkEditor({ linkDraft, originalSlug, copySource, domains, pools, busy, formErrors, slugInput, saveLink, updateLinkDraft, useNewLinkName }: Props) {
  return (
          <form
            noValidate
            id="link-form"
            onSubmit={(e) => void saveLink(e)}
            className="form-grid"
          >
            <label>
              所属域名
              <select
                {...fieldProps("link-domain", formErrors)}
                value={linkDraft.domainId}
                onChange={(e) => updateLinkDraft({ domainId: e.target.value })}
                disabled={Boolean(originalSlug)}
                required
              >
                {domains.map((d) => (
                  <option value={d.id} key={d.id}>
                    {d.host} /{d.prefix}/
                  </option>
                ))}
              </select>
                <FieldError name="link-domain" errors={formErrors} />
            </label>
            <label>
              短链接名称
              <input
                {...fieldProps("link-slug", formErrors)}
                ref={slugInput}
                value={linkDraft.slug}
                onChange={(e) => updateLinkDraft({ slug: originalSlug ? e.target.value : e.target.value.toLowerCase() })}
                placeholder="例如 welcome"
                maxLength={32}
                required
                disabled={Boolean(originalSlug)}
              />
                <FieldError name="link-slug" errors={formErrors} />
              <small>
                它是网址最后一段，例如
                /welcome；可用字母、数字、下划线或连字符。新名称自动转为小写，旧链接名称保持原样。
              </small>
            </label>
            {originalSlug && (
              <div className="form-note">
                <p>名称是网址的一部分。需要新名称时，可以带上当前设置创建新链接，旧链接继续保留。</p>
                <button
                  type="button"
                  className="button secondary"
                  disabled={busy}
                  onClick={useNewLinkName}
                >
                  换一个名称
                </button>
              </div>
            )}
            {copySource && (
              <div className="form-note" role="status">
                <strong>旧链接 /{copySource.slug} 会继续保留</strong>
                <p>跳转设置和邀请码已带入。这次填写的内容只用于新链接；新地址确认可用后，可以按需删除旧链接。</p>
              </div>
            )}
            <div className="form-divider" />
            <div className="mode-switch" role="group" aria-label="地址来源">
              <button
                type="button"
                className={!linkDraft.poolId ? "selected" : ""}
                aria-pressed={!linkDraft.poolId}
                onClick={() => updateLinkDraft({ poolId: "" })}
              >
                手动填写
              </button>
              <button
                type="button"
                className={linkDraft.poolId ? "selected" : ""}
                aria-pressed={Boolean(linkDraft.poolId)}
                disabled={!pools?.length}
                onClick={() =>
                  updateLinkDraft({
                    poolId: linkDraft.poolId || pools?.[0]?.id || "",
                  })
                }
              >
                平台地址
              </button>
            </div>
            {!pools?.length && (
              <p className="form-note">
                如需使用平台地址，请先到「平台地址」添加一组地址。
              </p>
            )}
            {linkDraft.poolId ? (
              <>
                <label>
                  平台地址
                  <select
                    {...fieldProps("link-pool", formErrors)}
                value={linkDraft.poolId}
                    onChange={(e) => updateLinkDraft({ poolId: e.target.value })}
                  >
                    {(pools || []).map((pool) => (
                      <option key={pool.id} value={pool.id}>
                        {pool.name}
                      </option>
                    ))}
                  </select>
                <FieldError name="link-pool" errors={formErrors} />
                </label>
                <label>
                  此链接的邀请码
                  <input
                    {...fieldProps("link-code", formErrors)}
                value={linkDraft.code}
                    onChange={(e) => updateLinkDraft({ code: e.target.value })}
                    maxLength={128}
                    placeholder="例如 member_01"
                    required
                  />
                <FieldError name="link-code" errors={formErrors} />
                </label>
                <p className="form-note">
                  创建时会自动把所需平台配置同步到所选域名的账户；这条链接保留自己的邀请码。更改平台链接后，已关联短链接会一起更新。
                </p>
              </>
            ) : (
              <>
                <label>
                  中国大陆打开的网址
                  <input
                    type="url"
                    {...fieldProps("link-cn", formErrors)}
                value={linkDraft.cnUrl}
                    onChange={(e) => updateLinkDraft({ cnUrl: e.target.value })}
                    placeholder="https://example.com/zh"
                    required
                  />
                <FieldError name="link-cn" errors={formErrors} />
                </label>
                <label>
                  其他地区打开的网址
                  <input
                    type="url"
                    {...fieldProps("link-default", formErrors)}
                value={linkDraft.defaultUrl}
                    onChange={(e) => updateLinkDraft({ defaultUrl: e.target.value })}
                    placeholder="https://example.com/en"
                    required
                  />
                <FieldError name="link-default" errors={formErrors} />
                </label>
              </>
            )}
            <p className="form-note">保存前先核对网址和修改范围。</p>
          </form>
  );
}
