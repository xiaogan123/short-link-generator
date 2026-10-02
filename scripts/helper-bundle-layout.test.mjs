import assert from 'node:assert/strict';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

test('Tauri custom-file destination keys place the staged helper inside Contents/XPCServices', t => {
  const config = JSON.parse(readFileSync(new URL('../src-tauri/tauri.conf.json', import.meta.url)));
  const root = mkdtempSync(join(tmpdir(), 'slg-helper-layout-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const tauriRoot = join(root, 'project', 'src-tauri');
  const source = join(root, 'project', '_private', 'credential-helper-stage', 'credential-helper.xpc');
  const contents = join(root, 'built.app', 'Contents');
  mkdirSync(tauriRoot, { recursive: true });
  mkdirSync(source, { recursive: true });
  mkdirSync(contents, { recursive: true });
  writeFileSync(join(source, 'layout.fixture'), 'staged helper bytes');

  // Tauri CLI 2.12.0 app.rs copy_custom_files_to_bundle uses (contents_path, path):
  // each key is the bundle destination and each value is the source path.
  for (const [contentsPath, sourcePath] of Object.entries(config.bundle.macOS.files)) {
    const destination = resolve(contents, contentsPath);
    assert.equal(destination, join(contents, 'XPCServices', 'credential-helper.xpc'));
    mkdirSync(join(contents, 'XPCServices'), { recursive: true });
    cpSync(resolve(tauriRoot, sourcePath), destination, { recursive: true });
  }
  assert.equal(readFileSync(join(contents, 'XPCServices', 'credential-helper.xpc', 'layout.fixture'), 'utf8'),
    'staged helper bytes');
});
