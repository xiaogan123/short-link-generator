// Parse the load-command boundaries emitted by `otool -l` for one thin Mach-O.
// A minos value in a different command must never satisfy this check.
const invalid = () => new Error('Credential helper requires one macOS 11.0 LC_BUILD_VERSION command.');
const version = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:\.(0|[1-9][0-9]*))?$/;

export function requireMacOS11BuildVersion(output) {
  if (typeof output !== 'string' || !output.length || output.length > 1024 * 1024 ||
      output.includes('\0') || (output.match(/\bLC_BUILD_VERSION\b/g) ?? []).length !== 1 ||
      /\bLC_VERSION_MIN_MACOSX\b/.test(output)) throw invalid();
  const blocks = [];
  let current;
  for (const line of output.split(/\r?\n/)) {
    const header = /^Load command (0|[1-9][0-9]*)$/.exec(line);
    if (header) {
      if (Number(header[1]) !== blocks.length) throw invalid();
      current = [];
      blocks.push(current);
    } else if (current) current.push(line.trim());
    else if (line.includes('LC_BUILD_VERSION')) throw invalid();
  }
  const build = blocks.filter(block => block.some(line => line === 'cmd LC_BUILD_VERSION'));
  if (build.length !== 1) {
    throw invalid();
  }
  const lines = build[0].filter(Boolean);
  if (lines.length < 6 || lines[0] !== 'cmd LC_BUILD_VERSION') throw invalid();
  const commandSize = /^cmdsize (0|[1-9][0-9]*)$/.exec(lines[1]);
  const platform = /^platform (0|[1-9][0-9]*)$/.exec(lines[2]);
  const minimum = /^minos (\S+)$/.exec(lines[3]);
  const sdk = /^sdk (\S+)$/.exec(lines[4]);
  const tools = /^ntools (0|[1-9][0-9]*)$/.exec(lines[5]);
  if (!commandSize || !platform || !minimum || !sdk || !tools ||
      !version.test(sdk[1]) || !version.test(minimum[1])) throw invalid();
  const min = version.exec(minimum[1]);
  const count = Number(tools[1]);
  if (platform[1] !== '1' || min[1] !== '11' || min[2] !== '0' ||
      Number(min[3] ?? '0') !== 0 || !Number.isSafeInteger(count) || count > 32 ||
      Number(commandSize[1]) !== 24 + 8 * count || lines.length !== 6 + 2 * count) throw invalid();
  for (let index = 0; index < count; index++) {
    const tool = /^tool (0|[1-9][0-9]*)$/.exec(lines[6 + 2 * index]);
    const toolVersion = /^version (\S+)$/.exec(lines[7 + 2 * index]);
    if (!tool || !toolVersion || !version.test(toolVersion[1])) throw invalid();
  }
  return { platform: 'macos', minimumSystemVersion: '11.0.0' };
}
