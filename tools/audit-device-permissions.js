'use strict';
// Read-only audit of MARÈIA devices.json. Reports aggregate counts only.
// No names, IDs, tokens, hashes, paths or personal information are printed.
const fs = require('node:fs');

function auditDevices(data, at = Date.now()) {
  if (!data || typeof data !== 'object' || !Array.isArray(data.devices)) {
    throw new Error('invalid_device_store');
  }
  const summary = {
    total: data.devices.length,
    active: 0,
    revoked: 0,
    expired: 0,
    unknown_expiry: 0,
    active_pc_action: 0,
    active_wildcard: 0,
    potentially_privileged_unknown_expiry: 0,
    malformed_entries: 0,
  };
  for (const d of data.devices) {
    if (!d || typeof d !== 'object' || Array.isArray(d)) {
      summary.malformed_entries++;
      continue;
    }
    if (d.revoked_at) {
      if (typeof d.revoked_at === 'string' && Number.isFinite(Date.parse(d.revoked_at))) {
        summary.revoked++;
        continue;
      }
      // Invalid revocation markers must not mask potentially active privileges.
      summary.malformed_entries++;
    }
    const expires = typeof d.expires_at === 'string' ? Date.parse(d.expires_at) : NaN;
    const validPermissions = Array.isArray(d.permissions) &&
      d.permissions.every(p => typeof p === 'string' && p.trim().length > 0);
    if (!validPermissions) summary.malformed_entries++;
    const permissions = validPermissions ? d.permissions : [];
    const wildcard = permissions.includes('*');
    const pcAction = permissions.includes('pc:action');
    if (!Number.isFinite(expires)) {
      summary.unknown_expiry++;
      if (wildcard || pcAction) summary.potentially_privileged_unknown_expiry++;
      continue;
    }
    if (expires <= at) { summary.expired++; continue; }
    summary.active++;
    if (wildcard) summary.active_wildcard++;
    if (pcAction) summary.active_pc_action++;
  }
  const riskCount = summary.active_pc_action + summary.active_wildcard +
    summary.unknown_expiry + summary.malformed_entries;
  return { ...summary, needs_manual_review: riskCount > 0 };
}

function main(argv = process.argv.slice(2)) {
  if (argv.length !== 1 || !argv[0] || argv[0].startsWith('-')) {
    process.stderr.write('Usage: node audit-device-permissions.js <path-to-devices.json>\n');
    return 1;
  }
  try {
    const stats = fs.statSync(argv[0]);
    if (!stats.isFile() || stats.size > 10 * 1024 * 1024) throw new Error('invalid_input_file');
    const report = auditDevices(JSON.parse(fs.readFileSync(argv[0], 'utf8')));
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    return report.needs_manual_review ? 2 : 0;
  } catch {
    process.stderr.write('Audit failed: invalid or inaccessible device store (no data disclosed).\n');
    return 1;
  }
}
if (require.main === module) process.exitCode = main();
module.exports = { auditDevices, main };
