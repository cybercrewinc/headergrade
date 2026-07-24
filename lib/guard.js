const dns = require('dns').promises;
const net = require('net');

function isPrivateIp(ip) {
  if (net.isIPv6(ip)) {
    const low = ip.toLowerCase();
    return low === '::1' || low.startsWith('fc') || low.startsWith('fd') || low.startsWith('fe80');
  }
  const parts = ip.split('.').map(Number);
  const [a, b] = parts;
  return (
    a === 10 ||
    a === 127 ||
    a === 0 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254)
  );
}

// Rejects hostnames that resolve to private / loopback / link-local ranges so
// the scanner can't be used to probe internal infrastructure (SSRF).
async function assertPublicHost(hostname) {
  if (net.isIP(hostname)) {
    if (isPrivateIp(hostname)) throw new Error('Refusing to scan private or internal addresses.');
    return;
  }
  const results = await dns.lookup(hostname, { all: true });
  for (const r of results) {
    if (isPrivateIp(r.address)) throw new Error('Refusing to scan private or internal addresses.');
  }
}

module.exports = { isPrivateIp, assertPublicHost };
