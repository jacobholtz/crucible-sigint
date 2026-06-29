// Paste this entire block into your browser DevTools Console while on
// http://localhost:8000/ — it reads the API keys you have in localStorage,
// formats them as a .env file, and triggers a download. Drop the
// downloaded .env at the project root and restart the server.
(() => {
  const map = {
    shodan:      'SHODAN_API_KEY',
    virustotal:  'VIRUSTOTAL_API_KEY',
    otx:         'ALIENVAULT_API_KEY',
    abusech:     'ABUSECH_API_KEY',
    censys:      'CENSYS_API_KEY_RAW',
    certspotter: 'CERTSPOTTER_API_KEY',
    urlscan:     'URLSCAN_API_KEY',
    spyonweb:    'SPYONWEB_API_KEY',
  };
  let out = '# Crucible .env — generated from browser localStorage on '
          + new Date().toISOString() + '\n';
  for (const [svc, env] of Object.entries(map)) {
    const v = localStorage.getItem('api_' + svc) || '';
    if (!v) continue;
    if (env === 'CENSYS_API_KEY_RAW' && v.includes(':')) {
      const [id, sec] = v.split(':', 2);
      out += 'CENSYS_API_ID='    + id  + '\n';
      out += 'CENSYS_API_SECRET=' + sec + '\n';
    } else if (env !== 'CENSYS_API_KEY_RAW') {
      out += env + '=' + v + '\n';
    }
  }
  console.log('Generated:\n' + out);
  const blob = new Blob([out], { type: 'text/plain' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = '.env';
  a.click();
  URL.revokeObjectURL(a.href);
})();
