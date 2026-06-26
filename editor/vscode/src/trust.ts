// aether — plugin trust UI.
//
// Talks to /v1/trust on a running `aether serve`. Lists trusted
// ed25519 keys, lets the user add (paste hex) or remove (per-row).
// Same bearer auth model as the chat panel.

import * as vscode from 'vscode';

function getConfig() {
    const cfg = vscode.workspace.getConfiguration('aether');
    return {
        // Derive the /v1/trust URL from the same serveUrl setting we use
        // for the chat panel. We accept either an http(s) base, or a
        // ws(s) URL whose scheme we rewrite.
        serveUrl: cfg.get<string>('serveUrl') || 'ws://127.0.0.1:7777/ws/chat',
        serveToken: cfg.get<string>('serveToken') || '',
    };
}

function trustEndpoint(serveUrl: string): string {
    // ws://host:port/ws/chat → http://host:port/v1/trust
    let base = serveUrl
        .replace(/^ws:\/\//, 'http://')
        .replace(/^wss:\/\//, 'https://');
    const parsed = new URL(base);
    parsed.pathname = '/v1/trust';
    parsed.search = '';
    parsed.hash = '';
    return parsed.toString();
}

async function fetchKeys(): Promise<{ keys: string[]; path: string }> {
    const cfg = getConfig();
    const url = trustEndpoint(cfg.serveUrl);
    const headers: Record<string, string> = {};
    if (cfg.serveToken) headers['Authorization'] = `Bearer ${cfg.serveToken}`;
    const resp = await fetch(url, { method: 'GET', headers });
    if (!resp.ok) {
        const text = await resp.text();
        throw new Error(`GET ${url} → ${resp.status} ${text}`);
    }
    return (await resp.json()) as { keys: string[]; path: string };
}

async function addKey(publicKey: string): Promise<void> {
    const cfg = getConfig();
    const url = trustEndpoint(cfg.serveUrl);
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (cfg.serveToken) headers['Authorization'] = `Bearer ${cfg.serveToken}`;
    const resp = await fetch(url, {
        method: 'POST',
        headers,
        body: JSON.stringify({ public_key: publicKey }),
    });
    if (!resp.ok) {
        const text = await resp.text();
        throw new Error(`POST ${url} → ${resp.status} ${text}`);
    }
}

async function removeKey(prefix: string): Promise<void> {
    const cfg = getConfig();
    const url = trustEndpoint(cfg.serveUrl);
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (cfg.serveToken) headers['Authorization'] = `Bearer ${cfg.serveToken}`;
    const resp = await fetch(url, {
        method: 'DELETE',
        headers,
        body: JSON.stringify({ prefix }),
    });
    if (!resp.ok) {
        const text = await resp.text();
        throw new Error(`DELETE ${url} → ${resp.status} ${text}`);
    }
}

export function showTrustPanel(context: vscode.ExtensionContext): void {
    const panel = vscode.window.createWebviewPanel(
        'aetherTrust',
        'Aether — Plugin Trust',
        vscode.ViewColumn.Active,
        { enableScripts: true, retainContextWhenHidden: false },
    );
    panel.webview.html = html(panel.webview);

    const refresh = async () => {
        try {
            const data = await fetchKeys();
            panel.webview.postMessage({ type: 'keys', keys: data.keys, path: data.path });
        } catch (e: any) {
            panel.webview.postMessage({ type: 'error', message: String(e?.message ?? e) });
        }
    };

    panel.webview.onDidReceiveMessage(async (msg: any) => {
        switch (msg.type) {
            case 'init':
                await refresh();
                break;
            case 'add':
                try {
                    await addKey(String(msg.key));
                    await refresh();
                } catch (e: any) {
                    panel.webview.postMessage({ type: 'error', message: String(e?.message ?? e) });
                }
                break;
            case 'remove':
                try {
                    await removeKey(String(msg.prefix));
                    await refresh();
                } catch (e: any) {
                    panel.webview.postMessage({ type: 'error', message: String(e?.message ?? e) });
                }
                break;
        }
    });
}

function html(webview: vscode.Webview): string {
    const csp = [
        "default-src 'none'",
        `style-src ${webview.cspSource} 'unsafe-inline'`,
        `script-src ${webview.cspSource} 'unsafe-inline'`,
    ].join('; ');
    return /* html */ `<!doctype html>
<html><head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="${csp}">
<style>
  body { font-family: var(--vscode-font-family); padding: 1em; color: var(--vscode-foreground); }
  h1 { font-size: 1.2em; margin-top: 0; }
  .path { color: var(--vscode-descriptionForeground); font-size: 0.9em; margin-bottom: 1em; }
  ul { list-style: none; padding: 0; }
  li { display: flex; align-items: center; gap: 0.5em; padding: 0.4em 0; border-bottom: 1px solid var(--vscode-panel-border); }
  code { flex: 1; font-family: var(--vscode-editor-font-family); word-break: break-all; }
  button { background: var(--vscode-button-background); color: var(--vscode-button-foreground); border: none; padding: 0.3em 0.8em; cursor: pointer; }
  button:hover { background: var(--vscode-button-hoverBackground); }
  .add { display: flex; gap: 0.5em; margin-top: 1em; }
  .add input { flex: 1; background: var(--vscode-input-background); color: var(--vscode-input-foreground); border: 1px solid var(--vscode-input-border); padding: 0.3em; font-family: var(--vscode-editor-font-family); }
  .err { color: var(--vscode-errorForeground); margin: 1em 0; white-space: pre-wrap; }
</style>
</head><body>
<h1>Trusted plugin keys</h1>
<div class="path" id="path"></div>
<ul id="keys"></ul>
<div class="add">
  <input id="newkey" placeholder="ed25519 public key (64 hex chars)">
  <button id="addbtn">Add</button>
</div>
<div class="err" id="err" hidden></div>
<script>
  const vscode = acquireVsCodeApi();
  const ul = document.getElementById('keys');
  const pathEl = document.getElementById('path');
  const errEl = document.getElementById('err');
  const input = document.getElementById('newkey');
  function showError(msg) {
    errEl.textContent = msg || '';
    errEl.hidden = !msg;
  }
  document.getElementById('addbtn').addEventListener('click', () => {
    const k = input.value.trim();
    if (!k) return;
    showError('');
    vscode.postMessage({ type: 'add', key: k });
    input.value = '';
  });
  window.addEventListener('message', (ev) => {
    const m = ev.data;
    if (m.type === 'keys') {
      pathEl.textContent = m.path || '';
      ul.innerHTML = '';
      if (!m.keys || m.keys.length === 0) {
        const li = document.createElement('li');
        li.innerHTML = '<em>no trusted keys</em>';
        ul.appendChild(li);
        return;
      }
      for (const k of m.keys) {
        const li = document.createElement('li');
        const code = document.createElement('code');
        code.textContent = k;
        const btn = document.createElement('button');
        btn.textContent = 'Remove';
        btn.addEventListener('click', () => {
          showError('');
          vscode.postMessage({ type: 'remove', prefix: k });
        });
        li.appendChild(code);
        li.appendChild(btn);
        ul.appendChild(li);
      }
      showError('');
    } else if (m.type === 'error') {
      showError(m.message);
    }
  });
  vscode.postMessage({ type: 'init' });
</script>
</body></html>`;
}
