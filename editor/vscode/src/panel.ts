// aether chat webview panel.
//
// Renders an HTML page in a VS Code webview that opens a WebSocket to
// `aether serve` and streams agent text deltas into a chat history.
//
// The panel is OPENED via the `aether.openChat` command. The user must
// have `aether serve --bind 127.0.0.1:7777` (or wherever `aether.serveUrl`
// points) running separately — the extension does NOT spawn the server
// for v0.17 to keep lifecycle simple. Click "Reconnect" if the server
// restarts.

import * as vscode from 'vscode';

let currentPanel: vscode.WebviewPanel | undefined;

export function showChatPanel(context: vscode.ExtensionContext): void {
    if (currentPanel) {
        currentPanel.reveal(vscode.ViewColumn.Beside);
        return;
    }

    currentPanel = vscode.window.createWebviewPanel(
        'aetherChat',
        'aether chat',
        vscode.ViewColumn.Beside,
        {
            enableScripts: true,
            retainContextWhenHidden: true,
        },
    );

    currentPanel.webview.html = renderHtml();

    currentPanel.onDidDispose(
        () => {
            currentPanel = undefined;
        },
        null,
        context.subscriptions,
    );

    // Bidirectional messaging: the webview sends "config-request" on
    // load, and the extension responds with the current settings so
    // the webview can connect to the right URL with the right token.
    currentPanel.webview.onDidReceiveMessage(
        (msg: { type: string; [k: string]: unknown }) => {
            switch (msg.type) {
                case 'config-request': {
                    const cfg = vscode.workspace.getConfiguration('aether');
                    currentPanel?.webview.postMessage({
                        type: 'config',
                        serveUrl: cfg.get<string>('serveUrl'),
                        serveToken: cfg.get<string>('serveToken'),
                        model: cfg.get<string>('model'),
                    });
                    break;
                }
                case 'log': {
                    // Useful for debugging — surfaced in the output channel
                    // if the extension wants to capture it. Currently no-op.
                    break;
                }
            }
        },
        undefined,
        context.subscriptions,
    );
}

/// The HTML+JS payload rendered inside the webview. Minimal vanilla
/// JS — markdown-it loaded from a CDN inside the webview's strict CSP
/// (we add `'unsafe-inline'` for scripts because we inline our handler,
/// and an explicit cdn host for the markdown-it script).
function renderHtml(): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline' https://cdn.jsdelivr.net; connect-src ws: wss:;">
<title>aether chat</title>
<style>
:root {
    color-scheme: light dark;
    --bg: var(--vscode-editor-background);
    --fg: var(--vscode-editor-foreground);
    --accent: var(--vscode-textLink-foreground);
    --user-bg: var(--vscode-input-background);
    --agent-bg: var(--vscode-editor-inactiveSelectionBackground);
    --muted: var(--vscode-descriptionForeground);
}
body { margin: 0; padding: 0; background: var(--bg); color: var(--fg); font-family: var(--vscode-font-family); font-size: 13px; }
#wrap { display: flex; flex-direction: column; height: 100vh; }
#history { flex: 1; overflow-y: auto; padding: 12px; }
.turn { margin-bottom: 12px; padding: 8px 12px; border-radius: 4px; }
.turn.user { background: var(--user-bg); }
.turn.agent { background: var(--agent-bg); }
.turn.system { color: var(--muted); font-style: italic; font-size: 12px; padding: 4px 12px; }
.role { font-weight: 600; font-size: 11px; color: var(--muted); margin-bottom: 4px; text-transform: uppercase; letter-spacing: 0.04em; }
pre { background: var(--vscode-textBlockQuote-background); padding: 8px; border-radius: 3px; overflow-x: auto; font-family: var(--vscode-editor-font-family); }
code { font-family: var(--vscode-editor-font-family); }
#input-bar { display: flex; gap: 6px; padding: 8px; border-top: 1px solid var(--vscode-input-border, transparent); background: var(--bg); }
#prompt { flex: 1; padding: 6px 8px; background: var(--vscode-input-background); color: var(--vscode-input-foreground); border: 1px solid var(--vscode-input-border, transparent); border-radius: 3px; font-family: inherit; font-size: inherit; resize: none; }
button { padding: 6px 10px; background: var(--vscode-button-background); color: var(--vscode-button-foreground); border: none; border-radius: 3px; cursor: pointer; font-family: inherit; font-size: inherit; }
button:hover { background: var(--vscode-button-hoverBackground); }
button:disabled { opacity: 0.5; cursor: not-allowed; }
#status { padding: 4px 12px; font-size: 11px; color: var(--muted); border-top: 1px solid var(--vscode-input-border, transparent); }
.disconnected { color: var(--vscode-errorForeground); }
.connected { color: var(--vscode-charts-green); }
</style>
</head>
<body>
<div id="wrap">
    <div id="history"></div>
    <div id="status">connecting…</div>
    <div id="input-bar">
        <textarea id="prompt" rows="2" placeholder="Message aether… (Cmd+Enter to send)"></textarea>
        <button id="send" disabled>Send</button>
        <button id="reconnect">Reconnect</button>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/markdown-it@14.1.0/dist/markdown-it.min.js"></script>
<script>
const vscode = acquireVsCodeApi();
const md = window.markdownit({ html: false, breaks: true, linkify: true });

const history = document.getElementById('history');
const status = document.getElementById('status');
const prompt = document.getElementById('prompt');
const sendBtn = document.getElementById('send');
const reconnectBtn = document.getElementById('reconnect');

let ws = null;
let cfg = null;
let currentAgentDiv = null;
let currentAgentMarkdown = '';
let inFlight = false;

function setStatus(text, klass) {
    status.textContent = text;
    status.className = klass || '';
}

function appendTurn(role, text) {
    const div = document.createElement('div');
    div.className = 'turn ' + role;
    const roleSpan = document.createElement('div');
    roleSpan.className = 'role';
    roleSpan.textContent = role;
    div.appendChild(roleSpan);
    const body = document.createElement('div');
    body.innerHTML = md.render(text || '');
    div.appendChild(body);
    history.appendChild(div);
    history.scrollTop = history.scrollHeight;
    return body;
}

function appendSystem(text) {
    const div = document.createElement('div');
    div.className = 'turn system';
    div.textContent = text;
    history.appendChild(div);
    history.scrollTop = history.scrollHeight;
}

function connect() {
    if (!cfg) {
        setStatus('no config yet', 'disconnected');
        return;
    }
    if (ws) { ws.close(); ws = null; }
    setStatus('connecting to ' + cfg.serveUrl + '…', '');
    try {
        ws = new WebSocket(cfg.serveUrl);
    } catch (e) {
        setStatus('connect failed: ' + e.message, 'disconnected');
        return;
    }
    ws.onopen = () => {
        setStatus('connected', 'connected');
        sendBtn.disabled = false;
    };
    ws.onclose = () => {
        setStatus('disconnected — click Reconnect', 'disconnected');
        sendBtn.disabled = true;
        ws = null;
    };
    ws.onerror = () => {
        setStatus('error — is aether serve running?', 'disconnected');
    };
    ws.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            if (msg.type === 'delta') {
                if (!currentAgentDiv) {
                    currentAgentDiv = appendTurn('agent', '');
                    currentAgentMarkdown = '';
                }
                currentAgentMarkdown += msg.text || '';
                currentAgentDiv.innerHTML = md.render(currentAgentMarkdown);
                history.scrollTop = history.scrollHeight;
            } else if (msg.type === 'done') {
                if (currentAgentDiv && msg.text) {
                    currentAgentDiv.innerHTML = md.render(msg.text);
                }
                currentAgentDiv = null;
                inFlight = false;
                sendBtn.disabled = false;
                const u = msg.usage || {};
                const cost = msg.cost_usd != null ? msg.cost_usd.toFixed(4) : '?';
                appendSystem(\`done — in=\${u.input_tokens||0} out=\${u.output_tokens||0} cost~$\${cost}\`);
                if (msg.error) {
                    appendSystem('error: ' + msg.error);
                }
            } else if (msg.type === 'error') {
                appendSystem('error: ' + msg.message);
                inFlight = false;
                sendBtn.disabled = false;
            }
        } catch (e) {
            appendSystem('bad frame: ' + e.message);
        }
    };
}

function send() {
    if (!ws || ws.readyState !== WebSocket.OPEN || inFlight) return;
    const text = prompt.value.trim();
    if (!text) return;
    appendTurn('user', text);
    prompt.value = '';
    inFlight = true;
    sendBtn.disabled = true;
    const payload = { prompt: text };
    if (cfg && cfg.model) payload.model = cfg.model;
    ws.send(JSON.stringify(payload));
}

sendBtn.addEventListener('click', send);
reconnectBtn.addEventListener('click', connect);
prompt.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
        e.preventDefault();
        send();
    }
});

window.addEventListener('message', (event) => {
    const msg = event.data;
    if (msg.type === 'config') {
        cfg = { serveUrl: msg.serveUrl, serveToken: msg.serveToken, model: msg.model };
        connect();
    }
});

vscode.postMessage({ type: 'config-request' });
</script>
</body>
</html>`;
}
