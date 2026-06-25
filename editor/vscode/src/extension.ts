// aether VS Code extension — bare-minimum skeleton.
//
// Three commands, each spawns the `aether` CLI binary as a child
// process and streams its stdout into a dedicated output channel.
//
//   aether.ask                 — prompt via input box
//   aether.askAboutSelection   — prompt with the active editor's
//                                selection prepended as context
//   aether.doctor              — runs `aether doctor --json` and
//                                pretty-prints the report
//
// This is a v1 skeleton — single output channel, one-shot per invocation.
// Streaming + multi-turn UI lives behind a separate panel (planned v0.17).

import * as vscode from 'vscode';
import { spawn, ChildProcess } from 'child_process';

let output: vscode.OutputChannel | null = null;
let activeProc: ChildProcess | null = null;

function getOutput(): vscode.OutputChannel {
    if (!output) {
        output = vscode.window.createOutputChannel('aether');
    }
    return output;
}

function getConfig() {
    const cfg = vscode.workspace.getConfiguration('aether');
    return {
        binaryPath: cfg.get<string>('binaryPath') || 'aether',
        model: cfg.get<string>('model') || '',
        permissionMode: cfg.get<string>('permissionMode') || 'default',
    };
}

/**
 * Spawn `aether -p PROMPT` with the configured flags and stream stdout
 * into the output channel. Returns a Promise that resolves when the
 * process exits.
 */
function runAetherPrint(prompt: string, cwd: string): Promise<void> {
    return new Promise((resolve, reject) => {
        const cfg = getConfig();
        const out = getOutput();
        const args: string[] = ['-p', prompt, '--permission-mode', cfg.permissionMode];
        if (cfg.model) {
            args.push('--model', cfg.model);
        }
        // Always disable streaming to stdout from the harness — we want
        // line-buffered output we can pipe into the channel.
        const env = { ...process.env, AETHER_NO_STREAM: '1' };

        out.appendLine(`\n[aether $ ${cfg.binaryPath} ${args.slice(0, 2).join(' ')} ...]`);
        const proc = spawn(cfg.binaryPath, args, { cwd, env });
        activeProc = proc;

        proc.stdout?.on('data', (chunk: Buffer) => {
            out.append(chunk.toString());
        });
        proc.stderr?.on('data', (chunk: Buffer) => {
            // Stderr carries [tool] markers and the [aether-usage ...] line
            // — show them so the user knows what's happening.
            out.append(chunk.toString());
        });
        proc.on('error', (err: Error) => {
            out.appendLine(`\n[aether error] ${err.message}`);
            activeProc = null;
            reject(err);
        });
        proc.on('close', (code: number | null) => {
            out.appendLine(`\n[aether exit ${code ?? 'unknown'}]`);
            activeProc = null;
            if (code === 0) {
                resolve();
            } else {
                reject(new Error(`aether exited with code ${code}`));
            }
        });
    });
}

async function cmdAsk(): Promise<void> {
    const prompt = await vscode.window.showInputBox({
        prompt: 'aether: Ask anything',
        placeHolder: 'Refactor X to use Y / Fix bug in foo.py / ...',
    });
    if (!prompt) {
        return;
    }
    const cwd = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || process.cwd();
    getOutput().show(true);
    try {
        await runAetherPrint(prompt, cwd);
    } catch (e) {
        vscode.window.showErrorMessage(`aether: ${(e as Error).message}`);
    }
}

async function cmdAskAboutSelection(): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showWarningMessage('aether: no active editor');
        return;
    }
    const selectedText = editor.document.getText(editor.selection);
    if (!selectedText.trim()) {
        vscode.window.showWarningMessage('aether: nothing selected');
        return;
    }
    const userQuestion = await vscode.window.showInputBox({
        prompt: 'aether: question about selected code',
        placeHolder: 'What does this do? / Why does this fail when X? / Refactor to use Y',
    });
    if (!userQuestion) {
        return;
    }
    const language = editor.document.languageId;
    const filePath = vscode.workspace.asRelativePath(editor.document.uri);
    const prompt =
        `${userQuestion}\n\n` +
        `Context — selected ${language} code from ${filePath}:\n\n` +
        `\`\`\`${language}\n${selectedText}\n\`\`\`\n`;
    const cwd = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || process.cwd();
    getOutput().show(true);
    try {
        await runAetherPrint(prompt, cwd);
    } catch (e) {
        vscode.window.showErrorMessage(`aether: ${(e as Error).message}`);
    }
}

async function cmdDoctor(): Promise<void> {
    const cfg = getConfig();
    const out = getOutput();
    out.show(true);
    out.appendLine(`\n[aether $ ${cfg.binaryPath} doctor --json]`);
    return new Promise<void>((resolve, reject) => {
        const proc = spawn(cfg.binaryPath, ['doctor', '--json'], {});
        let stdout = '';
        let stderr = '';
        proc.stdout?.on('data', (c: Buffer) => {
            stdout += c.toString();
        });
        proc.stderr?.on('data', (c: Buffer) => {
            stderr += c.toString();
        });
        proc.on('error', (err: Error) => {
            out.appendLine(`[aether doctor error] ${err.message}`);
            reject(err);
        });
        proc.on('close', (code: number | null) => {
            if (stdout.trim()) {
                try {
                    const parsed = JSON.parse(stdout);
                    out.appendLine(JSON.stringify(parsed, null, 2));
                } catch {
                    out.appendLine(stdout);
                }
            }
            if (stderr.trim()) {
                out.appendLine(`\n[stderr]\n${stderr}`);
            }
            out.appendLine(`\n[aether doctor exit ${code ?? 'unknown'}]`);
            resolve();
        });
    });
}

export function activate(context: vscode.ExtensionContext): void {
    context.subscriptions.push(vscode.commands.registerCommand('aether.ask', cmdAsk));
    context.subscriptions.push(
        vscode.commands.registerCommand('aether.askAboutSelection', cmdAskAboutSelection),
    );
    context.subscriptions.push(vscode.commands.registerCommand('aether.doctor', cmdDoctor));
}

export function deactivate(): void {
    if (activeProc && !activeProc.killed) {
        activeProc.kill();
    }
    if (output) {
        output.dispose();
    }
}
