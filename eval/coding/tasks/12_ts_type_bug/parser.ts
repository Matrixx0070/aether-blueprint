// Parses a query string into a typed config object.
//
// BUG: the function lies about its return type. It says `Config` (no
// optional fields) but actually returns objects where every field can
// be undefined. Downstream code that trusts the type crashes at runtime.

export interface Config {
    host: string;
    port: number;
    secure: boolean;
}

export function parseConfig(input: string): Config {
    const out: Record<string, string> = {};
    for (const pair of input.split('&')) {
        const eq = pair.indexOf('=');
        if (eq > 0) {
            out[pair.slice(0, eq)] = pair.slice(eq + 1);
        }
    }
    // The cast hides the real shape — fields can be undefined here, but
    // we lie about it via `as Config`.
    return {
        host: out['host'],
        port: Number(out['port']),
        secure: out['secure'] === 'true',
    } as Config;
}

// Caller that trusts the type signature.
export function describeConfig(c: Config): string {
    return `${c.secure ? 'https' : 'http'}://${c.host}:${c.port}`;
}
