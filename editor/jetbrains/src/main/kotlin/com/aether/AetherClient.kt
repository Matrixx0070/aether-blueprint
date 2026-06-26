package com.aether

import java.net.URI
import java.net.http.HttpClient
import java.net.http.WebSocket
import java.util.concurrent.CompletableFuture

/**
 * Thin WS client. One prompt per connection (server contract is one
 * agent turn per WS lifetime; reconnect on the next prompt). Frames are
 * JSON: server sends `{"type":"delta","text":...}` and a terminal
 * `{"type":"done","usage":{...},"cost_usd":N,"text":...}` or
 * `{"type":"error","message":...}`.
 *
 * Callbacks fire on the WebSocket worker thread; UI code must marshal
 * back to the EDT itself.
 */
class AetherClient(
    private val serverUrl: String,
    private val bearerToken: String,
) {
    fun send(
        prompt: String,
        model: String,
        onDelta: (String) -> Unit,
        onDone: (totalText: String, inputTokens: Long, outputTokens: Long, costUsd: Double) -> Unit,
        onError: (String) -> Unit,
    ): WebSocket {
        val client = HttpClient.newHttpClient()
        var builder = client.newWebSocketBuilder()
        if (bearerToken.isNotBlank()) {
            builder = builder.header("Authorization", "Bearer $bearerToken")
        }
        val sb = StringBuilder()
        val listener = object : WebSocket.Listener {
            override fun onOpen(ws: WebSocket) {
                val req = """{"prompt":${jsonString(prompt)},"model":${jsonString(model)}}"""
                ws.sendText(req, true)
                ws.request(1)
            }
            override fun onText(ws: WebSocket, data: CharSequence, last: Boolean): CompletableFuture<*>? {
                sb.append(data)
                if (last) {
                    val frame = sb.toString()
                    sb.clear()
                    handle(frame, onDelta, onDone, onError)
                }
                ws.request(1)
                return null
            }
            override fun onError(ws: WebSocket, error: Throwable) {
                onError(error.message ?: error::class.simpleName ?: "ws error")
            }
        }
        return builder.buildAsync(URI.create(serverUrl), listener).join()
    }

    private fun handle(
        frame: String,
        onDelta: (String) -> Unit,
        onDone: (String, Long, Long, Double) -> Unit,
        onError: (String) -> Unit,
    ) {
        val type = extractField(frame, "type") ?: return
        when (type) {
            "delta" -> extractField(frame, "text")?.let(onDelta)
            "done" -> {
                val text = extractField(frame, "text") ?: ""
                val inTok = extractNested(frame, "usage", "input_tokens")?.toLongOrNull() ?: 0L
                val outTok = extractNested(frame, "usage", "output_tokens")?.toLongOrNull() ?: 0L
                val cost = extractField(frame, "cost_usd")?.toDoubleOrNull() ?: 0.0
                onDone(text, inTok, outTok, cost)
            }
            "error" -> onError(extractField(frame, "message") ?: "error")
        }
    }

    /**
     * Tiny JSON-string field reader. Avoids a JSON dep — the server emits
     * a fixed shape, so a regex extract is sufficient. Handles \" escapes
     * and \\u escapes by passing them through to the consumer; the
     * consumer renders the delta as-is.
     */
    private fun extractField(json: String, name: String): String? {
        val key = "\"$name\""
        val idx = json.indexOf(key)
        if (idx < 0) return null
        var i = idx + key.length
        while (i < json.length && json[i] != ':') i++
        if (i >= json.length) return null
        i++
        while (i < json.length && json[i].isWhitespace()) i++
        if (i >= json.length) return null
        val ch = json[i]
        if (ch == '"') {
            val sb = StringBuilder()
            i++
            while (i < json.length) {
                val c = json[i]
                if (c == '\\' && i + 1 < json.length) {
                    val next = json[i + 1]
                    sb.append(when (next) {
                        '"' -> '"'
                        '\\' -> '\\'
                        '/' -> '/'
                        'b' -> '\b'
                        'f' -> '\u000C'
                        'n' -> '\n'
                        'r' -> '\r'
                        't' -> '\t'
                        else -> { sb.append('\\'); next }
                    })
                    i += 2
                } else if (c == '"') {
                    return sb.toString()
                } else {
                    sb.append(c)
                    i++
                }
            }
            return null
        } else {
            val start = i
            while (i < json.length && json[i] != ',' && json[i] != '}' && !json[i].isWhitespace()) i++
            return json.substring(start, i)
        }
    }

    private fun extractNested(json: String, outer: String, inner: String): String? {
        val outerKey = "\"$outer\""
        val idx = json.indexOf(outerKey)
        if (idx < 0) return null
        val brace = json.indexOf('{', idx)
        val close = if (brace < 0) -1 else json.indexOf('}', brace)
        if (brace < 0 || close < 0) return null
        return extractField(json.substring(brace, close + 1), inner)
    }

    private fun jsonString(s: String): String {
        val sb = StringBuilder("\"")
        for (c in s) {
            when (c) {
                '\\' -> sb.append("\\\\")
                '"' -> sb.append("\\\"")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                else -> if (c < ' ') sb.append("\\u%04x".format(c.code)) else sb.append(c)
            }
        }
        sb.append('"')
        return sb.toString()
    }
}
