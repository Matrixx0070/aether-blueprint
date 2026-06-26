package com.aether

import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.project.Project
import com.intellij.openapi.wm.ToolWindow
import com.intellij.openapi.wm.ToolWindowFactory
import com.intellij.ui.content.ContentFactory
import java.awt.BorderLayout
import javax.swing.*

class AetherToolWindowFactory : ToolWindowFactory {
    override fun createToolWindowContent(project: Project, toolWindow: ToolWindow) {
        val panel = AetherChatPanel()
        val content = ContentFactory.getInstance().createContent(panel, "", false)
        toolWindow.contentManager.addContent(content)
    }
}

class AetherChatPanel : JPanel(BorderLayout()) {
    private val output = JTextArea().apply {
        isEditable = false
        lineWrap = true
        wrapStyleWord = true
    }
    private val input = JTextField()
    private val sendButton = JButton("Send")
    private val statusLabel = JLabel("idle")

    init {
        val centre = JScrollPane(output)
        val south = JPanel(BorderLayout()).apply {
            add(input, BorderLayout.CENTER)
            add(sendButton, BorderLayout.EAST)
        }
        add(centre, BorderLayout.CENTER)
        add(south, BorderLayout.SOUTH)
        add(statusLabel, BorderLayout.NORTH)

        sendButton.addActionListener { send() }
        input.addActionListener { send() }
    }

    private fun send() {
        val prompt = input.text.trim()
        if (prompt.isEmpty()) return
        input.text = ""
        appendUser(prompt)
        statusLabel.text = "thinking…"

        val settings = AetherSettings.get()
        val client = AetherClient(settings.serverUrl, settings.bearerToken)
        appendAssistantHeader()

        Thread {
            try {
                client.send(
                    prompt = prompt,
                    model = settings.defaultModel,
                    onDelta = { delta ->
                        ApplicationManager.getApplication().invokeLater {
                            output.append(delta)
                            output.caretPosition = output.document.length
                        }
                    },
                    onDone = { _, inTok, outTok, cost ->
                        ApplicationManager.getApplication().invokeLater {
                            output.append("\n")
                            statusLabel.text = "tokens in=$inTok out=$outTok · cost=\$%.4f".format(cost)
                        }
                    },
                    onError = { msg ->
                        ApplicationManager.getApplication().invokeLater {
                            output.append("\n[error] $msg\n")
                            statusLabel.text = "error"
                        }
                    },
                )
            } catch (e: Exception) {
                ApplicationManager.getApplication().invokeLater {
                    output.append("\n[ws error] ${e.message ?: e::class.simpleName}\n")
                    statusLabel.text = "error"
                }
            }
        }.start()
    }

    private fun appendUser(prompt: String) {
        output.append("\nyou › $prompt\n")
    }

    private fun appendAssistantHeader() {
        output.append("\naether › ")
        output.caretPosition = output.document.length
    }
}
