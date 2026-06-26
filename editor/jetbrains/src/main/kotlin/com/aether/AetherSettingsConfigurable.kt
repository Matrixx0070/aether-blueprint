package com.aether

import com.intellij.openapi.options.Configurable
import com.intellij.ui.dsl.builder.bindText
import com.intellij.ui.dsl.builder.panel
import javax.swing.JComponent

class AetherSettingsConfigurable : Configurable {
    private val settings = AetherSettings.get()
    private var component: JComponent? = null

    override fun getDisplayName(): String = "Aether"

    override fun createComponent(): JComponent {
        val panel = panel {
            row("Server URL:") {
                textField()
                    .bindText({ settings.serverUrl }, { settings.serverUrl = it })
                    .comment("WebSocket endpoint of <code>aether serve</code>, e.g. ws://127.0.0.1:7777/ws/chat")
            }
            row("Bearer token:") {
                passwordField()
                    .bindText({ settings.bearerToken }, { settings.bearerToken = it })
                    .comment("Optional. Required when AETHER_SERVE_TOKEN is set on the server.")
            }
            row("Default model:") {
                textField()
                    .bindText({ settings.defaultModel }, { settings.defaultModel = it })
            }
        }
        component = panel
        return panel
    }

    override fun isModified(): Boolean = false  // bindText handles dirty-tracking
    override fun apply() { /* bindText writes through */ }
    override fun disposeUIResources() { component = null }
}
