package com.aether

import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.components.PersistentStateComponent
import com.intellij.openapi.components.Service
import com.intellij.openapi.components.State
import com.intellij.openapi.components.Storage
import com.intellij.util.xmlb.XmlSerializerUtil

@State(
    name = "AetherSettings",
    storages = [Storage("aether.xml")]
)
@Service(Service.Level.APP)
class AetherSettings : PersistentStateComponent<AetherSettings.State> {
    data class State(
        var serverUrl: String = "ws://127.0.0.1:7777/ws/chat",
        var bearerToken: String = "",
        var defaultModel: String = "claude-haiku-4-5-20251001"
    )

    private var state = State()

    override fun getState(): State = state
    override fun loadState(loaded: State) {
        XmlSerializerUtil.copyBean(loaded, state)
    }

    var serverUrl: String
        get() = state.serverUrl
        set(value) { state.serverUrl = value }

    var bearerToken: String
        get() = state.bearerToken
        set(value) { state.bearerToken = value }

    var defaultModel: String
        get() = state.defaultModel
        set(value) { state.defaultModel = value }

    companion object {
        fun get(): AetherSettings = ApplicationManager.getApplication().getService(AetherSettings::class.java)
    }
}
