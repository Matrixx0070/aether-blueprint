package com.aether

import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.wm.ToolWindowManager

/**
 * The Tools menu action — just unhides + focuses the Aether tool window.
 * The actual chat lives in AetherToolWindow; this keeps the action
 * thin so the keyboard shortcut and menu entry are pure UX glue.
 */
class AskAction : AnAction() {
    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        val tw = ToolWindowManager.getInstance(project).getToolWindow("Aether") ?: return
        tw.activate(null)
    }
}
