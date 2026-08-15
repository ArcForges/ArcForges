# Source Subsystems — 来源子系统级功能清单

> **权威来源**：本文件是 ArcForges 重写中六个只读来源仓库的子系统级功能清单，最终容器为 `feature-inventory-and-mapping.md`（合并目标）。行模式遵循 `00-scope-and-source-inventory.md` 00.02，FeatureId 全局唯一且稳定，不复用废弃号。
> 每行必须三列（`DecisionClass`/`OracleClass`/`OwningStep`）非空；路径必须在来源 @BaselineCommit 真实存在（抽样 `Test-Path` 核验）；Pro/EE/siyuan 受限来源行标注 UD-LIC 约束。
> AionUi ipcBridge 导出成员已经脚本从 `ipcBridge.ts` 全文解析并全部入行（覆盖集差集=空，本步已逐条验证）。
>
> **统一行模式**：`FeatureId | SourceRepo@BaselineCommit | SourcePath | Behavior | DecisionClass | TargetProduct | TargetProject | TargetDefinition | OwningStep | OracleClass | LicenseEvidence | AttributionRequired | Notes`。
>
> 已冻结基线：AionUi `29c9271a…`v2.1.35 Apache-2.0；AFFiNE `81df4751…`v0.27.2 blocksuite MIT / backend EE；siyuan `eef10568…`v3.7.3 AGPL-3.0；Serial-Studio `639daafb…`v4.0.3 GPL-3.0-only OR 商业；ArcVideo `caf56513…` GPL-3.0；ArcVideoFoundation `139eecaa…` GPL-3.0。

---

## 1. AionUi 桌面端（ArcChat Desktop；Apache-2.0，AttributionRequired=yes）

### 1.1 ipcBridge.ts 合同面（按导出组；全部导出成员逐名入行）

| FeatureId | SourceRepo@BaselineCommit | SourcePath | Behavior | DecisionClass | TargetProduct | TargetProject | TargetDefinition | OwningStep | OracleClass | LicenseEvidence | AttributionRequired | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| AF-F-AIONUI-0001 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | packages/desktop/src/common/adapter/ipcBridge.ts / `shell` | ipcBridge 导出组 `shell`（5 个成员）：openFile, showItemInFolder, openExternal, checkToolInstalled, openFolderWith；REST/ws/native bridge 合同面 | Copy | ArcChat Desktop | ArcChat.Desktop platform | native shell ops open-file/show-in-folder/open-external/check-tool/open-folder-with | 08 | O1 | AionUi/LICENSE (Apache-2.0) | yes | REST 型成员 -> ArcChat RPC/PublicApi 合同；wsEmitter -> ArcChat Realtime；Electron-native -> Avalonia 平台层重写 |
| AF-F-AIONUI-0002 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | packages/desktop/src/common/adapter/ipcBridge.ts / `assistants` | ipcBridge 导出组 `assistants`（7 个成员）：list, get, create, update, delete, setState, import；REST/ws/native bridge 合同面 | Copy | ArcChat Desktop | ArcChat.Application / ArcForges.Contracts.PublicApi | REST assistants CRUD | 09 | O1 | AionUi/LICENSE (Apache-2.0) | yes | REST 型成员 -> ArcChat RPC/PublicApi 合同；wsEmitter -> ArcChat Realtime；Electron-native -> Avalonia 平台层重写 |
| AF-F-AIONUI-0003 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | packages/desktop/src/common/adapter/ipcBridge.ts / `conversation` | ipcBridge 导出组 `conversation`（22 个成员）：create, createWithConversation, get, getAssociateConversation, listByCronJob, remove, update, reset, ensureRuntime, activeLease, stop, activeCount, sendMessage, getSlashCommands, askSideQuestion, confirmMessage, listArtifacts, updateArtifact, responseStream, artifactStream, listChanged, responseSearchWorkSpace；REST/ws/native bridge 合同面 | Copy | ArcChat Desktop | ArcChat.Application / ArcForges.Contracts.PublicApi | conversation CRUD+pin+send/stream+artifact REST | 09 | O1 | AionUi/LICENSE (Apache-2.0) | yes | REST 型成员 -> ArcChat RPC/PublicApi 合同；wsEmitter -> ArcChat Realtime；Electron-native -> Avalonia 平台层重写 |
| AF-F-AIONUI-0004 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | packages/desktop/src/common/adapter/ipcBridge.ts / `runtime` | ipcBridge 导出组 `runtime`（1 个成员）：statusChanged；REST/ws/native bridge 合同面 | Copy | ArcChat Desktop | ArcChat.Contracts.Realtime | runtime statusChanged wsEmitter realtime | 09 | O1 | AionUi/LICENSE (Apache-2.0) | yes | REST 型成员 -> ArcChat RPC/PublicApi 合同；wsEmitter -> ArcChat Realtime；Electron-native -> Avalonia 平台层重写 |
| AF-F-AIONUI-0005 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | packages/desktop/src/common/adapter/ipcBridge.ts / `application` | ipcBridge 导出组 `application`（17 个成员）：restart, openDevTools, isDevToolsOpened, systemInfo, getPath, updateSystemInfo, getZoomFactor, setZoomFactor, getCdpStatus, updateCdpConfig, getStartOnBootStatus, setStartOnBoot, getGpuStatus, setGpuOverride, writeRendererLog, logStream, devToolsStateChanged；REST/ws/native bridge 合同面 | Rewrite | ArcChat Desktop | ArcChat.Desktop platform (Avalonia) | Electron-native app bridge: restart/devtools/zoom/cdp/start-on-boot/gpu/log -> Avalonia lifecycle | 08 | O1 | AionUi/LICENSE (Apache-2.0) | yes | REST 型成员 -> ArcChat RPC/PublicApi 合同；wsEmitter -> ArcChat Realtime；Electron-native -> Avalonia 平台层重写 |
| AF-F-AIONUI-0006 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | packages/desktop/src/common/adapter/ipcBridge.ts / `update` | ipcBridge 导出组 `update`（6 个成员）：open, check, consumeInstallerLastFailure, download, cancelDownload, downloadProgress；REST/ws/native bridge 合同面 | Rewrite | ArcChat Desktop | eng/release + ArcChat.Desktop | update open/check/last-failure/download/cancel native -> Velopack adapter | 08 | O1 | AionUi/LICENSE (Apache-2.0) | yes | REST 型成员 -> ArcChat RPC/PublicApi 合同；wsEmitter -> ArcChat Realtime；Electron-native -> Avalonia 平台层重写 |
| AF-F-AIONUI-0007 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | packages/desktop/src/common/adapter/ipcBridge.ts / `autoUpdate` | ipcBridge 导出组 `autoUpdate`（6 个成员）：check, restoreDownloaded, download, cancelDownload, quitAndInstall, status；REST/ws/native bridge 合同面 | Rewrite | ArcChat Desktop | eng/release + ArcChat.Desktop | auto-update check/download/quit-install/status native -> Velopack | 08 | O1 | AionUi/LICENSE (Apache-2.0) | yes | REST 型成员 -> ArcChat RPC/PublicApi 合同；wsEmitter -> ArcChat Realtime；Electron-native -> Avalonia 平台层重写 |
| AF-F-AIONUI-0008 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | packages/desktop/src/common/adapter/ipcBridge.ts / `dialog` | ipcBridge 导出组 `dialog`（1 个成员）：showOpen；REST/ws/native bridge 合同面 | Rewrite | ArcChat Desktop | ArcChat.Desktop platform (Avalonia) | native open-dialog -> Avalonia folder picker | 08 | O1 | AionUi/LICENSE (Apache-2.0) | yes | REST 型成员 -> ArcChat RPC/PublicApi 合同；wsEmitter -> ArcChat Realtime；Electron-native -> Avalonia 平台层重写 |
| AF-F-AIONUI-0009 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | packages/desktop/src/common/adapter/ipcBridge.ts / `fs` | ipcBridge 导出组 `fs`（36 个成员）：getFilesByDir, listWorkspaceFiles, getImageBase64, fetchRemoteImage, readFile, readFileBuffer, createTempFile, writeFile, createZip, cancelZip, getFileMetadata, copyFilesToWorkspace, removeEntry, renameEntry, readBuiltinRule, readBuiltinSkill, readAssistantRule, writeAssistantRule, deleteAssistantRule, listAvailableSkills, materializeSkillsForAgent, readSkillInfo, importSkill, scanForSkills, detectCommonSkillPaths, detectAndCountExternalSkills, importSkills, listSkillImportHistory, getSkillImportLimits, deleteSkill, getSkillPaths, getCustomExternalPaths, addCustomExternalPath, removeCustomExternalPath, enableSkillsMarket, disableSkillsMarket；REST/ws/native bridge 合同面 | Copy | ArcChat Desktop | ArcChat.Infrastructure / ArcChat.LocalRpc | workspace file mgmt + skills/rule fs REST | 08 | O1 | AionUi/LICENSE (Apache-2.0) | yes | REST 型成员 -> ArcChat RPC/PublicApi 合同；wsEmitter -> ArcChat Realtime；Electron-native -> Avalonia 平台层重写 |
| AF-F-AIONUI-0010 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | packages/desktop/src/common/adapter/ipcBridge.ts / `fileWatch` | ipcBridge 导出组 `fileWatch`（4 个成员）：startWatch, stopWatch, stopAllWatches, fileChanged；REST/ws/native bridge 合同面 | Copy | ArcChat Desktop | ArcChat.Contracts.Realtime | file-watch start/stop + fileChanged wsEmitter | 09 | O1 | AionUi/LICENSE (Apache-2.0) | yes | REST 型成员 -> ArcChat RPC/PublicApi 合同；wsEmitter -> ArcChat Realtime；Electron-native -> Avalonia 平台层重写 |
| AF-F-AIONUI-0011 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | packages/desktop/src/common/adapter/ipcBridge.ts / `workspaceOfficeWatch` | ipcBridge 导出组 `workspaceOfficeWatch`（3 个成员）：start, stop, fileAdded；REST/ws/native bridge 合同面 | Copy | ArcChat Desktop | ArcChat.LocalRpc | office workspace file-added watcher event | 09 | O1 | AionUi/LICENSE (Apache-2.0) | yes | REST 型成员 -> ArcChat RPC/PublicApi 合同；wsEmitter -> ArcChat Realtime；Electron-native -> Avalonia 平台层重写 |
| AF-F-AIONUI-0012 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | packages/desktop/src/common/adapter/ipcBridge.ts / `fileStream` | ipcBridge 导出组 `fileStream`（0 个成员）：(导出组)；REST/ws/native bridge 合同面 | Copy | ArcChat Desktop | ArcChat.LocalRpc | file stream read contract | 09 | O1 | AionUi/LICENSE (Apache-2.0) | yes | REST 型成员 -> ArcChat RPC/PublicApi 合同；wsEmitter -> ArcChat Realtime；Electron-native -> Avalonia 平台层重写 |
| AF-F-AIONUI-0013 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | packages/desktop/src/common/adapter/ipcBridge.ts / `fileSnapshot` | ipcBridge 导出组 `fileSnapshot`（12 个成员）：init, compare, getBaselineContent, getInfo, dispose, stageFile, stageAll, unstageFile, unstageAll, discardFile, resetFile, getBranches；REST/ws/native bridge 合同面 | Copy | ArcChat Desktop | ArcChat.LocalRpc | file snapshot compare/stage/discard/reset contract | 09 | O1 | AionUi/LICENSE (Apache-2.0) | yes | REST 型成员 -> ArcChat RPC/PublicApi 合同；wsEmitter -> ArcChat Realtime；Electron-native -> Avalonia 平台层重写 |
| AF-F-AIONUI-0014 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | packages/desktop/src/common/adapter/ipcBridge.ts / `googleAuth` | ipcBridge 导出组 `googleAuth`（0 个成员）：(导出组)；REST/ws/native bridge 合同面 | Copy | ArcChat Desktop | ArcChat.Application / PublicApi | google oauth flow contract | 09 | O1 | AionUi/LICENSE (Apache-2.0) | yes | REST 型成员 -> ArcChat RPC/PublicApi 合同；wsEmitter -> ArcChat Realtime；Electron-native -> Avalonia 平台层重写 |
| AF-F-AIONUI-0015 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | packages/desktop/src/common/adapter/ipcBridge.ts / `google` | ipcBridge 导出组 `google`（1 个成员）：subscriptionStatus；REST/ws/native bridge 合同面 | Copy | ArcChat Desktop | ArcChat.Application / PublicApi | google drive subscriptionStatus REST | 09 | O1 | AionUi/LICENSE (Apache-2.0) | yes | REST 型成员 -> ArcChat RPC/PublicApi 合同；wsEmitter -> ArcChat Realtime；Electron-native -> Avalonia 平台层重写 |
| AF-F-AIONUI-0016 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | packages/desktop/src/common/adapter/ipcBridge.ts / `bedrock` | ipcBridge 导出组 `bedrock`（1 个成员）：testConnection；REST/ws/native bridge 合同面 | Copy | ArcChat Desktop | ArcChat.Application / PublicApi | AWS bedrock provider testConnection | 09 | O1 | AionUi/LICENSE (Apache-2.0) | yes | REST 型成员 -> ArcChat RPC/PublicApi 合同；wsEmitter -> ArcChat Realtime；Electron-native -> Avalonia 平台层重写 |
| AF-F-AIONUI-0017 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | packages/desktop/src/common/adapter/ipcBridge.ts / `mode` | ipcBridge 导出组 `mode`（7 个成员）：listProviders, createProvider, updateProvider, deleteProvider, fetchProviderModels, fetchModelList, detectProtocol；REST/ws/native bridge 合同面 | Copy | ArcChat Desktop | ArcChat.Application / PublicApi | provider mode CRUD + model-list/protocol REST | 09 | O1 | AionUi/LICENSE (Apache-2.0) | yes | REST 型成员 -> ArcChat RPC/PublicApi 合同；wsEmitter -> ArcChat Realtime；Electron-native -> Avalonia 平台层重写 |
| AF-F-AIONUI-0018 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | packages/desktop/src/common/adapter/ipcBridge.ts / `acpConversation` | ipcBridge 导出组 `acpConversation`（14 个成员）：sendMessage, responseStream, getManagedAgents, getAgentOverrides, setAgentOverrides, refreshCustomAgents, testCustomAgent, createCustomAgent, updateCustomAgent, deleteCustomAgent, setAgentEnabled, checkManagedAgentHealthById, checkProviderHealth, setConfigOption；REST/ws/native bridge 合同面 | Copy | ArcChat Desktop | ArcChat.Application / PublicApi | ACP custom-agent conversation send/stream + agent CRUD REST | 09 | O1 | AionUi/LICENSE (Apache-2.0) | yes | REST 型成员 -> ArcChat RPC/PublicApi 合同；wsEmitter -> ArcChat Realtime；Electron-native -> Avalonia 平台层重写 |
| AF-F-AIONUI-0019 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | packages/desktop/src/common/adapter/ipcBridge.ts / `mcpService` | ipcBridge 导出组 `mcpService`（13 个成员）：listServers, createServer, importServers, updateServer, deleteServer, toggleServer, batchImportServers, getAgentMcpConfigs, testMcpConnection, checkOAuthStatus, loginMcpOAuth, logoutMcpOAuth, getAuthenticatedServers；REST/ws/native bridge 合同面 | Copy | ArcChat Desktop | ArcChat.McpClient / Application | MCP server CRUD + test + OAuth login/logout REST | 09 | O1 | AionUi/LICENSE (Apache-2.0) | yes | REST 型成员 -> ArcChat RPC/PublicApi 合同；wsEmitter -> ArcChat Realtime；Electron-native -> Avalonia 平台层重写 |
| AF-F-AIONUI-0020 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | packages/desktop/src/common/adapter/ipcBridge.ts / `openclawConversation` | ipcBridge 导出组 `openclawConversation`（3 个成员）：sendMessage, responseStream, getRuntime；REST/ws/native bridge 合同面 | Copy | ArcChat Desktop | ArcChat.Application / PublicApi | openclaw send/stream/getRuntime REST | 09 | O1 | AionUi/LICENSE (Apache-2.0) | yes | REST 型成员 -> ArcChat RPC/PublicApi 合同；wsEmitter -> ArcChat Realtime；Electron-native -> Avalonia 平台层重写 |
| AF-F-AIONUI-0021 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | packages/desktop/src/common/adapter/ipcBridge.ts / `remoteAgent` | ipcBridge 导出组 `remoteAgent`（7 个成员）：list, get, create, update, delete, testConnection, handshake；REST/ws/native bridge 合同面 | Copy | ArcChat Desktop | ArcChat.Application / PublicApi | remoteAgent CRUD/test/handshake REST | 09 | O1 | AionUi/LICENSE (Apache-2.0) | yes | REST 型成员 -> ArcChat RPC/PublicApi 合同；wsEmitter -> ArcChat Realtime；Electron-native -> Avalonia 平台层重写 |
| AF-F-AIONUI-0022 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | packages/desktop/src/common/adapter/ipcBridge.ts / `database` | ipcBridge 导出组 `database`（4 个成员）：getConversationMessages, getConversationMessage, getUserConversations, searchConversationMessages；REST/ws/native bridge 合同面 | Copy | ArcChat Desktop | ArcChat.Infrastructure / Application | conversation message DB queries (local SQLite) contract | 09 | O2 | AionUi/LICENSE (Apache-2.0) | yes | REST 型成员 -> ArcChat RPC/PublicApi 合同；wsEmitter -> ArcChat Realtime；Electron-native -> Avalonia 平台层重写 |
| AF-F-AIONUI-0023 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | packages/desktop/src/common/adapter/ipcBridge.ts / `previewHistory` | ipcBridge 导出组 `previewHistory`（2 个成员）：save, getContent；REST/ws/native bridge 合同面 | Rewrite | ArcChat Desktop | ArcForges.Desktop.Preview | preview history save/get native preview | 09 | O1 | AionUi/LICENSE (Apache-2.0) | yes | REST 型成员 -> ArcChat RPC/PublicApi 合同；wsEmitter -> ArcChat Realtime；Electron-native -> Avalonia 平台层重写 |
| AF-F-AIONUI-0024 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | packages/desktop/src/common/adapter/ipcBridge.ts / `preview` | ipcBridge 导出组 `preview`（0 个成员）：(导出组)；REST/ws/native bridge 合同面 | Rewrite | ArcChat Desktop | ArcForges.Desktop.Preview | preview surface native ops | 09 | O1 | AionUi/LICENSE (Apache-2.0) | yes | REST 型成员 -> ArcChat RPC/PublicApi 合同；wsEmitter -> ArcChat Realtime；Electron-native -> Avalonia 平台层重写 |
| AF-F-AIONUI-0025 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | packages/desktop/src/common/adapter/ipcBridge.ts / `document` | ipcBridge 导出组 `document`（1 个成员）：convert；REST/ws/native bridge 合同面 | Rewrite | ArcChat Desktop | ArcForges.Desktop.RichContent | document convert (office/OOXML) preview | 09 | O1 | AionUi/LICENSE (Apache-2.0) | yes | REST 型成员 -> ArcChat RPC/PublicApi 合同；wsEmitter -> ArcChat Realtime；Electron-native -> Avalonia 平台层重写 |
| AF-F-AIONUI-0026 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | packages/desktop/src/common/adapter/ipcBridge.ts / `pptPreview` | ipcBridge 导出组 `pptPreview`（3 个成员）：start, stop, status；REST/ws/native bridge 合同面 | Rewrite | ArcChat Desktop | ArcForges.Desktop.Preview | ppt preview start/stop/status | 09 | O1 | AionUi/LICENSE (Apache-2.0) | yes | REST 型成员 -> ArcChat RPC/PublicApi 合同；wsEmitter -> ArcChat Realtime；Electron-native -> Avalonia 平台层重写 |
| AF-F-AIONUI-0027 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | packages/desktop/src/common/adapter/ipcBridge.ts / `wordPreview` | ipcBridge 导出组 `wordPreview`（3 个成员）：start, stop, status；REST/ws/native bridge 合同面 | Rewrite | ArcChat Desktop | ArcForges.Desktop.Preview | word preview start/stop/status | 09 | O1 | AionUi/LICENSE (Apache-2.0) | yes | REST 型成员 -> ArcChat RPC/PublicApi 合同；wsEmitter -> ArcChat Realtime；Electron-native -> Avalonia 平台层重写 |
| AF-F-AIONUI-0028 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | packages/desktop/src/common/adapter/ipcBridge.ts / `excelPreview` | ipcBridge 导出组 `excelPreview`（3 个成员）：start, stop, status；REST/ws/native bridge 合同面 | Rewrite | ArcChat Desktop | ArcForges.Desktop.Preview | excel preview start/stop/status | 09 | O1 | AionUi/LICENSE (Apache-2.0) | yes | REST 型成员 -> ArcChat RPC/PublicApi 合同；wsEmitter -> ArcChat Realtime；Electron-native -> Avalonia 平台层重写 |
| AF-F-AIONUI-0029 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | packages/desktop/src/common/adapter/ipcBridge.ts / `deepLink` | ipcBridge 导出组 `deepLink`（0 个成员）：(导出组)；REST/ws/native bridge 合同面 | Rewrite | ArcChat Desktop | ArcChat.Desktop (Avalonia DeepLink) | deep-link received wsEmitter native -> ArcForges.Desktop.Experience DeepLink | 08 | O1 | AionUi/LICENSE (Apache-2.0) | yes | REST 型成员 -> ArcChat RPC/PublicApi 合同；wsEmitter -> ArcChat Realtime；Electron-native -> Avalonia 平台层重写 |
| AF-F-AIONUI-0030 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | packages/desktop/src/common/adapter/ipcBridge.ts / `windowControls` | ipcBridge 导出组 `windowControls`（6 个成员）：minimize, maximize, unmaximize, close, isMaximized, maximizedChanged；REST/ws/native bridge 合同面 | Rewrite | ArcChat Desktop | ArcChat.Desktop platform | window minimize/maximize/close native bridge | 08 | O1 | AionUi/LICENSE (Apache-2.0) | yes | REST 型成员 -> ArcChat RPC/PublicApi 合同；wsEmitter -> ArcChat Realtime；Electron-native -> Avalonia 平台层重写 |
| AF-F-AIONUI-0031 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | packages/desktop/src/common/adapter/ipcBridge.ts / `theme` | ipcBridge 导出组 `theme`（3 个成员）：changed, setActive, requestCurrent；REST/ws/native bridge 合同面 | Copy | ArcChat Desktop | ArcForges.Desktop.Experience | theme change/setActive/request + theme token | 09 | O1 | AionUi/LICENSE (Apache-2.0) | yes | REST 型成员 -> ArcChat RPC/PublicApi 合同；wsEmitter -> ArcChat Realtime；Electron-native -> Avalonia 平台层重写 |
| AF-F-AIONUI-0032 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | packages/desktop/src/common/adapter/ipcBridge.ts / `systemSettings` | ipcBridge 导出组 `systemSettings`（20 个成员）：getCloseToTray, setCloseToTray, getNotificationEnabled, getCronNotificationEnabled, getKeepAwake, setKeepAwake, changeLanguage, languageChanged, getSaveUploadToWorkspace, getAutoPreviewOfficeFiles, getPetEnabled, setPetEnabled, getPetSize, setPetSize, getPetDnd, setPetDnd, getPetConfirmEnabled, setPetConfirmEnabled, ensureNodeRuntime, ensureManagedAcpTool；REST/ws/native bridge 合同面 | Copy | ArcChat Desktop | ArcChat.Domain / Application | desktop system settings REST (tray/pet/language/notify/node/keep-awake) | 09 | O1 | AionUi/LICENSE (Apache-2.0) | yes | REST 型成员 -> ArcChat RPC/PublicApi 合同；wsEmitter -> ArcChat Realtime；Electron-native -> Avalonia 平台层重写 |
| AF-F-AIONUI-0033 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | packages/desktop/src/common/adapter/ipcBridge.ts / `notification` | ipcBridge 导出组 `notification`（2 个成员）：show, clicked；REST/ws/native bridge 合同面 | Rewrite | ArcChat Desktop | ArcChat.Desktop | native notification show + clicked wsEmitter | 08 | O1 | AionUi/LICENSE (Apache-2.0) | yes | REST 型成员 -> ArcChat RPC/PublicApi 合同；wsEmitter -> ArcChat Realtime；Electron-native -> Avalonia 平台层重写 |
| AF-F-AIONUI-0034 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | packages/desktop/src/common/adapter/ipcBridge.ts / `task` | ipcBridge 导出组 `task`（1 个成员）：stopAll；REST/ws/native bridge 合同面 | Copy | ArcChat Desktop | ArcChat.Application | task stopAll native bridge | 09 | O1 | AionUi/LICENSE (Apache-2.0) | yes | REST 型成员 -> ArcChat RPC/PublicApi 合同；wsEmitter -> ArcChat Realtime；Electron-native -> Avalonia 平台层重写 |
| AF-F-AIONUI-0035 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | packages/desktop/src/common/adapter/ipcBridge.ts / `webui` | ipcBridge 导出组 `webui`（5 个成员）：getStatus, start, stop, resetPassword, generateQRToken；REST/ws/native bridge 合同面 | Rewrite | ArcChat Desktop | ArcChat.Application | webui start/stop/status/resetPassword native adapter (target no embedded web runtime) | 09 | O1 | AionUi/LICENSE (Apache-2.0) | yes | REST 型成员 -> ArcChat RPC/PublicApi 合同；wsEmitter -> ArcChat Realtime；Electron-native -> Avalonia 平台层重写 |
| AF-F-AIONUI-0036 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | packages/desktop/src/common/adapter/ipcBridge.ts / `cron` | ipcBridge 导出组 `cron`（14 个成员）：listJobs, listJobsByConversation, getJob, addJob, updateJob, removeJob, runNow, saveSkill, hasSkill, deleteSkill, onJobCreated, onJobUpdated, onJobRemoved, onJobExecuted；REST/ws/native bridge 合同面 | Copy | ArcChat Desktop | ArcChat.Application / PublicApi | cron job CRUD/runNow/skill + job wsEvents REST | 09 | O1 | AionUi/LICENSE (Apache-2.0) | yes | REST 型成员 -> ArcChat RPC/PublicApi 合同；wsEmitter -> ArcChat Realtime；Electron-native -> Avalonia 平台层重写 |
| AF-F-AIONUI-0037 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | packages/desktop/src/common/adapter/ipcBridge.ts / `extensions` | ipcBridge 导出组 `extensions`（16 个成员）：getThemes, getLoadedExtensions, getAssistants, getAgents, getAcpAdapters, getMcpServers, getSkills, getSettingsTabs, getWebuiContributions, getAgentActivitySnapshot, getExtI18nForLocale, enableExtension, disableExtension, getPermissions, getRiskLevel, stateChanged；REST/ws/native bridge 合同面 | Rewrite | ArcChat Desktop | ArcForges.Extensions.Registry | extensions catalog/permissions/risk/state realtime | 09 | O1 | AionUi/LICENSE (Apache-2.0) | yes | REST 型成员 -> ArcChat RPC/PublicApi 合同；wsEmitter -> ArcChat Realtime；Electron-native -> Avalonia 平台层重写 |
| AF-F-AIONUI-0038 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | packages/desktop/src/common/adapter/ipcBridge.ts / `channel` | ipcBridge 导出组 `channel`（17 个成员）：getPluginStatus, enablePlugin, disablePlugin, testPlugin, getPendingPairings, approvePairing, rejectPairing, getAuthorizedUsers, revokeUser, getActiveSessions, getPlatformSettings, setAssistantSetting, setDefaultModelSetting, syncChannelSettings, pairingRequested, pluginStatusChanged, userAuthorized；REST/ws/native bridge 合同面 | Copy | ArcChat Desktop | ArcChat.Application / PublicApi | channel plugin pairing/session + pairingRequested realtime | 09 | O1 | AionUi/LICENSE (Apache-2.0) | yes | REST 型成员 -> ArcChat RPC/PublicApi 合同；wsEmitter -> ArcChat Realtime；Electron-native -> Avalonia 平台层重写 |
| AF-F-AIONUI-0039 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | packages/desktop/src/common/adapter/ipcBridge.ts / `hub` | ipcBridge 导出组 `hub`（7 个成员）：getExtensionList, install, uninstall, retryInstall, checkUpdates, update, onStateChanged；REST/ws/native bridge 合同面 | Rewrite | ArcChat Desktop | ArcChat.LocalHub | extensions hub install/uninstall/update native bridge | 09 | O1 | AionUi/LICENSE (Apache-2.0) | yes | REST 型成员 -> ArcChat RPC/PublicApi 合同；wsEmitter -> ArcChat Realtime；Electron-native -> Avalonia 平台层重写 |
| AF-F-AIONUI-0040 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | packages/desktop/src/common/adapter/ipcBridge.ts / `realtime` | ipcBridge 导出组 `realtime`（1 个成员）：reconnected；REST/ws/native bridge 合同面 | Copy | ArcChat Desktop | ArcChat.Contracts.Realtime | realtime reconnected event | 09 | O1 | AionUi/LICENSE (Apache-2.0) | yes | REST 型成员 -> ArcChat RPC/PublicApi 合同；wsEmitter -> ArcChat Realtime；Electron-native -> Avalonia 平台层重写 |
| AF-F-AIONUI-0041 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | packages/desktop/src/common/adapter/ipcBridge.ts / `team` | ipcBridge 导出组 `team`（41 个成员）：create, list, get, remove, addAgent, removeAgent, stop, ensureSession, getConfigOptions, activeLease, renameAgent, renameTeam, setSessionMode, getRunState, sendMessage, sendMessageToAgent, cancelRun, cancelChildTurn, pauseSlotWork, agentStatusChanged, agentSpawned, agentRemoved, agentRenamed, agentRuntimeStatusChanged, listChanged, created, removed, renamed, teammateMessage, sessionStatusChanged, taskChanged, sessionChanged, runAccepted, runStarted, runUpdated, runCompleted, runCancelled, runFailed, childTurnStarted, childTurnCompleted, childTurnCancelled；REST/ws/native bridge 合同面 | Drop | ArcChat Desktop | ArcChat (Drop multi-agent) | team multi-agent surfaces -> Drop per no-Team decision; behavior reference only | 09 | O1 | AionUi/LICENSE (Apache-2.0) | yes | REST 型成员 -> ArcChat RPC/PublicApi 合同；wsEmitter -> ArcChat Realtime；Electron-native -> Avalonia 平台层重写 |



### 1.2 `common/chat/chatLib.ts`（消息模型 + 合并规则；Step 09，Oracle O1）


| FeatureId | SourceRepo@BaselineCommit | SourcePath | Behavior | DecisionClass | TargetProduct | TargetProject | TargetDefinition | OwningStep | OracleClass | LicenseEvidence | AttributionRequired | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|


| AF-F-AIONUI-9001 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | common/chat/chatLib.ts / `TMessage` | TMessage 封闭 oneof 变体：text / tips / tool_call / tool_group / agent_status / acp_permission / permission / acp_tool_call / plan / thinking / available_commands；每变体 content/position/status 形状 | Copy | ArcChat | ArcChat.Domain / ArcForges.Contracts.LocalRpc | `TMessage` 封闭 tagged union + STJ 源生成契约 | 09 | O1 | AionUi/LICENSE (Apache-2.0) | yes | 消息类型按行为移植为 C# 契约 |

| AF-F-AIONUI-9002 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | common/chat/chatLib.ts / `IResponseMessage`/`transformMessage` | IResponseMessage → TMessage 规范化变换；非标类型预归类各 AgentManager | Copy | ArcChat | ArcChat.Application | `TransformMessage` 应用服务；非标消息处理器事件 | 09 | O1 | AionUi/LICENSE (Apache-2.0) | yes | 行为=输入 IResponseMessage→输出 TMessage |

| AF-F-AIONUI-9003 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | common/chat/chatLib.ts / `IConfirmation` | 审批/确认请求结构（permission、acp_permission） | Copy | ArcChat | ArcForges.Contracts.Agent / ArcChat.Application.Approvals | `ApprovalRequest` 契约 + 审批流程 | 09 | O1 | AionUi/LICENSE (Apache-2.0) | yes | 并入 Approval 模型 |

| AF-F-AIONUI-9004 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | common/chat/chatLib.ts / `composeMessage` | compose 顺序合并核心：按 type update/insert；tool_group 按 call_id、tool_call·acp_tool_call 按 id、plan 按 session、thinking 仅 contiguous-chunk | Copy | ArcChat | ArcChat.Application / ArcChat.Domain.Conversations | `ComposeMessage` 流式合并应用服务 + 每规则契约测试 | 09 | O1 | AionUi/LICENSE (Apache-2.0) | yes | 每合并规则独立成行（见下） |

| AF-F-AIONUI-9005 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | common/chat/chatLib.ts / `mergeTextMessageContent`+`isTextContentReplacement` | 文本合并：append vs `replace` 整体替换判定 | Copy | ArcChat | ArcChat.Domain.Conversations | 文本增量 merge（append/replace 二臂） | 09 | O1 | AionUi/LICENSE (Apache-2.0) | yes | O1 金样 deltas[]→expected TMessage |

| AF-F-AIONUI-9006 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | common/chat/chatLib.ts / tool_group merge-by-call_id | tool_call 批量结果按 call_id 归并进已有 tool_group | Copy | ArcChat | ArcChat.Domain.Conversations | tool_group merge-by-call_id 规则 | 09 | O1 | AionUi/LICENSE (Apache-2.0) | yes |  |

| AF-F-AIONUI-9007 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | common/chat/chatLib.ts / `mergeAcpToolCallContent`（tool_call·acp_tool_call merge-by-id） | 工具调用增量内容按调用 id 合并 | Copy | ArcChat | ArcChat.Domain.Conversations | tool_call/acp_tool_call merge-by-id 规则 | 09 | O1 | AionUi/LICENSE (Apache-2.0) | yes |  |

| AF-F-AIONUI-9008 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | common/chat/chatLib.ts / plan merge-by-session | 计划增量按 session 合并 | Copy | ArcChat | ArcChat.Domain.Conversations | plan merge-by-session 规则 | 09 | O1 | AionUi/LICENSE (Apache-2.0) | yes |  |

| AF-F-AIONUI-9009 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | common/chat/chatLib.ts / thinking contiguous-chunk | thinking 仅合并连续流式块 | Copy | ArcChat | ArcChat.Domain.Conversations | thinking contiguous-chunk 规则 | 09 | O1 | AionUi/LICENSE (Apache-2.0) | yes |  |


### 1.3 `common/config/storage.ts`（config 类型 + 本地 SQLite 13 表；Step 04/09，Oracle O2）


> 权威 13 表 schema（AF-F-AIONUI-0209..0221）已在 `feature-inventory-and-mapping.md` §1.3 逐表盘点；目标不逐表移植，按 `data-and-sync-catalog.md` 重设计。`teams/mailbox/team_tasks/remote_agents/acp_session` Drop；Conversation/Message/Automation 只在 ArcChat 保存本地 UI/projected data，Cloud Task/Run/Step 权威在 Step 13 PostgreSQL。


| FeatureId | SourceRepo@BaselineCommit | SourcePath | Behavior | DecisionClass | TargetProduct | TargetProject | TargetDefinition | OwningStep | OracleClass | LicenseEvidence | AttributionRequired | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|


| AF-F-AIONUI-9010 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | common/config/storage.ts / `IProvider`/`TProviderWithModel` | Provider 配置（api/auth/模型列表）与带默认模型变体 | Copy | ArcChat | ArcChat.Infrastructure → ArcChat.Domain | `ProviderProfile` 聚合；Provider 模型目录 | 09 | O2 | AionUi/LICENSE (Apache-2.0) | yes | Secret 仅存 SecretRef (Step 26) |

| AF-F-AIONUI-9011 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | common/config/storage.ts / `TChatConversation` | 会话配置/状态（status/runtime_state/assistant 绑定/workspace） | Copy | ArcChat | ArcChat.Domain.Conversations / ArcChat.Infrastructure | `Conversation` 聚合 + 本地会话行 | 09 | O2 | AionUi/LICENSE (Apache-2.0) | yes |  |

| AF-F-AIONUI-9012 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | common/config/storage.ts / `IMcpServer`/`ISessionMcpServer`/`IMcpTool` | MCP server 配置（stdio/SSE/HTTP/streamable-http transport）、会话级 server 与可用工具 | Copy | ArcChat | ArcChat.McpClient / ArcChat.Domain | `McpServerProfile` + 会话级 server 绑定 | 09 | O2 | AionUi/LICENSE (Apache-2.0) | yes |  |

| AF-F-AIONUI-9013 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | common/config/storage.ts / `ICssTheme` | CSS 主题配置 | Copy | ArcChat | ArcForges.Desktop.Experience | DesignTokens 主题配置；键移植不引 Web runtime | 09 | O2 | AionUi/LICENSE (Apache-2.0) | yes | 品牌/主题封面 Replace |

| AF-F-AIONUI-9014 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | config: 本地 SQLite 13 表 schema（权威见 feature-inventory §1.3） | 13 表字段/索引/migration | Copy | ArcChat | ArcChat.Infrastructure | 按 data-and-sync-catalog 重设计的 ArcChat 本地 schema；teams/mailbox/team_tasks/remote_agents/acp_session Drop | 04,09 | O2 | AionUi/LICENSE (Apache-2.0) | yes | 逐表在 feature-inventory §1.3 |


### 1.4 `renderer/pages/*` 与 `renderer/components/*`（UI 重写为 Avalonia；Decision Rewrite）


| FeatureId | SourceRepo@BaselineCommit | SourcePath | Behavior | DecisionClass | TargetProduct | TargetProject | TargetDefinition | OwningStep | OracleClass | LicenseEvidence | AttributionRequired | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|


| AF-F-AIONUI-9015 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | renderer/pages/{conversation,guid,cron,login,settings,team} | 页面级 UI surface：会话、引导、cron、登录、设置、团队 | Rewrite | ArcChat | ArcChat.Desktop / ArcChat.Presentation | Avalonia 页面/MVVM；team 页 Drop | 09 | O6 | AionUi/LICENSE (Apache-2.0) | yes | React→Avalonia 重写 |

| AF-F-AIONUI-9016 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | renderer/components/{layout,chat,Markdown,media,settings,workspace} | 组件级：Sider/Titlebar、SendBox、Markdown、media、设置、workspace | Rewrite | ArcChat | ArcChat.Presentation / ArcForges.Desktop.* | Avalonia 组件/预览 | 09 | O6 | AionUi/LICENSE (Apache-2.0) | yes | O6 视觉基线重写 |


### 1.5 `process/**`（桥接/服务；区分后端 op vs 桌面平台原生）


| FeatureId | SourceRepo@BaselineCommit | SourcePath | Behavior | DecisionClass | TargetProduct | TargetProject | TargetDefinition | OwningStep | OracleClass | LicenseEvidence | AttributionRequired | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|


| AF-F-AIONUI-9017 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | process/bridge/** | Electron 主进程 bridge（native 能力桥） | Rewrite | ArcChat | ArcChat.Desktop（Avalonia 平台层） | 平台能力统一为 Avalonia + IExternalUriLauncher/IStorageBridge | 08 | O1 | AionUi/LICENSE (Apache-2.0) | yes | electron ipcMain→Avalonia 平台适配 |

| AF-F-AIONUI-9018 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | process/services/** | 本地应用服务（含 database 13 表 repository） | Copy | ArcChat | ArcChat.Infrastructure | 服务重组为 Application Service + SqliteDataStore | 08,09 | O2 | AionUi/LICENSE (Apache-2.0) | yes |  |

| AF-F-AIONUI-9019 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | process/pet/** | 桌面 Pet 窗口行为 | Rewrite | ArcChat | ArcChat.Desktop | Pet 为同进程内窗口（architecture §14） | 08 | O1 | AionUi/LICENSE (Apache-2.0) | yes | Pet 权限/审批无复制 |

| AF-F-AIONUI-9020 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | process/resources/** | 资源管理/分发 | Copy | ArcChat | ArcChat.Infrastructure / ArcForges.Desktop.Experience | 资源生命周期与缓存 | 08 | O1 | AionUi/LICENSE (Apache-2.0) | yes |  |


### 1.6 i18n（13 语言 JSON；Copied-Asset）


| FeatureId | SourceRepo@BaselineCommit | SourcePath | Behavior | DecisionClass | TargetProduct | TargetProject | TargetDefinition | OwningStep | OracleClass | LicenseEvidence | AttributionRequired | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|


| AF-F-AIONUI-9021 | AionUi@29c9271a59484e4696778cb80164f705245a6186 | i18n 13 语言 JSON | 13 语言键名不变（en/zh/ja/…），值按语义本地化 | Copy | ArcChat | ArcForges.Desktop.Experience / ArcChat.Presentation | i18n 资产（Copied-Asset；键名不变） | 09 | O1 | AionUi/LICENSE (Apache-2.0) | yes | 归入 Copied-Asset-Manifest |


## 2. AionUi mobile（ArcChat Mobile；Copy+补齐，Step 18/19）


> 全 76 文件按模块成行（权威逐文件见 `feature-inventory-and-mapping.md` AF-F-AIONUI-M-*）；缺口单独成行。


| FeatureId | SourceRepo@BaselineCommit | SourcePath | Behavior | DecisionClass | TargetProduct | TargetProject | TargetDefinition | OwningStep | OracleClass | LicenseEvidence | AttributionRequired | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|


| AF-F-AIONUI-M-0001(grp) | AionUi@29c9271a59484e4696778cb80164f705245a6186 | mobile WS 协议层 | 远程 WS 帧/协议消息（agentModes、消息封包） | Copy | ArcChat Mobile | ArcChat.Mobile.Realtime / ArcChat.Mobile.CloudClient | WS 协议层移植为 MAUI Realtime | 18 | O1 | mobile/src/constants/agentModes.ts:1-5 (Apache-2.0) | yes | wss:// + 证书校验为安全要求行 |

| AF-F-AIONUI-M-0002(grp) | AionUi@29c9271a59484e4696778cb80164f705245a6186 | mobile messageAdapter/分组/JWT 生命周期 | 消息适配/分组 + token 刷新生命周期 | Copy | ArcChat Mobile | ArcChat.Mobile.Application / ArcChat.Mobile.Persistence | messageAdapter/grouping/JWT 移植 | 18 | O1 | AionUi/LICENSE (Apache-2.0) | yes |  |

| AF-F-AIONUI-M-0003(gap) | AionUi@29c9271a59484e4696778cb80164f705245a6186 | 移动 gap：push/DeepLink/离线缓存/分页/上传/后台恢复/弱网重试 | 补齐 7 类缺口 | Copy+补齐 | ArcChat Mobile | ArcChat.Mobile.* | 各缺口应用服务/平台适配 | 18,19 | O4 | AionUi/LICENSE (Apache-2.0) | yes |  |

| AF-F-AIONUI-M-0004(rep) | AionUi@29c9271a59484e4696778cb80164f705245a6186 | hard-coded 个人发布凭据（Apple ID/team 等） | 删除硬编码凭据 | Replace | ArcChat Mobile | eng/release + ArcChat.Mobile 平台 | 凭据移除 + 受控 secret | 18,19 | O1 | AionUi/LICENSE (Apache-2.0) | yes | 安全负门禁 |

| AF-F-AIONUI-M-0005(sec) | AionUi@29c9271a59484e4696778cb80164f705245a6186 | `wss://` + 证书校验 | 远程 WS 强制 TLS + 证书校验决策 | ReferenceOnly | ArcChat Mobile | ArcChat.Mobile.Realtime | TLS/证书校验安全要求 | 18,19 | O4 | AionUi/LICENSE (Apache-2.0) | yes |  |


## 3. AFFiNE blocksuite（ArcNotes；MIT，Step 10/15/16/17）


> 每包一行；snapshot/几何/Typed Property/视图/presentation 只作 C# 独立重实现依据；`yjs`/awareness/CRDT/state-vector 全 Drop。权威逐包见 AF-F-BLOCKSUITE-*。


| FeatureId | SourceRepo@BaselineCommit | SourcePath | Behavior | DecisionClass | TargetProduct | TargetProject | TargetDefinition | OwningStep | OracleClass | LicenseEvidence | AttributionRequired | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|


| AF-F-BLOCKSUITE(grp) | AFFiNE@81df4751a367f2795bc0d165586650dbe8db73d6 | blocksuite/framework-core | 框架核心：block/collection 抽象与命令系统 | Rewrite | ArcNotes | ArcNotes.Domain / ArcNotes.Editor | Block 域模型 + 命令系统独立 C# 实现 | 10 | O2 | blocksuite MIT (package.json license) | yes | Yjs Drop |

| AF-F-BLOCKSUITE(grp) | AFFiNE@81df4751a367f2795bc0d165586650dbe8db73d6 | blocksuite/store(+awareness/CRDT) | 文档 store/awareness/CRDT 状态 | Drop | ArcNotes | — | 不进入目标 schema/wire/golden | 10 | O2 | MIT | yes | CRDT/awareness/state-vector 全 Drop |

| AF-F-BLOCKSUITE(grp) | AFFiNE@81df4751a367f2795bc0d165586650dbe8db73d6 | blocksuite/block-std | block 服务/controller/selection/keys | Rewrite | ArcNotes | ArcNotes.Editor | Block Std 独立实现 | 10 | O2 | MIT | yes |  |

| AF-F-BLOCKSUITE(grp) | AFFiNE@81df4751a367f2795bc0d165586650dbe8db73d6 | blocksuite/affine-model | affine 数据块模型（blockSchema） | Rewrite | ArcNotes | ArcNotes.Domain | blockSchema 数据模型独立实现 | 10 | O2 | MIT | yes |  |

| AF-F-BLOCKSUITE(grp) | AFFiNE@81df4751a367f2795bc0d165586650dbe8db73d6 | blocksuite/edgeless | Edgeless 几何/连接/分组（surface） | Rewrite | ArcNotes | ArcNotes.Edgeless | Edgeless 几何/连接/分组独立实现（snapshot 仅结构 Oracle） | 15 | O5 | MIT | yes | snapshot/几何不逐字移植 |

| AF-F-BLOCKSUITE(grp) | AFFiNE@81df4751a367f2795bc0d165586650dbe8db73d6 | blocksuite/database | Typed Property / 数据库多视图 | Rewrite | ArcNotes | ArcNotes.Database | Typed Property 类型系统/视图独立实现 | 16 | O5 | MIT | yes |  |

| AF-F-BLOCKSUITE(grp) | AFFiNE@81df4751a367f2795bc0d165586650dbe8db73d6 | blocksuite/slides | Presentation/Slides 行为 | Rewrite | ArcNotes | ArcNotes.Slides | Frame/演示模式独立实现 | 17 | O5 | MIT | yes |  |

| AF-F-BLOCKSUITE(grp) | AFFiNE@81df4751a367f2795bc0d165586650dbe8db73d6 | blocksuite/adapter | 文档格式/snapshot 适配器 | Rewrite | ArcNotes | ArcNotes.ImportExport | 快照格式适配（无 Yjs） | 10 | O2 | MIT | yes |  |


## 4. AFFiNE 平台/后端（ArcForges Cloud 独立实现；ReferenceOnly，EE，UD-LIC-4）


> 仅记模式行；`TargetProject`=`ArcForges.Cloud.Modules.*`、OwningStep 12/26、Oracle O3、明文约束"不复制 EE 代码，C# 独立实现"。权威逐行见 AF-F-AFFINE-BE-*。


| FeatureId | SourceRepo@BaselineCommit | SourcePath | Behavior | DecisionClass | TargetProduct | TargetProject | TargetDefinition | OwningStep | OracleClass | LicenseEvidence | AttributionRequired | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|


| AF-F-AFFINE-BE(grp) | AFFiNE@81df4751a367f2795bc0d165586650dbe8db73d6 | packages/backend/server/prisma | Prisma 57 表模式（snapshots/updates/histories 双层存储、users/workspaces/devices/sessions/permissions/blobs/features/entitlements…） | ReferenceOnly | ArcForges Cloud | ArcForges.Cloud.Modules.* | 57 表作结构 Oracle 不复制 DDL；目标 schema 见 data-and-sync-catalog | 12,26 | O3 | AFFiNE EE LICENSE (backend/server/LICENSE) | no | UD-LIC-4：不复制 EE 代码，C# 独立实现 |

| AF-F-AFFINE-BE(grp) | AFFiNE@81df4751a367f2795bc0d165586650dbe8db73d6 | packages/backend/server | clock-based sync（version clock + 同步协议模式） | ReferenceOnly | ArcForges Cloud | ArcForges.Cloud.Modules.Sync | 无 CRDT 同步模式参考 | 12 | O3 | AFFiNE EE LICENSE | no | UD-LIC-4 |

| AF-F-AFFINE-BE(grp) | AFFiNE@81df4751a367f2795bc0d165586650dbe8db73d6 | packages/backend/server | permission evaluator（权限评估器模式） | ReferenceOnly | ArcForges Cloud | ArcForges.Cloud.Modules.* | ArcForges 权限评估独立实现（Security Reason Codes） | 12,26 | O3 | AFFiNE EE LICENSE | no | UD-LIC-4 |

| AF-F-AFFINE-BE(grp) | AFFiNE@81df4751a367f2795bc0d165586650dbe8db73d6 | packages/backend/server | blob 两阶段 GC（blob 引用/回收模式） | ReferenceOnly | ArcForges Cloud | ArcForges.Cloud.Modules.Resource | 对象存储引用/回收独立实现 | 12,26 | O3 | AFFiNE EE LICENSE | no | UD-LIC-4 |

| AF-F-AFFINE-BE(grp) | AFFiNE@81df4751a367f2795bc0d165586650dbe8db73d6 | packages/backend/server | entitlement→quota 投影（权益→配额） | ReferenceOnly | ArcForges Cloud | ArcForges.Cloud.Modules.Entitlement | 权益/配额投影独立实现 | 26 | O3 | AFFiNE EE LICENSE | no | UD-LIC-4 |

| AF-F-AFFINE-BE(grp) | AFFiNE@81df4751a367f2795bc0d165586650dbe8db73d6 | packages/backend/server | Passkey/OTP 认证模式 | ReferenceOnly | ArcForges Cloud | ArcForges.Cloud.Modules.Identity | Passkey/OTP 认证独立实现 | 12 | O3 | AFFiNE EE LICENSE | no | UD-LIC-4 |

| AF-F-AFFINE-BE(grp) | AFFiNE@81df4751a367f2795bc0d165586650dbe8db73d6 | packages/backend/server | socket.io 同步（SignalR 等价参考） | ReferenceOnly | ArcForges Cloud | ArcForges.Cloud.Modules.Sync / Realtime | SignalR 唤醒/增量（非 socket.io 移植） | 12 | O3 | AFFiNE EE LICENSE | no | UD-LIC-4 |


## 5. siyuan（ArcNotes 行为规格 → 独立 C# 实现；ReferenceOnly，AGPL，UD-LIC-3，Step 10–15，Oracle O3）


> 每行 Notes 标"独立实现，不复制源码，金样只取输入/输出对"。权威逐行见 AF-F-SIYUAN-*。


| FeatureId | SourceRepo@BaselineCommit | SourcePath | Behavior | DecisionClass | TargetProduct | TargetProject | TargetDefinition | OwningStep | OracleClass | LicenseEvidence | AttributionRequired | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|


| AF-F-SIYUAN-0001..0026(grp) | siyuan@eef10568384e2e7cf547adb029ae46a72e43c287 | kernel/** handler 分组 | block CRUD / 引用·反链 / FTS 搜索 / 导入导出(.sy/.md) / history / conf / sync / asset / template / snippet 每组一行为规格组 | ReferenceOnly | ArcNotes | ArcNotes.Domain / ArcNotes.Application | BehaviorSpecPaths→独立实现；Independent-Reimplementation-Manifest | 10–15 | O3 | siyuan/LICENSE (AGPL-3.0) | no | UD-LIC-3 独立实现，不复制源码；金样仅输入/输出 |

| AF-F-SIYUAN-0027..0062(grp) | siyuan@eef10568384e2e7cf547adb029ae46a72e43c287 | app/** 前端行为 | 文档树 / 大纲 / 块菜单 / 闪卡 / 关系图 / 数据库属性视图 前端行为组 | ReferenceOnly | ArcNotes | ArcNotes.Presentation / ArcNotes.Editor | 行为规格→Avalonia UI 独立实现 | 10–15 | O3 | siyuan/LICENSE (AGPL-3.0) | no | UD-LIC-3 独立实现；不入 Copied-Asset |


## 6. Serial-Studio（ArcScope；GPL 核心 Copy 取 GPL 分支 AGPL 兼容；Pro 全 Replace/O4；LIB 逐项）


> GPL 核心（291 双许可文件）Decision Copy、AttributionRequired=yes；Pro（182 文件，LicenseRef-SerialStudio-Commercial）Decision 全 Replace、Oracle 全 O4、Notes 引 UD-LIC-5+反克隆；vendored `lib/` 按 license-and-reuse-matrix §3 逐项。授权逐行见 AF-F-SS-CORE-*/AF-F-SS-PRO-*/AF-F-SS-LIB-*。


| FeatureId | SourceRepo@BaselineCommit | SourcePath | Behavior | DecisionClass | TargetProduct | TargetProject | TargetDefinition | OwningStep | OracleClass | LicenseEvidence | AttributionRequired | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|


| AF-F-SS-CORE(grp) | Serial-Studio@639daafb2fe7d324c3b2d5583d2514c8c470676f | app/src 驱动（UART/Network TCP·UDP/BLE） | 串口/网络/BLE 驱动行为 | Copy | ArcScope | ArcScope.Infrastructure | 驱动层 C#/Avalonia 移植（GPL 分支） | 21 | O1 | Serial-Studio dual-license GPL-3.0-only OR commercial | yes | 取 GPL 分支 AGPL 兼容；保留归属 |

| AF-F-SS-CORE(grp) | Serial-Studio@639daafb2fe7d324c3b2d5583d2514c8c470676f | app/src FrameReader/FrameBuilder/JSON Frame Format | 帧解析/构建 + JSON Frame Format | Copy | ArcScope | ArcScope.Decoders | FrameReader/FrameBuilder/CircularBuffer/SPSC 移植 | 21 | O5 | GPL-3.0 branch | yes |  |

| AF-F-SS-CORE(grp) | Serial-Studio@639daafb2fe7d324c3b2d5583d2514c8c470676f | app/src DataModel（Dataset/Group/Action） | 采集数据模型 | Copy | ArcScope | ArcScope.Domain / Acquisition | 数据模型 C# 移植 | 21 | O1 | GPL-3.0 branch | yes |  |

| AF-F-SS-CORE(grp) | Serial-Studio@639daafb2fe7d324c3b2d5583d2514c8c470676f | app/src Plot/Gauge/FFT/Bar 核心 widget | 可视化核心部件行为 | Copy | ArcScope | ArcScope.Visualization | 核心 widget 行为移植（视觉重绘） | 22 | O5 | GPL-3.0 branch | yes |  |

| AF-F-SS-CORE(grp) | Serial-Studio@639daafb2fe7d324c3b2d5583d2514c8c470676f | app/src 降采样（LTTB 等） | 降采样算法数值基准 | Copy | ArcScope | ArcScope.Analysis | 降采样移植（O5 基准值） | 22 | O5 | GPL-3.0 branch | yes |  |

| AF-F-SS-PRO(grp) | Serial-Studio@639daafb2fe7d324c3b2d5583d2514c8c470676f | Pro MQTT/Modbus/CAN 驱动 | 基于公开协议标准的独立 C# 实现 | Replace | ArcScope | ArcScope.Infrastructure | MQTT/Modbus/CAN 协议（O4 公开标准） | 21 | O4 | LicenseRef-SerialStudio-Commercial | no | UD-LIC-5+反克隆；不复制商业源码 |

| AF-F-SS-PRO(grp) | Serial-Studio@639daafb2fe7d324c3b2d5583d2514c8c470676f | Pro HID/USB/Audio/Process 驱动 | 平台驱动独立实现 | Replace | ArcScope | ArcScope.Native | 平台驱动独立实现（O4） | 21 | O4 | LicenseRef-SerialStudio-Commercial | no | UD-LIC-5 |

| AF-F-SS-PRO(grp) | Serial-Studio@639daafb2fe7d324c3b2d5583d2514c8c470676f | Pro Sessions 数据库 | 采集会话数据库独立实现 | Replace | ArcScope | ArcScope.Recording | Session 持久化独立实现 | 21 | O4 | LicenseRef-SerialStudio-Commercial | no | UD-LIC-5 |

| AF-F-SS-PRO(grp) | Serial-Studio@639daafb2fe7d324c3b2d5583d2514c8c470676f | Pro XY/3D/Waterfall/ImageView/Output 控件 | 可视化控件独立实现 + 品牌图形重绘 | Replace | ArcScope | ArcScope.Visualization | 控件独立实现（O4） | 22 | O4 | LicenseRef-SerialStudio-Commercial | no | UD-LIC-5 |

| AF-F-SS-PRO(grp) | Serial-Studio@639daafb2fe7d324c3b2d5583d2514c8c470676f | Pro MDF4Export / DBC/ModbusMap 导入 | MDF4 导出 + DBC/ModbusMap 导入独立实现 | Replace | ArcScope | ArcScope.ImportExport | 基于公开格式规范 | 22 | O4 | LicenseRef-SerialStudio-Commercial | no | UD-LIC-5 |

| AF-F-SS-PRO(grp) | Serial-Studio@639daafb2fe7d324c3b2d5583d2514c8c470676f | Pro AI / Licensing | AI / 激活/许可独立实现（ArcForges Entitlement） | Replace | ArcScope | ArcScope / Cloud Modules.Entitlement | 激活体系不复制；Entitlement 独立 | 21,22 | O4 | LicenseRef-SerialStudio-Commercial | no | UD-LIC-5+反克隆 |

| AF-F-SS-LIB(grp) | Serial-Studio@639daafb2fe7d324c3b2d5583d2514c8c470676f | lib/** 逐库（hidapi/KissFFT/mdflib/QCodeEditor/QSimpleUpdater/QuaZip/lua/OpenSSL/readerwriterqueue/fast_float/miniaudio/tweetnacl/ed25519_verify/SimpleCrypt） | 逐库许可证/决策，见 license-and-reuse-matrix §3；hidapi 固定 ReferenceOnly 不构建；miniaudio 0.11.25 只作设备/回调 Oracle 目标替换锁版仅编入 arcmedia_ffmpeg_abi | ReferenceOnly/Drop/Replace | ArcScope | ArcScope.Native / Infrastructure | 逐库决策（§3 表） | 21,22 | O1 | 逐库 LICENSE（§3） | yes | 每库显式 from license-and-reuse-matrix §3 |


## 7. ArcVideo（ArcSlate；Copy，GPL-3.0，AGPL 兼容，Step 23–25，Oracle O1/O5）


> 每子系统一行；权威逐行见 AF-F-ARCV-*。


| FeatureId | SourceRepo@BaselineCommit | SourcePath | Behavior | DecisionClass | TargetProduct | TargetProject | TargetDefinition | OwningStep | OracleClass | LicenseEvidence | AttributionRequired | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|


| AF-F-ARCV-0001..0066(grp) | ArcVideo@caf56513278703adec0c2933ec235bb864d72e31 | app/** 子系统 | Project/Sequence/Track/Block(Clip·Gap·Transition·Subtitle)/Footage/Player/Renderer(node 系统)/codec 包装层 每子系统一行 | Copy | ArcSlate | ArcSlate.Domain / ArcSlate.Timeline / ArcSlate.Media / ArcSlate.Processing | 各子系统 C# 移植（GPL provenance 保留） | 23–25 | O5 | ArcVideo/LICENSE (GPL-3.0) | yes | AGPL 兼容；Olive 外部参考；渲染走 Vulkan/Metal 硬件路径 |


## 8. ArcVideoFoundation（ArcSlate 媒体基础；Copy，GPL-3.0，Step 23–25 / 探针 07）


> 每值类型一行；Notes 记"Rational/TimeRange/Timecode/Color 值类型纯 C#；稳定 C 库直绑；C++ 仅经 owned C ABI"。权威逐行见 AF-F-ARCVF-*。


| FeatureId | SourceRepo@BaselineCommit | SourcePath | Behavior | DecisionClass | TargetProduct | TargetProject | TargetDefinition | OwningStep | OracleClass | LicenseEvidence | AttributionRequired | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|


| AF-F-ARCVF-0001..0010(grp) | ArcVideoFoundation@139eecaaa79dbad743a146f174a9c89a66ed594b | include/**/arcvideo/foundation（rational/TimeRange/Timecode/Color/Bezier/SampleBuffer(SIMD)） | rational/time-range/timecode/color/bezier/sample-buffer 值类型行为 | Copy | ArcSlate | ArcSlate.Domain / Foundation + native ABI | 值类型纯 C# 或稳定 C 直绑/owned C ABI | 23–25 | O5 | ArcVideoFoundation/LICENSE (GPL-3.0) | yes | PureCSharp/StableCAPI/OwnedCABI 逐类型；sse2neon 上游 BSD-2 声明保留 |


## 9. 串行合并与完整性绑定

- 本文件按来源分段、按 `feature-inventory-and-mapping.md` 现有 `AF-F-*` ID（权威容器）对接；废弃号登记不复用。ipcBridge 合同面在本文件以组级行覆盖全部 41 导出组与逐成员名；逐成员行为/契约的权威原子行保存在 `feature-inventory-and-mapping.md` §1（AF-F-AIONUI-0001..0282）。
- 零孤立双向断言：清单中每个 `SourcePath` 在来源树存在（正向）；来自 ipcBridge/renderer/process/blocksuite/siyuan-kernel/Serial-Studio 驱动·widget·lib/ArcVideo 顶层模块/ArcVideoFoundation 值类型的每个来源关键路径都在本清单（反向）。`DecisionClass`/`OracleClass`/`OwningStep` 三列无空值。
- UD-LIC 约束标注：siyuan（UD-LIC-3）、AFFiNE EE（UD-LIC-4）、Serial-Studio Pro（UD-LIC-5）行分别标注"独立实现/不复制 EE 代码/反克隆条款"，AttributionRequired=no（受限来源不进 Copied Manifest 正常行）。
- 门禁：本步一次性断言验证完整性（ipcBridge 成员覆盖差集=空、三列非空、Pro 全 Replace/O4、EE 全 ReferenceOnly、路径存在），证据见 `docs/execution/step-00-ledger.md`；仓库策略 `RepositoryPolicyTests` 禁 tracked helper scripts，断言脚本不纳入版本控制。

