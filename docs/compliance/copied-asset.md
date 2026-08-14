# Copied-Asset Manifest（移植资源清单）

> Structure per `license-and-reuse-matrix.md` §6.2; first entries per Step 00.04. Machine-readable double in
> `copied-asset.json`. `SuspiciousThirdPartyIp=true` entries are forced to `Status=Replace` and never carry a
> normal `TargetPath` (excluded/replacement section only).

## Fields

`AssetId | SourcePath | AssetClass(icon/theme/i18n/svg/palette/seed-data) | License | TargetPath | NoticeLine |
SuspiciousThirdPartyIp(bool+说明) | ReplacePlan | Status`

## First entries

### CAM-0001 — AionUi desktop i18n (13 languages)
| Field | Value |
|---|---|
| AssetId | `CAM-0001` |
| SourcePath | `AionUi/packages/desktop/locales/**`（13 语言 JSON） |
| AssetClass | i18n |
| License | Apache-2.0 |
| TargetPath | `src/ArcChat/Presentation` or DesignSystem i18n resources（键名不变） |
| NoticeLine | `NOTICE.md`: locale keys derived from AionUi (Apache-2.0) |
| SuspiciousThirdPartyIp | false |
| ReplacePlan | none（键名保持；值本地化维护） |
| Status | Planned |

### CAM-0002 — AionUi mobile theme tokens / i18n
| Field | Value |
|---|---|
| AssetId | `CAM-0002` |
| SourcePath | `AionUi/mobile/{constants/theme.ts, i18n/*, hooks/useThemeColor.ts}` |
| AssetClass | theme / i18n |
| License | Apache-2.0 |
| TargetPath | `src/Mobile/ArcChat.Mobile.*` tokens + resources（键名不变） |
| NoticeLine | `NOTICE.md`: theme tokens / i18n keys from AionUi (Apache-2.0) |
| SuspiciousThirdPartyIp | false |
| ReplacePlan | none |
| Status | Planned |

### CAM-0003 — AFFiNE blocksuite palette / default theme / partial SVG
| Field | Value |
|---|---|
| AssetId | `CAM-0003` |
| SourcePath | `AFFiNE/blocksuite/…` palette/default theme/部分 SVG |
| AssetClass | palette / theme / svg |
| License | MIT |
| TargetPath | `src/ArcNotes` + shared DesignSystem palette（按 asset 许可逐项） |
| NoticeLine | `NOTICE.md`: palette/theme/svg from AFFiNE blocksuite (MIT) |
| SuspiciousThirdPartyIp | false |
| ReplacePlan | 逐 asset 复核；有疑即转 Replace |
| Status | Planned |

### CAM-0004 — Seed data (masks / prompts / preset-assistant / builtin-MCP 结构与键)
| Field | Value |
|---|---|
| AssetId | `CAM-0004` |
| SourcePath | AionUi seed-data JSON（masks/prompts/preset-assistant/builtin-MCP 结构与键） |
| AssetClass | seed-data |
| License | Apache-2.0 |
| TargetPath | `src/ArcChat/…` seed-data（结构与键） |
| NoticeLine | `NOTICE.md`: seed data structure/keys from AionUi (Apache-2.0) |
| SuspiciousThirdPartyIp | false |
| ReplacePlan | 结构与键保持；值按产品维护 |
| Status | Planned |

### CAM-0005 — Suspicious third-party IP theme covers (REPLACE — excluded from normal flow)
| Field | Value |
|---|---|
| AssetId | `CAM-0005` |
| SourcePath | `AionUi/…hello-kitty.png`,`misaka-mikoto-theme.png` 等主题封面 |
| AssetClass | theme |
| License | unknown/第三方 IP |
| TargetPath | —（不进正常移植流） |
| NoticeLine | —（不迁入，重绘） |
| SuspiciousThirdPartyIp | **true**（疑涉第三方 IP） |
| ReplacePlan | **换入口：重绘**，不迁入 |
| Status | **Replace** |

### CAM-0006 — Serial-Studio all icons / brand (REPLACE)
| Field | Value |
|---|---|
| AssetId | `CAM-0006` |
| SourcePath | `Serial-Studio/app/**` icons/brand |
| AssetClass | icon |
| License | 商标/品牌（Serial-Studio `LICENSE.md` §7） |
| TargetPath | —（不进正常移植流） |
| NoticeLine | —（不迁入，重绘） |
| SuspiciousThirdPartyIp | **true**（商标政策） |
| ReplacePlan | **换入口：重绘** |
| Status | **Replace** |