# Copied-Asset Manifest (移植资源清单)

> First-batch structure + entries (authority: `license-and-reuse-matrix.md` §6.2, Step 00.04). Assets whose `SuspiciousThirdPartyIp=true` must have `Status=Replace` and appear only in the 排除/替换 section — never in a normal row with a `TargetPath`.

Field set: `AssetId | SourcePath | AssetClass | License | TargetPath | NoticeLine | SuspiciousThirdPartyIp | ReplacePlan | Status`.

## 正常移植行

| AssetId | SourcePath | AssetClass | License | TargetPath | NoticeLine | SuspiciousThirdPartyIp | ReplacePlan | Status |
|---|---|---|---|---|---|---|---|---|
| AS-0001 | AionUi i18n 13 语言 JSON | i18n | Apache-2.0 | `ArcForges.Desktop.Experience` / `ArcChat.Presentation` resources | retains AionUi Apache-2.0 attribution | false | none | Planned |
| AS-0002 | AionUi mobile theme token / i18n | theme/i18n | Apache-2.0 | `ArcChat.Mobile.Presentation` resources | retains AionUi Apache-2.0 attribution | false | none | Planned |
| AS-0003 | AFFiNE blocksuite palette / default theme / partial SVG | palette/theme/svg | MIT | `ArcNotes.*` / DesignTokens | retains MIT attribution | false | none | Planned |
| AS-0004 | seed data（masks/prompts/preset-assistant/builtin-MCP 的**结构与键**） | seed-data | Apache-2.0 | `ArcChat.*` seed manifests | retains AionUi Apache-2.0 attribution | false | none | Planned |

## 排除/替换节（SuspiciousThirdPartyIp=true ⇒ Status=Replace；不入正常移植流）

| AssetId | SourcePath | AssetClass | License | ReplacePlan | Status | Reason |
|---|---|---|---|---|---|---|
| AS-R1 | AionUi 疑涉第三方 IP 主题封面（`hello-kitty.png`、`misaka-mikoto-theme.png` 等） | theme cover | 未知（疑第三方 IP） | 重绘自有资源 | Replace | UD-LIC-2/§4 资源许可；疑涉第三方品牌/IP，不合法入 Copied-Asset |
| AS-R2 | Serial-Studio 全部图标/品牌 | icon/brand | LicenseRef-SerialStudio-Commercial 品牌政策 | 重绘自有品牌图形 | Replace | Serial-Studio 商标政策（LICENSE §7 禁 fork 用其品牌）；AGPL 覆盖代码不覆盖商标 |