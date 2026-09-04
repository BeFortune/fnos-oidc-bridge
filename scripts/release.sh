#!/usr/bin/env bash
# 一键发布:构建 FPK → 带版本号重命名 → sha256 → gh release create
# 用法: scripts/release.sh ["自定义 release 说明"]
# 不传说明时自动取 manifest 的 changelog 字段。网络不通时先 export HTTPS_PROXY=...
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION=$(awk -F= '/^version/{gsub(/[ \t]/,"",$2);print $2}' fpk/manifest)
[ -n "$VERSION" ] || { echo "manifest 里读不到 version" >&2; exit 1; }
TAG="v$VERSION"
PKG="fnosoidcbridge-$VERSION.fpk"

if gh release view "$TAG" >/dev/null 2>&1; then
  echo "release $TAG 已存在,如需重发请先删除: gh release delete $TAG" >&2
  exit 1
fi

bash "$ROOT/scripts/build-fpk.sh"

cp -f fnosoidcbridge.fpk "$PKG"
sha256sum "$PKG" > "$PKG.sha256"

CHANGELOG=$(awk -F= '/^changelog/{sub(/^[ \t]+/,"",$2);print $2}' fpk/manifest)
NOTES="${1:-$CHANGELOG}"

gh release create "$TAG" "$PKG" "$PKG.sha256" \
  --title "$TAG" \
  --notes "## fnos-oidc-bridge $VERSION

$NOTES

### 安装

\`\`\`bash
appcenter-cli install-fpk --volume 1 $PKG
\`\`\`

要求 fnOS 1.2.x。SHA256 校验: \`sha256sum -c $PKG.sha256\`

> ⚠️ 网页上传 FPK 提示「Failed to fetch」可无视,刷新应用中心即已装好;SSH 安装无此问题。"

echo "已发布: $(gh release view "$TAG" --json url -q .url)"
