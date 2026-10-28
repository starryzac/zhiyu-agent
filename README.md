# 知余

知余是一个把日常开支、储蓄目标和资金安排放在一起的个人财务应用。收入到账后，先留出生活需要的钱，再看看哪些目标可以往前走一步。

你可以使用十二类规则描述生活准备金、长期目标、分配偏好和操作边界；让多个目标共同分配已经到账的收入，或在明确授权后调拨目标资金。365日预测用来观察缺口与冲突，资产模块支持本地模拟申购、回款和赎回。条件不完整时，页面会逐个提出必要的问题，答案会回到候选方案中。

Agent 可以读取当前事实、解释约束、整理候选。它不能替用户确认规则，也不能代替本人提交资金操作。模型没有配置时，结构化页面和离线辅助仍可使用。

这是 Go、React 和 PostgreSQL 组成的本地模拟应用。模拟银行有独立数据库，操作会留下持久化的模拟流水；这里不连接真实银行，也不使用真实资金。

## 构建

需要 Go 1.27.2、Node.js 22.12 或更新版本、pnpm 11.25.0。下面的首次运行示例使用 Windows 上的 Docker Desktop（Linux 容器）创建独立的 PostgreSQL 16；编译本身不会建库或生成资金。

Windows 上的 PowerShell 7：

```powershell
.\scripts\build.ps1
```

已有本地依赖缓存时可以加 `-Offline`，也可用 `-StoreDir` 指定已有 pnpm 缓存。脚本构建应用、模拟银行和本地资料工具，程序在 `bin`，前端在 `web/dist`。

构建同时记录本次核心源码清单，并把对应关系写入应用与审计工具。清单位于 `bin/source-manifest.json`；审计信任配置须匹配这次构建，不能照搬另一份程序的配置。构建过程中源码发生变化会被拒绝。接口和数据库类型已随源码提供，普通构建不需要额外运行代码生成器。

## 第一次运行

请使用一个独立的本地 PostgreSQL 实例。应用库和模拟银行库分开，应用、迁移和银行也使用不同的数据库角色。不要将已有演示数据库作为新环境初始化。

配置准备入口是 `scripts/New-LocalRuntime.ps1`：

```powershell
.\scripts\New-LocalRuntime.ps1 -Root . -RuntimeDir .runtime -PostgresPort 55549 -ApiPort 19520 -BankPort 19521
```

它只生成全新的本地配置、会话码和空环境初始化 SQL，不连接数据库；已有配置目录会被拒绝。生成的 `app-runtime.json`、`migration-runtime.json`、`seed-runtime.json` 和 `bank-runtime.json` 各自用于对应角色。数据库凭据和 `demo-seed.json` 中的会话码留在本机，`.runtime` 不进入仓库。

先从生成的安装信息创建新容器。下面的命令不会显示数据库密码：

```powershell
$localInstall = Get-Content .runtime/local-install.json -Raw | ConvertFrom-Json
$containers = @(docker --context desktop-linux container ls -a --format '{{.Names}}')
if ($LASTEXITCODE -ne 0) { throw '请先启动 Docker Desktop 的 Linux 容器引擎' }
$volumes = @(docker --context desktop-linux volume ls --format '{{.Name}}')
if ($LASTEXITCODE -ne 0) { throw '无法读取本地 Docker 卷' }
if ($containers -contains $localInstall.container -or $volumes -contains $localInstall.volume) { throw '生成的容器或卷已存在，请保留并检查' }
docker --context desktop-linux volume create --label 'zhiyu.owner=zhiyu-go' --label "zhiyu.install=$($localInstall.environment)" $localInstall.volume
if ($LASTEXITCODE -ne 0) { throw '创建新卷失败' }
docker --context desktop-linux run -d --name $localInstall.container --label 'zhiyu.owner=zhiyu-go' --label "zhiyu.install=$($localInstall.environment)" --env-file .runtime/postgres.env -p "127.0.0.1:$($localInstall.ports.postgres):5432" --mount "type=volume,source=$($localInstall.volume),target=/var/lib/postgresql/data" $localInstall.postgres_image
if ($LASTEXITCODE -ne 0) { throw '启动新数据库容器失败' }
docker --context desktop-linux exec $localInstall.container pg_isready -U zygo_install_admin -d postgres
```

等 `pg_isready` 显示数据库正在接受连接，再创建库和角色：

```powershell
Get-Content .runtime/new-cluster-only.sql -Raw | docker --context desktop-linux exec -i --user postgres $localInstall.container psql -X -w -h /var/run/postgresql -U zygo_install_admin -d postgres
if ($LASTEXITCODE -ne 0) { throw '新数据库初始化未完成，请保留现场检查' }
.\bin\zhiyu.exe migrate -config .runtime/migration-runtime.json
if ($LASTEXITCODE -ne 0) { throw '应用数据库迁移未完成' }
```

接着在单独终端首次启动模拟银行并应用三组银行迁移：

```powershell
.\scripts\Start-LocalRole.ps1 -Root . -Role bank -InitializeBank
```

银行会持续运行，保留这个终端。回到初始化终端创建应用侧空账户，并登记银行侧的零原件：

```powershell
.\bin\zhiyu.exe seed -config .runtime/seed-runtime.json
if ($LASTEXITCODE -ne 0) { throw '空账户创建未完成' }
$bankDatabase = $localInstall.environment + '_bank'
Get-Content .runtime/bank-zero-only.sql -Raw | docker --context desktop-linux exec -i --user postgres $localInstall.container psql -X -w -h /var/run/postgresql -U zygo_bank -d $bankDatabase
if ($LASTEXITCODE -ne 0) { throw '银行空账户初始化未完成' }
```

这一步只登记同一 seed 的零余额账户、零开账原件和初始零目标，不会创建收入、资金操作、规则或授权。应用侧 seed 不会自动完成银行侧登记。

首次启用后台前，打开生成的 `.runtime/START-HERE.txt`，按照本机步骤和请求模板完成控制初始化。配置脚本不会直接把环境改为可写，也不会预先授予资金权限；当前状态需要实际核对，不能用预填的拥有者信息或另一环境的停止记录代替。生成文件、空账户准备和后台可以执行是不同的步骤。

## 日常启动

下面使用上节的端口和配置目录，分别在终端运行。同一个角色只运行一份；初始化时仍在运行的银行继续使用原终端，后续重启时再使用这里的银行命令：

```powershell
.\scripts\Start-LocalRole.ps1 -Root . -Role bank
.\scripts\Start-LocalRole.ps1 -Root . -Role api
.\scripts\Start-LocalRole.ps1 -Root . -Role worker
.\scripts\Start-LocalRole.ps1 -Root . -Role native-standing
.\scripts\Start-LocalRole.ps1 -Root . -Role projection
```

启动入口运行固定的正常产品程序，并在本机记录启动与退出；在各自终端按 Ctrl+C 正常关闭。重启沿用原配置和资料，如果上次关闭了写入，按本机步骤核对恢复，不重新初始化。

打开 `http://127.0.0.1:19520`，用本机 `demo-seed.json` 的 `login_secret` 作为会话码登录。首次创建的是空账户；有页面不代表已经到账、已经授权或已经产生银行效果。

API 提供前端时，`app-runtime.json` 的 `web_origin` 必须与 API 地址一致。本地启动入口固定使用这组同源配置。

开发前端时，可以另用浏览器 origin 为 `http://127.0.0.1:5178` 的开发配置，直接启动不带 `-web-root` 的 API，再设置 `ZHIYU_API_TARGET` 指向该 API 后运行 `pnpm --dir web dev`。开发配置不要混用到上面的固定启动入口；`pnpm preview` 不代理后端接口。

## 演示和使用边界

先在“我的规则”中创建并本人确认规则，再到“目标与执行”查看候选和授权范围。保存草稿不会使规则生效，规则生效也不等于已经授予持续执行权限。金额、单次上限、累计上限与截止时间会分别检查。

模拟收入工具 `creditseed` 使用单独的本地来源授权文件，保留签名事件和原事件键；它不是登录页面的一键加钱按钮。历史资料和审计签名材料也由本机操作者单独准备，不随仓库分发。仓库不包含其他用户的数据或预先授予的资金权限。

操作显示待核对时，保留原计划、原操作键和浏览器中的恢复资料，按原记录继续查询。不要清理本地数据或换一个新请求重做。浏览器恢复资料依赖 IndexedDB；更换浏览器或清除站点存储后，不会凭空找回另一份本地原件。

可选模型配置模板在 `config/deepseek.example.json`。将它复制到本机运行配置目录的 `deepseek.json` 后，显式启用并设置其中指定的环境变量。密钥不要写进源码；实际模型调用会把获准的模拟资料发给配置的服务并产生费用。模型不可用时，页面会保留失败提示，不把工具读取或候选状态改写成资金操作完成。

## 代码

```text
cmd/            应用、模拟银行和本地资料工具
internal/       规则、规划、授权、执行、审计与HTTP接口
db/             应用迁移、查询和内嵌银行结构
api/openapi/    接口契约
web/src/        React页面和恢复资料存储
config/         可选模型配置模板
scripts/        本地构建与初始化入口
```

依赖的许可原文保留在 `licenses`，对应关系见 `THIRD-PARTY-NOTICES.txt`。
