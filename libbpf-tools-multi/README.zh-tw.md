# libbpf-tools-multi — Busybox 風格多呼叫二進位檔

一個靜態連結的單一二進位檔 (`libbpf-tools-box`)，包含來自 [`libbpf-tools/`](../libbpf-tools/) 的全部 91 個工具，依照名稱進行分派 — 就像 BusyBox 一樣。

---

## 概述

與其分發 91 個獨立的二進位檔（每個都重複包含 libbpf、skeleton 位元碼和輔助程式碼），`libbpf-tools-box` 將它們全部打包到一個檔案中。這在嵌入式 Linux / Android 等儲存空間和傳輸頻寬寶貴的環境中尤其重要。

```
libbpf-tools-box opensnoop            # 直接呼叫
libbpf-tools-box softirqs 1 5
ln -s libbpf-tools-box opensnoop && ./opensnoop   # busybox 符號鏈接風格
```

全部 91 個工具保留其完整功能集；唯一的差異在於呼叫方式。

---

## 前置需求

您**必須**先建置 `libbpf-tools/`。這會產生：

- `libbpf-tools/.output/libbpf.a` — libbpf 靜態函式庫
- `libbpf-tools/.output/<tool>.skel.h` — 每個工具的 BPF 骨架
- `libbpf-tools/.output/bpftool` —（僅在建置過程中使用）

```bash
# 主機建置
make -C ../libbpf-tools

# 交叉編譯 arm64
make -C ../libbpf-tools ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-

# 交叉編譯 arm32
make -C ../libbpf-tools ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf-
```

---

## 建置

```bash
cd libbpf-tools-multi/

# 原生主機建置
make

# 交叉編譯 arm64
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-

# 交叉編譯 arm32
make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf-
```

產出的二進位檔為目前目錄下的 `libbpf-tools-box`。

---

## 使用方法

### 直接呼叫

```bash
./libbpf-tools-box opensnoop
./libbpf-tools-box softirqs 1 5
./libbpf-tools-box runqlat --help
./libbpf-tools-box profile -F 99 10
```

### Busybox 符號鏈接風格

一條指令建立所有工具的**符號鏈接**：

```bash
./libbpf-tools-box --install -f /usr/local/bin
./opensnoop
./softirqs 1 5
```

或在編譯後直接使用 `make install`：

```bash
make install DESTDIR=/usr/local/bin
```

詳細選項請參閱 [`--install`](#--install)。

### --list

列出所有可用的工具名稱（每行一個，適合腳本使用）：

```bash
./libbpf-tools-box --list
argdist
bashreadline
bindsnoop
...
```

### --install

在目標目錄中為所有工具建立符號鏈接（或硬鏈接）：

```bash
# 建立符號鏈接（預設）
./libbpf-tools-box --install /usr/local/bin

# 硬鏈接（同一 filesystem，節省空間）
./libbpf-tools-box --install -H /usr/local/bin

# 強制覆蓋已存在的鏈接
./libbpf-tools-box --install -f /usr/local/bin

# 詳細模式 — 顯示每個鏈接的建立過程
./libbpf-tools-box --install -v -f /data/bcc/bin
```

選項說明：

| 旗標 | 長格式 | 說明 |
|---|---|---|
| *(預設)* | | 建立符號鏈接 |
| `-s` | `--symbolic` | 明確指定符號鏈接（同預設） |
| `-H` | `--hardlink` | 建立硬鏈接 |
| `-f` | `--force` | 強制覆蓋已存在的檔案/鏈接 |
| `-v` | `--verbose` | 顯示每個鏈接的建立過程 |

### 在 Android 上使用

```bash
adb push libbpf-tools-box /data/libbpf-tools-box
adb shell "chmod +x /data/libbpf-tools-box"
adb shell "/data/libbpf-tools-box opensnoop"
adb shell "/data/libbpf-tools-box --btf /data/vmlinux softirqs 1 2"

# 在裝置上安裝所有符號鏈接
adb shell "mkdir -p /data/bcc/bin"
adb shell "/data/libbpf-tools-box --install -f /data/bcc/bin"
adb shell "ls -l /data/bcc/bin/opensnoop"
# → lrwxrwxrwx ... /data/bcc/bin/opensnoop -> /data/libbpf-tools-box
```

---

## 架構

### Wrapper 包裝手法

`libbpf-tools/` 中的工具無法直接鏈接在一起，因為其中 68+ 個工具定義了彼此衝突的非靜態全域符號（例如 `argp_program_version`、`handle_event`、`libbpf_print_fn`、`main`）。

**解決方案：** 對於每個工具，Makefile 會在 `.output/wrappers/<tool>.c` 自動產生一個輕量 wrapper `.c`。該 wrapper 使用 C 前置處理器的 `#define` 在 `#include` 原始工具原始碼**之前**重新命名衝突的符號：

```c
/* opensnoop 的自動產生 wrapper — 請勿手動編輯 */
#define main                     opensnoop_main
#define argp_program_version     opensnoop_argp_version
#define argp_program_bug_address opensnoop_argp_bug_address
#define argp_program_doc         opensnoop_argp_doc
#define argp_args_doc            opensnoop_argp_args_doc
#define handle_event             opensnoop_handle_event
#define handle_lost_events       opensnoop_handle_lost_events
#define libbpf_print_fn          opensnoop_libbpf_print_fn
#include "/path/to/libbpf-tools/opensnoop.c"
```

- 工具 `.c` 內部的**靜態**（`static`）全域變數/函式維持不變 — 它們在不同翻譯單元之間永遠不會衝突。
- 所有衝突的**非靜態**符號都會獲得每個工具獨有的名稱。
- 使用 `#include` 引入 `.c` 檔案是刻意為之，這也是如何套用重新命名的方式。

### 共享與獨有的部分

| 項目 | 處理方式 |
|---|---|
| `libbpf.a` | 只鏈接一次，由所有工具共享 |
| `trace_helpers.o`、`compat.o` 等 | 從 `libbpf-tools/*.c` 編譯一次，只鏈接一次 |
| 工具 BPF 骨架（`*.skel.h`） | 嵌入在每個工具的物件檔中（每個工具獨有） |
| `argp_program_version`、`main` 等 | 透過 wrapper 中的 `#define` 為每個工具重新命名 |
| 工具 `.c` 內部的靜態輔助函式 | 保持 `static` — 不可能衝突 |

### 建置階段

1. **第一階段 — 前置需求檢查**：確認 `../libbpf-tools/.output/libbpf.a` 存在。若不存在則顯示有幫助的錯誤訊息並退出。
2. **第二階段 — 建置**：
   - 為每個工具產生 wrapper `.c`
   - 編譯每個 wrapper `.o`（使用預先建置的 `*.skel.h`）
   - 從 `libbpf-tools/*.c` 編譯共用輔助 `.o` 檔案
   - 將所有內容與 `libbpf.a` 鏈接 → `libbpf-tools-box`

---

## 上游同步與新增工具

本目錄**永遠不會修改 `../libbpf-tools/` 中的檔案**。同步上游很簡單：

```bash
git fetch upstream
git merge upstream/main
# 完成 — 本目錄不會碰觸 libbpf-tools/
```

### 當上游新增工具時

假設上游新增了 `newtool`（即合併後出現了含有 `main()` 的 `libbpf-tools/newtool.c`）：

1. 將 `newtool` 加入 [`Makefile`](Makefile) 的 `TOOLS` 列表中。
2. 在 [`dispatch.c`](dispatch.c) 中加入 `extern int newtool_main(int argc, char **argv);`。
3. 在 `dispatch.c` 的 `tools[]` 表格中加入 `{ "newtool", newtool_main }`。
4. 執行 `make` — wrapper 會自動產生，工具會編譯並鏈接。

`libbpf-tools/` 本身不需要任何修改。

### 如果建置失敗並出現「multiple definition」錯誤

上游新增了會衝突的非靜態全域符號。修正方式：

1. 從鏈接器錯誤訊息中找出該符號。
2. 在 `Makefile` 的 wrapper 產生規則中加入一行 `#define`：
   ```makefile
   printf '#define new_symbol  %s_new_symbol\n' "$$TOOL" >> $@; \
   ```
3. 重新建置 — `libbpf-tools/` 不需要任何修改。

### 每個 wrapper 中都重新命名的符號

| 原始符號 | 重新命名為 |
|---|---|
| `main` | `TOOL_main` |
| `argp_program_version` | `TOOL_argp_version` |
| `argp_program_bug_address` | `TOOL_argp_bug_address` |
| `argp_program_doc` | `TOOL_argp_doc` |
| `argp_args_doc` | `TOOL_argp_args_doc` |
| `handle_event` | `TOOL_handle_event` |
| `handle_lost_events` | `TOOL_handle_lost_events` |
| `libbpf_print_fn` | `TOOL_libbpf_print_fn` |

這些 `#define` 會套用到每個工具（若工具未使用某個特定符號，則不會造成影響）。

---

## 驗證

```bash
# 計算獨立的 _main 符號數量 — 應為 91
nm libbpf-tools-box | grep '_main$' | wc -l

# 確認沒有裸露的 handle_event（全部都應有前綴）
nm libbpf-tools-box | grep 'T handle_event' || echo "OK: no bare handle_event"

# 或使用內建的 verify 目標
make verify
```

---

## 大小比較

| 方式 | 大約大小（arm64 靜態連結） |
|---|---|
| 91 個獨立二進位檔 | ~91 × 4 MB ≈ 364 MB |
| `libbpf-tools-box` 多呼叫 | ~20–30 MB（共享 libbpf + 骨架） |

確切數字取決於核心版本、除錯資訊和壓縮方式。

---

## 本目錄中的檔案

| 檔案 | 用途 |
|---|---|
| `Makefile` | 建置系統（產生 wrapper、編譯、鏈接） |
| `dispatch.c` | `main()` 分派器 — 根據 argv[0] 或 argv[1] 路由 |
| `README.md` | 本檔案（英文版） |
| `README.zh-tw.md` | 本檔案（繁體中文版） |
| `.output/wrappers/` | 自動產生的 wrapper `.c` 檔案（已加入 gitignore） |
| `.output/*.o` | 編譯後的物件檔（已加入 gitignore） |
| `libbpf-tools-box` | 產出的二進位檔（已加入 gitignore） |
