# libbpf-tools-rs：基於 Rust (Aya) 的 Busybox eBPF 追蹤工具套件

`libbpf-tools-rs` 是一個現代化、基於 Rust 與 **Aya** eBPF 框架開發的系統監控與追蹤工具套件。本專案將經典的 C 語言版本 `libbpf-tools` 重構，並整合成類似 Busybox 的**單一靜態二進位檔** `bcc-box`。透過在單一檔案內進行多指令路由分流，大幅簡化了工具在目標系統上的佈署成本。

本套件採用完全靜態連結（Static Linking），針對各種 Linux 主機、容器環境以及無內建 BTF 的遠端 Android 設備（AArch64）進行了深度最佳化。

---

## 專案架構與元件組成

整個專案由 `libbpf-tools-rs/` 子目錄下的四個核心 Crate 組成：

1. **`bcc-box` (用戶空間主程式 CLI)**
   - 負責與使用者互動的主程式。
   - 支援 **Busybox 式的軟連結路由**：如果將主程式建立軟連結至特定的工具名稱（例如 `opensnoop` -> `bcc-box`），直接執行 `opensnoop` 即會執行對應的追蹤功能。
   - 負責載入外部 BTF 檔案、進行 CO-RE 重定位、初始化 BPF Ring Buffer 並格式化輸出事件。
2. **`bcc-box-ebpf` (核心空間 eBPF 程式)**
   - 包含寫入核心的 eBPF 原始碼。
   - 使用 Rust `nightly` 工具鏈編譯，目標平台為 `bpfel-unknown-none`。
3. **`bcc-box-common` (共享資料結構)**
   - 定義核心空間（eBPF）與用戶空間（Userspace）通訊所需的共享資料型態（例如 `Event` 結構體）。
4. **`xtask` (BPF 編譯輔助工具)**
   - 一個自動化建置輔助任務。使用 nightly 工具鏈將 `bcc-box-ebpf` 編譯成 eBPF 檔案，並複製到 `bcc-box/resources/`，以便 userspace 程式在編譯時透過 `include_bytes!` 將 bytecode 直接打包嵌入。

---

## 技術亮點與特色

- **完全靜態連結 (Static Linking)**：支援 `musl` 編譯目標（`x86_64-unknown-linux-musl` 與 `aarch64-unknown-linux-musl`），編譯出無任何動態連結庫依賴的獨立執行檔。
- **外部 BTF 載入支援 (`--btf` / `LIBBPF_VMLINUX_BTF`)**：針對預設沒有 `/sys/kernel/btf/vmlinux` 的核心（例如許多 Android 設備），可透過 `--btf /path/to/vmlinux` 參數或設定 `LIBBPF_VMLINUX_BTF` 環境變數手動載入獨立 BTF 檔案，確保 CO-RE 順暢運作。
- **繞過 ARM64 LTO 優化（二級 `pt_regs` 解引用）**：在啟用了 LTO（連結時間最佳化）的核心中，編譯器可能會重排或挪用核心函數的暫存器。`bcc-box` 掛載在穩定的 syscall wrappers 入口（`__arm64_sys_*`），並透過對暫存器指標進行二級解引用，安全且精準地讀取暫存器參數。
- **相容 32 位元 Compat 進程**：在 ARM64 系統上，同時掛載 64 位元 (`__arm64_sys_*`) 與 32 位元相容模式 (`__arm64_compat_sys_*`) 的 syscall 入口點，保證能完整追蹤系統中混合運行的 32 位元與 64 位元進程。

---

## 建置前置需求

編譯本套件需要安裝 Rust 工具鏈與對應的編譯目標：

1. **安裝 Rustup**
2. **安裝 Nightly 工具鏈與 BPF Target**（用於編譯 eBPF 程式碼）：
   ```bash
   rustup toolchain install nightly
   rustup target add --toolchain nightly bpfel-unknown-none
   ```
3. **跨平台編譯目標**（選填，若需交叉編譯）：
   ```bash
   rustup target add aarch64-unknown-linux-musl
   rustup target add x86_64-unknown-linux-musl
   ```

---

## 建置步驟

本專案提供了一個 `build.sh` 輔助腳本與 `Makefile`，讓您可以在不同平台上簡單地一鍵編譯。

進入 `libbpf-tools-rs/` 目錄並執行編譯指令：

### 1. 編譯目前主機架構 (Host, 預設)
編譯 eBPF 位元組碼並為當前的主機編譯 userspace 程式：
```bash
make host
# 或: ./build.sh host
```
產出的二進位檔案將會位於 `target/release/bcc-box`。

### 2. 交叉編譯至 ARM64 (AArch64 Musl)
```bash
make arm64
# 或: ./build.sh arm64
```
產出的二進位檔案將會位於 `target/aarch64-unknown-linux-musl/release/bcc-box`。

### 3. 交叉編譯至 x86_64 (x86_64 Musl)
```bash
make x86_64
# 或: ./build.sh x86_64
```
產出的二進位檔案將會位於 `target/x86_64-unknown-linux-musl/release/bcc-box`。

### 4. 編譯所有平台
```bash
make all
# 或: ./build.sh all
```

### 5. 清理編譯快取與產出
```bash
make clean
# 或: ./build.sh clean
```

---

## 使用說明

### 1. 直接執行子命令
執行 `bcc-box` 主程式並傳入子命令（工具名稱）：
```bash
# 基本語法
./bcc-box <工具名稱> [選項]

# 範例：指定外部 BTF 檔案並執行 opensnoop
./bcc-box --btf /data/vmlinux opensnoop
```

### 2. Busybox 軟連結路由
您可以為支援的工具建立軟連結。主程式會根據執行的檔名自動分流至正確的功能：
```bash
# 建立軟連結
ln -s bcc-box opensnoop
ln -s bcc-box execsnoop

# 直接透過軟連結執行（效果等同於帶子命令執行）
./opensnoop --btf /data/vmlinux
./execsnoop --btf /data/vmlinux
```

---

## 目前支援的工具

- **`opensnoop`**：追蹤全系統的檔案開啟（open/openat）行為，顯示行程 PID、指令名稱、傳回的檔案描述符（FD）、錯誤碼以及檔案路徑。
- **`execsnoop`**：追蹤全系統新進程的執行（execve）軌跡，捕捉行程名稱、父行程 ID、執行傳回值與完整的命令列參數。
