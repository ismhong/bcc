# libbpf-tools 到 libbpf-tools-rs 移植優先順序規劃

此文件列出了原 C 語言版 `libbpf-tools` 下的所有工具，並根據其實用性、系統監控價值以及診斷排障的優先順序進行分級。這將做為我們後續依序移植工具至 Rust/Aya (`libbpf-tools-rs`) 的導引路線圖。

---

## 移植優先級彙總表

| 順序 | 工具名稱 (Tool) | 優先級 (Priority) | 監控維度 (Dimension) | 實用價值與描述 |
| :--- | :--- | :--- | :--- | :--- |
| 1 | **opensnoop** | 已完成 | 檔案系統 (FS) | 追蹤檔案開啟行為（已完成實作與 Android 驗證）。 |
| 2 | **execsnoop** | 已完成 | 行程管理 (Process) | 追蹤行程執行與參數（已完成實作與 Android 驗證）。 |
| 3 | **tcpconnect** | **P0 (極高)** | 網路 (Network) | 追蹤主動發起的 TCP 連線與目的位址。網路排障最常用工具。 |
| 4 | **biolatency** | **P0 (極高)** | 磁碟 I/O (Storage) | 以直方圖顯示區塊裝置 I/O 延遲分佈。磁碟效能分析首選。 |
| 5 | **oomkill** | **P0 (極高)** | 記憶體 (Memory) | 捕捉系統 OOM (Out Of Memory) 殺死行程事件，記錄時間與釋放記憶體。 |
| 6 | **sigsnoop** | **P0 (極高)** | 行程管理 (Process) | 追蹤系統中傳送的各種 Signal 信號（如 kill -9），定位非預期退出的進行。 |
| 7 | **tcplife** | **P1 (高)** | 網路 (Network) | 記錄 TCP 連線生命週期，包括連線時間、傳輸吞吐量與連線時長。 |
| 8 | **biosnoop** | **P1 (高)** | 磁碟 I/O (Storage) | 追蹤每一次區塊裝置 I/O 的詳細請求，計算硬碟響應時間。 |
| 9 | **runqlat** | **P1 (高)** | CPU / 調度 (CPU) | 統計行程在 CPU 運行佇列（Run Queue）中的等待時間（調度延遲）。 |
| 10 | **syscount** | **P1 (高)** | 系統呼叫 (Syscall) | 統計系統呼叫的次數與延遲，找出系統效能瓶頸。 |
| 11 | **memleak** | **P1 (高)** | 記憶體 (Memory) | 偵測核心與用戶空間的記憶體洩漏，並印出分配棧軌跡。 |
| 12 | **filetop** | **P1 (高)** | 檔案系統 (FS) | 類似 top 指令，即時顯示檔案讀寫頻率最頻繁的檔案與行程。 |
| 13 | **tcpconnlat** | **P1 (高)** | 網路 (Network) | 計算 TCP 連線建立時的三向交握延遲（SYN 到 ACK 的時間）。 |
| 14 | **offcputime** | **P1 (高)** | CPU / 調度 (CPU) | 追蹤行程離開 CPU 處於等待狀態的原因與調用棧，用於分析阻塞效能瓶頸。 |
| 15 | **profile** | **P2 (中)** | CPU / 調度 (CPU) | 定時採樣 CPU 調用棧（Stack traces），用於產生成效能火焰圖（Flame Graphs）。 |
| 16 | **capable** | **P2 (中)** | 安全 (Security) | 監控系統中權限檢查（Linux Capabilities）的結果，可用於安全審計。 |
| 17 | **hardirqs** | **P2 (中)** | 系統中斷 (Interrupt) | 統計硬體中斷（Hard IRQ）的次數與處理耗時。 |
| 18 | **softirqs** | **P2 (中)** | 系統中斷 (Interrupt) | 統計軟體中斷（Soft IRQ）的次數與處理耗時。 |
| 19 | **mountsnoop** | **P2 (中)** | 檔案系統 (FS) | 追蹤 Mount 命名空間的操作（mount/unmount），容器診斷必備。 |
| 20 | **fsslower** | **P2 (中)** | 檔案系統 (FS) | 追蹤超過特定閾值的慢速檔案系統讀寫操作（支援 ext4, xfs, nfs 等）。 |
| 21 | **tcprtt** | **P2 (中)** | 網路 (Network) | 採樣並統計 TCP 連線的 RTT（往返時間）分佈。 |
| 22 | **tcpstates** | **P2 (中)** | 網路 (Network) | 追蹤 TCP 狀態機的轉換過程（如 ESTABLISHED -> CLOSE_WAIT）。 |
| 23 | **vfsstat** | **P2 (中)** | 檔案系統 (FS) | 統計常見 VFS 操作（read, write, open, fsync）的每秒執行次數。 |
| 24 | **runqslower** | **P2 (中)** | CPU / 調度 (CPU) | 追蹤並列印出等待運行佇列時間超過設定閾值的行程。 |
| 25 | **statsnoop** | **P2 (中)** | 檔案系統 (FS) | 追蹤 stat() 系列系統呼叫，常用於定位「檔案未找到」的載入路徑問題。 |
| 26 | **stackcount** | **P2 (中)** | 調用鏈 (Stack) | 統計特定核心/用戶空間函數的呼叫次數，並按調用棧聚合。 |
| 27 | **funclatency** | **P2 (中)** | 調用鏈 (Stack) | 測量特定核心/用戶空間函數的執行延遲，以直方圖呈現。 |
| 28 | **funcslower** | **P2 (中)** | 調用鏈 (Stack) | 追蹤執行時間超過設定閾值的特定函數。 |
| 29 | **oomkill** | **P2 (中)** | 記憶體 (Memory) | 捕捉 OOM 事件與行程資訊。 |
| 30 | **readahead** | **P3 (低)** | 檔案系統 (FS) | 評估預讀（Readahead）機制的使用率與效率。 |
| 31 | **cachestat** | **P3 (低)** | 記憶體 (Memory) | 統計頁快取（Page Cache）的命中率與髒頁寫回狀況。 |
| 32 | **bashreadline** | **P3 (低)** | 安全 / 行為 (Behavior) | 監控全系統終端機中輸入的 Bash 命令列（追蹤 readline 呼叫）。 |
| 33 | **bindsnoop** | **P3 (低)** | 網路 (Network) | 監控 Socket bind() 綁定埠口的行為，追蹤埠口衝突與佔用。 |
| 34 | **exitsnoop** | **P3 (低)** | 行程管理 (Process) | 追蹤行程的退出事件與退出狀態碼（exit code）。 |
| 35 | **forksnoop** | **P3 (低)** | 行程管理 (Process) | 追蹤行程 fork() / clone() 衍生新進程的關係鏈。 |
| 36 | **gethostlatency** | **P3 (低)** | 網路 (Network) | 追蹤 DNS 查詢解析（getaddrinfo/gethostbyname）的響應延遲。 |
| 37 | **solisten** | **P3 (低)** | 網路 (Network) | 監控程式呼叫 listen() 開始監聽埠口的事件。 |
| 38 | **drsnoop** | **P3 (低)** | 記憶體 (Memory) | 追蹤記憶體直接回收（Direct Reclaim）的次數與延遲。 |
| 39 | **filelife** | **P3 (低)** | 檔案系統 (FS) | 追蹤短期檔案（建立後很快就被刪除）的存活時間分佈。 |
| 40 | **ksnoop** | **P3 (低)** | 核心除錯 (Kernel) | 核心函數呼叫參數與返回值的通用追蹤器（需要較新核心支援）。 |
| 41 | **memleaktop** | **P3 (低)** | 記憶體 (Memory) | 即時顯示目前分配記憶體最多且疑似洩漏的行程。 |
| 42 | **cpuidle** | **P3 (低)** | CPU / 電源 (Power) | 追蹤 CPU 進入與退出 Idle 狀態的事件與電源管理分析。 |
| 43 | **cpufreq** | **P3 (低)** | CPU / 電源 (Power) | 監控 CPU 頻率動態調頻的轉換過程。 |
| 44 | **cpudist** | **P3 (低)** | CPU / 調度 (CPU) | 統計行程在 CPU 上連續執行的時間長度分佈。 |
| 45 | **cmasnoop** | **P3 (低)** | 記憶體 (Memory) | 追蹤連續記憶體分配（CMA）的申請與釋放行為。 |
| 46 | **cmatop** | **P3 (低)** | 記憶體 (Memory) | 即時顯示 CMA 記憶體佔用排行榜。 |
| 47 | **cmatrack** | **P3 (低)** | 記憶體 (Memory) | 追蹤 CMA 記憶體分配生命週期。 |
| 48 | **gpumemtop** | **P3 (低)** | GPU 監控 (GPU) | 監控 GPU 記憶體分配與使用率狀況（特定硬體適用）。 |
| 49 | **rtkheaptop** | **P3 (低)** | 記憶體 (Memory) | 追蹤即時作業系統特定的堆積分配。 |
| 50 | **schedblockedtop** | **P3 (低)** | CPU / 調度 (CPU) | 追蹤被阻塞的行程與導致阻塞的調用棧排行榜。 |
| 51 | **tcpsynbl** | **P3 (低)** | 網路 (Network) | 統計 TCP SYN Backlog 佇列長度，判斷是否有 SYN Flood 攻擊。 |
| 52 | **tcppktlat** | **P3 (低)** | 網路 (Network) | 追蹤 TCP 封包在主機協定棧中的傳輸延遲。 |
| 53 | **tcptracer** | **P3 (低)** | 網路 (Network) | 追蹤 TCP 連線的狀態轉換細節與主動/被動連線過程。 |
| 54 | **vmallocleak** | **P3 (低)** | 記憶體 (Memory) | 追蹤核心空間 vmalloc 虛擬記憶體的分配與洩漏。 |
| 55 | **vmoom** | **P3 (低)** | 記憶體 (Memory) | 統計核心空間的 OOM 事件統計資訊。 |
| 56 | **whoentercritical** | **P3 (低)** | 鎖競爭 (Locking) | 監控哪些行程進入了核心臨界區。 |
| 57 | **whoentersmc** | **P3 (低)** | 網路 (Network) | 追蹤進入 SMC (Shared Memory Communications) 協定的連線。 |
| 58 | **biostacks** | **P3 (低)** | 磁碟 I/O (Storage) | 追蹤 I/O 請求產生的核心調用棧。 |
| 59 | **llcstat** | **P3 (低)** | 緩取 (Cache) | 統計最後一級快取（LLC）的命中與未命中次數。 |
| 60 | **mdflush** | **P3 (低)** | 磁碟 I/O (Storage) | 追蹤軟 RAID (MD) 的 Flush 清理行為。 |
| 61 | **runqlen** | **P3 (低)** | CPU / 調度 (CPU) | 追蹤 CPU 運行佇列的長度分佈。 |
| 62 | **syncsnoop** | **P3 (低)** | 檔案系統 (FS) | 追蹤 sync() 系統呼叫，了解何時發生全系統資料強制同步寫回。 |

---

## 核心 P0 級移植順序與指南

在後續的工具移植中，請依照 `libbpf-to-rust-aya` 指導手冊，優先執行以下 P0 級工具的移植：

1. **`tcpconnect`**
   - **核心掛載點**：`tcp_v4_connect` 與 `tcp_v6_connect` 的 Entry/Exit。
   - **Android 兼容**：需要特別關注 Android 核心中這兩個符號是否被導出，以及如何使用 kprobes 穩定掛載。
2. **`biolatency`**
   - **核心掛載點**：區塊 I/O 請求的生命週期探針（如 `block_rq_insert`, `block_rq_issue`, `block_rq_complete` 等）。
   - **Android 兼容**：區塊層探針通常為 tracepoints。在無 tracepoints 的 Android Box 設備上，需查找核心區塊驱动底層的替代掛載函數。
3. **`oomkill`**
   - **核心掛載點**：`oom_kill_process` 核心函數。
4. **`sigsnoop`**
   - **核心掛載點**：`get_signal` 或系統呼叫 `sys_kill`, `sys_tgkill` 等進入點。
