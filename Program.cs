using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Windows.Forms;
using Microsoft.Data.Sqlite;
using System.Management;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Reflection;
using System.Timers;

namespace Antivirus
{
    class Program
    {
        private static NotifyIcon? trayIcon;
        private static string quarantinePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SimpleAntivirus", "Quarantine");
        private static string dbPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SimpleAntivirus", "ScanHistory.db");
        private static string logPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SimpleAntivirus", "Logs");
        private static readonly HttpClient httpClient = new HttpClient();
        private static readonly string apiKey = "46219682e8f5d9ab59eebc93a442dab6a9577e33d1f6f3ed47720252782fd6a3"; // VirusTotal API key
        private static readonly List<FileSystemWatcher> watchers = new List<FileSystemWatcher>();
        private static readonly System.Timers.Timer scanTimer = new System.Timers.Timer(3600000); // Scan every hour
        private static readonly HashSet<string> criticalSystemFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "ntdll.dll", "kernel32.dll", "user32.dll", "gdi32.dll", "advapi32.dll",
            "shell32.dll", "msvcrt.dll", "rpcrt4.dll", "ole32.dll", "comctl32.dll"
        };

        [STAThread]
        static void Main()
        {
            try
            {
                Console.WriteLine("Starting Simple Antivirus...");
                Application.EnableVisualStyles();
                Console.WriteLine("Visual styles enabled.");
                Application.SetCompatibleTextRenderingDefault(false);
                Console.WriteLine("Compatible text rendering set.");

                InitializeDirectories();
                Console.WriteLine("Directories initialized.");
                InitializeDatabase();
                Console.WriteLine("Database initialized.");
                InitializeSystemTray();
                Console.WriteLine("System tray initialized.");
                InitializeFileSystemWatchers();
                Console.WriteLine("File system watchers initialized.");
                InitializePeriodicScan();
                Console.WriteLine("Periodic scan initialized.");
                Task.Run(() => ScanExistingDlls()).GetAwaiter().GetResult(); // Scan existing DLLs at startup
                Console.WriteLine("Existing DLLs scanned.");

                Application.Run();
                Console.WriteLine("Application running.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}\n{ex.StackTrace}");
                Log($"Main error: {ex.Message}\n{ex.StackTrace}");
                MessageBox.Show($"Simple Antivirus failed to start: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                throw; // Keep for debugging
            }
        }

        private static void InitializeDirectories()
        {
            Directory.CreateDirectory(quarantinePath);
            Directory.CreateDirectory(logPath);
        }

        private static void InitializeDatabase()
        {
            try
            {
                using var connection = new SqliteConnection($"Data Source={dbPath}");
                connection.Open();
                var command = connection.CreateCommand();
                command.CommandText = @"
                    CREATE TABLE IF NOT EXISTS ScanHistory (
                        FileHash TEXT PRIMARY KEY,
                        FilePath TEXT,
                        ScanResult TEXT,
                        ScanDate TEXT
                    )";
                command.ExecuteNonQuery();
                Log("Database initialized.");
            }
            catch (Exception ex)
            {
                Log($"Failed to initialize database: {ex.Message}");
            }
        }

        private static void InitializeSystemTray()
        {
            try
            {
                Icon icon;
                try
                {
                    using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("Antivirus.Autorun.ico");
                    if (stream == null)
                    {
                        throw new FileNotFoundException("Embedded resource 'Autorun.ico' not found.");
                    }
                    icon = new Icon(stream);
                    Log("Embedded icon loaded successfully.");
                }
                catch (Exception ex)
                {
                    Log($"Failed to load embedded icon: {ex.Message}. Using default icon.");
                    icon = SystemIcons.Application;
                }

                trayIcon = new NotifyIcon
                {
                    Icon = icon,
                    Text = "Simple Antivirus",
                    Visible = true
                };

                var contextMenu = new ContextMenuStrip();
                contextMenu.Items.Add("View Logs", null, (s, e) => Process.Start("explorer.exe", logPath));
                contextMenu.Items.Add("Open Quarantine", null, (s, e) => Process.Start("explorer.exe", quarantinePath));
                contextMenu.Items.Add("Exit", null, (s, e) => Application.Exit());
                trayIcon.ContextMenuStrip = contextMenu;

                trayIcon.DoubleClick += (s, e) => Process.Start("explorer.exe", quarantinePath);
                Log("System tray initialized successfully.");
            }
            catch (Exception ex)
            {
                Log($"Failed to initialize system tray: {ex.Message}");
                MessageBox.Show($"System tray error: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private static void InitializeFileSystemWatchers()
        {
            try
            {
                var drives = DriveInfo.GetDrives().Where(d => d.IsReady && (d.DriveType == DriveType.Fixed || d.DriveType == DriveType.Removable || d.DriveType == DriveType.Network));
                foreach (var drive in drives)
                {
                    try
                    {
                        Log($"Setting up watcher for drive: {drive.RootDirectory.FullName}");
                        var watcher = new FileSystemWatcher
                        {
                            Path = drive.RootDirectory.FullName,
                            Filter = "*.dll",
                            NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName | NotifyFilters.LastWrite,
                            IncludeSubdirectories = true,
                            EnableRaisingEvents = true
                        };
                        watcher.Created += (s, e) => HandleFileEventAsync(() => OnFileCreated(e.FullPath, "Created"));
                        watcher.Changed += (s, e) => HandleFileEventAsync(() => OnFileCreated(e.FullPath, "Changed"));
                        watcher.Renamed += (s, e) => HandleFileEventAsync(() => OnFileCreated(e.FullPath, "Renamed"));
                        watcher.Error += (s, e) => Log($"FileSystemWatcher error on {drive.RootDirectory.FullName}: {e.GetException().Message}");
                        watchers.Add(watcher);
                    }
                    catch (Exception ex)
                    {
                        Log($"Failed to set up watcher for {drive.RootDirectory.FullName}: {ex.Message}");
                    }
                }
                Log($"File system watchers initialized for {watchers.Count} drives.");
            }
            catch (Exception ex)
            {
                Log($"Failed to initialize file system watchers: {ex.Message}");
            }
        }

        private static void HandleFileEventAsync(Func<Task> asyncAction)
        {
            Task.Run(async () =>
            {
                try
                {
                    await asyncAction();
                }
                catch (Exception ex)
                {
                    Log($"Error in file event handler: {ex.Message}");
                }
            });
        }

        private static void InitializePeriodicScan()
        {
            scanTimer.Elapsed += async (s, e) => await ScanExistingDlls();
            scanTimer.AutoReset = true;
            scanTimer.Start();
            Log("Periodic scan timer started (every 1 hour).");
        }

        private static async Task ScanExistingDlls()
        {
            try
            {
                Log("Starting scan of existing DLLs...");
                var drives = DriveInfo.GetDrives().Where(d => d.IsReady && (d.DriveType == DriveType.Fixed || d.DriveType == DriveType.Removable || d.DriveType == DriveType.Network));
                foreach (var drive in drives)
                {
                    try
                    {
                        foreach (var file in Directory.EnumerateFiles(drive.RootDirectory.FullName, "*.dll", SearchOption.AllDirectories))
                        {
                            await OnFileCreated(file, "Periodic Scan");
                        }
                    }
                    catch (UnauthorizedAccessException ex)
                    {
                        Log($"Access denied scanning {drive.RootDirectory.FullName}: {ex.Message}");
                    }
                    catch (Exception ex)
                    {
                        Log($"Error scanning {drive.RootDirectory.FullName}: {ex.Message}");
                    }
                }
                Log("Existing DLL scan completed.");
            }
            catch (Exception ex)
            {
                Log($"Error during existing DLL scan: {ex.Message}");
            }
        }

        private static async Task OnFileCreated(string filePath, string eventType)
        {
            if (IsCriticalSystemFile(filePath))
            {
                Log($"Skipped {filePath}: Critical system file ({eventType})");
                return;
            }

            try
            {
                Log($"Detected DLL: {filePath} ({eventType})");
                bool isUnsigned = !IsFileSigned(filePath);
                string fileHash = CalculateFileHash(filePath);
                if (string.IsNullOrEmpty(fileHash))
                {
                    Log($"Skipping {filePath}: Failed to calculate hash ({eventType})");
                    return;
                }

                if (isUnsigned)
                {
                    Log($"Unsigned DLL detected: {filePath} ({eventType})");
                    await QuarantineFile(filePath, fileHash, $"Unsigned DLL ({eventType})");
                    return;
                }

                if (!await IsFileScanned(fileHash))
                {
                    var scanResult = await ScanWithVirusTotal(filePath, fileHash);
                    if (scanResult?.IsMalicious == true)
                    {
                        await QuarantineFile(filePath, fileHash, $"VirusTotal flagged as malicious ({eventType})");
                    }
                    await StoreScanResult(fileHash, filePath, scanResult?.Result ?? "Clean");
                }
            }
            catch (Exception ex)
            {
                Log($"Error processing {filePath} ({eventType}): {ex.Message}");
            }
        }

        private static bool IsCriticalSystemFile(string filePath)
        {
            try
            {
                string fileName = Path.GetFileName(filePath);
                if (!criticalSystemFiles.Contains(fileName))
                {
                    return false;
                }

                // Verify the file is Microsoft-signed
                var cert = X509CertificateLoader.LoadCertificateFromFile(filePath);
                var cert2 = new X509Certificate2(cert);
                var chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                bool isValid = chain.Build(cert2);
                bool isMicrosoftSigned = isValid && cert2.Issuer.Contains("Microsoft");

                if (isMicrosoftSigned)
                {
                    Log($"File {filePath} is critical (Microsoft-signed: {fileName})");
                    return true;
                }

                Log($"File {filePath} matches critical name {fileName} but is not Microsoft-signed");
                return false;
            }
            catch (Exception ex)
            {
                Log($"Error checking critical status for {filePath}: {ex.Message}");
                return false; // Assume non-critical if signature check fails
            }
        }

        private static bool IsFileSigned(string filePath)
        {
            try
            {
                var cert = X509CertificateLoader.LoadCertificateFromFile(filePath);
                var cert2 = new X509Certificate2(cert);
                var chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                bool isValid = chain.Build(cert2);
                Log($"Signature check for {filePath}: {(isValid ? "Valid" : "Invalid")} certificate chain. Issuer: {cert2.Issuer}");
                return isValid;
            }
            catch (Exception ex)
            {
                Log($"Signature check failed for {filePath}: {ex.Message}");
                return false;
            }
        }

        private static string CalculateFileHash(string filePath)
        {
            try
            {
                using var sha256 = SHA256.Create();
                using var stream = File.OpenRead(filePath);
                var hash = sha256.ComputeHash(stream);
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
            catch (Exception ex)
            {
                Log($"Failed to calculate hash for {filePath}: {ex.Message}");
                return string.Empty;
            }
        }

        private static async Task<bool> IsFileScanned(string fileHash)
        {
            try
            {
                using var connection = new SqliteConnection($"Data Source={dbPath}");
                await connection.OpenAsync();
                var command = connection.CreateCommand();
                command.CommandText = "SELECT COUNT(*) FROM ScanHistory WHERE FileHash = $hash";
                command.Parameters.AddWithValue("$hash", fileHash);
                var count = Convert.ToInt64(await command.ExecuteScalarAsync() ?? 0);
                return count > 0;
            }
            catch (Exception ex)
            {
                Log($"Error checking scan history for hash {fileHash}: {ex.Message}");
                return false;
            }
        }

        private static async Task<VirusTotalResult?> ScanWithVirusTotal(string filePath, string fileHash)
        {
            try
            {
                httpClient.DefaultRequestHeaders.Add("x-apikey", apiKey);
                var response = await httpClient.GetAsync($"https://www.virustotal.com/api/v3/files/{fileHash}");
                if (response.IsSuccessStatusCode)
                {
                    var json = await response.Content.ReadAsStringAsync();
                    Log($"VirusTotal scan successful for {filePath}");
                    return JsonSerializer.Deserialize<VirusTotalResult>(json);
                }
                else if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                {
                    Log($"File {filePath} not found in VirusTotal, uploading...");
                    using var form = new MultipartFormDataContent();
                    var fileContent = new ByteArrayContent(File.ReadAllBytes(filePath));
                    form.Add(fileContent, "file", Path.GetFileName(filePath));
                    response = await httpClient.PostAsync("https://www.virustotal.com/api/v3/files", form);
                    if (response.IsSuccessStatusCode)
                    {
                        var json = await response.Content.ReadAsStringAsync();
                        Log($"VirusTotal upload successful for {filePath}");
                        return JsonSerializer.Deserialize<VirusTotalResult>(json);
                    }
                    else
                    {
                        Log($"VirusTotal upload failed for {filePath}: {response.StatusCode}");
                    }
                }
                else
                {
                    Log($"VirusTotal scan failed for {filePath}: {response.StatusCode}");
                }
            }
            catch (Exception ex)
            {
                Log($"VirusTotal scan error for {filePath}: {ex.Message}");
            }
            return null;
        }

        private static async Task StoreScanResult(string fileHash, string filePath, string scanResult)
        {
            try
            {
                using var connection = new SqliteConnection($"Data Source={dbPath}");
                await connection.OpenAsync();
                var command = connection.CreateCommand();
                command.CommandText = @"
                    INSERT INTO ScanHistory (FileHash, FilePath, ScanResult, ScanDate)
                    VALUES ($hash, $path, $result, $date)";
                command.Parameters.AddWithValue("$hash", fileHash);
                command.Parameters.AddWithValue("$path", filePath);
                command.Parameters.AddWithValue("$result", scanResult);
                command.Parameters.AddWithValue("$date", DateTime.UtcNow.ToString("o"));
                await command.ExecuteNonQueryAsync();
                Log($"Stored scan result for {filePath}: {scanResult}");
            }
            catch (Exception ex)
            {
                Log($"Failed to store scan result for {filePath}: {ex.Message}");
            }
        }

        private static async Task QuarantineFile(string filePath, string fileHash, string reason)
        {
            try
            {
                Log($"Attempting to quarantine {filePath}: {reason}");

                // Kill processes using the file
                var processes = GetProcessesUsingFile(filePath);
                foreach (var process in processes)
                {
                    if (!IsCriticalProcess(process))
                    {
                        try
                        {
                            Log($"Killing process {process.ProcessName} (PID: {process.Id}) using {filePath}");
                            process.Kill();
                            await Task.Delay(100); // Wait for process to terminate
                        }
                        catch (Exception ex)
                        {
                            Log($"Failed to kill process {process.ProcessName} (PID: {process.Id}): {ex.Message}");
                        }
                    }
                    else
                    {
                        Log($"Skipped killing critical process {process.ProcessName} (PID: {process.Id})");
                    }
                }

                // Take ownership and modify permissions
                TakeOwnership(filePath);
                RemoveInheritedPermissions(filePath);
                GrantAdminPermissions(filePath);

                // Move to quarantine
                var quarantineFilePath = Path.Combine(quarantinePath, $"{fileHash}_{Path.GetFileName(filePath)}");
                File.Move(filePath, quarantineFilePath);
                Log($"Quarantined {filePath} to {quarantineFilePath}. Reason: {reason}");

                // Restart affected applications
                foreach (var process in processes)
                {
                    if (process.ProcessName.Equals("explorer", StringComparison.OrdinalIgnoreCase))
                    {
                        Log("Restarting explorer.exe");
                        Process.Start("explorer.exe");
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"Failed to quarantine {filePath}: {ex.Message}");
            }
        }

        private static List<Process> GetProcessesUsingFile(string filePath)
        {
            var processes = new List<Process>();
            try
            {
                var wmiQuery = $"SELECT * FROM Win32_Process WHERE ExecutablePath IS NOT NULL";
                using var searcher = new ManagementObjectSearcher(wmiQuery);
                foreach (ManagementObject obj in searcher.Get())
                {
                    var processId = Convert.ToInt32(obj["ProcessId"]);
                    try
                    {
                        var process = Process.GetProcessById(processId);
                        foreach (ProcessModule module in process.Modules)
                        {
                            if (module.FileName.Equals(filePath, StringComparison.OrdinalIgnoreCase))
                            {
                                Log($"Found process {process.ProcessName} (PID: {process.Id}) using {filePath}");
                                processes.Add(process);
                                break;
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Log($"Error checking modules for PID {processId}: {ex.Message}");
                    }
                }

                // Fallback for GAC or protected locations
                try
                {
                    foreach (var process in Process.GetProcesses())
                    {
                        try
                        {
                            foreach (ProcessModule module in process.Modules)
                            {
                                if (module.FileName.Equals(filePath, StringComparison.OrdinalIgnoreCase))
                                {
                                    Log($"Fallback: Found process {process.ProcessName} (PID: {process.Id}) using {filePath}");
                                    if (!processes.Any(p => p.Id == process.Id))
                                    {
                                        processes.Add(process);
                                    }
                                    break;
                                }
                            }
                        }
                        catch { }
                    }
                }
                catch (Exception ex)
                {
                    Log($"Error in fallback process scan for {filePath}: {ex.Message}");
                }
            }
            catch (Exception ex)
            {
                Log($"Error querying processes for {filePath}: {ex.Message}");
            }
            return processes;
        }

        private static bool IsCriticalProcess(Process process)
        {
            var criticalProcesses = new[] { "svchost", "csrss", "smss", "wininit", "services", "lsass", "winlogon" };
            bool isCritical = criticalProcesses.Contains(process.ProcessName.ToLower());
            if (isCritical)
            {
                Log($"Process {process.ProcessName} (PID: {process.Id}) is critical.");
            }
            return isCritical;
        }

        private static void TakeOwnership(string filePath)
        {
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "takeown",
                        Arguments = $"/F \"{filePath}\" /A",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                process.Start();
                process.WaitForExit();
                Log($"Took ownership of {filePath}");
            }
            catch (Exception ex)
            {
                Log($"Failed to take ownership of {filePath}: {ex.Message}");
            }
        }

        private static void RemoveInheritedPermissions(string filePath)
        {
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "icacls",
                        Arguments = $@"{filePath} /inheritance:d",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                process.Start();
                process.WaitForExit();
                Log($"Removed inherited permissions for {filePath}");
            }
            catch (Exception ex)
            {
                Log($"Failed to remove inherited permissions for {filePath}: {ex.Message}");
            }
        }

        private static void GrantAdminPermissions(string filePath)
        {
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "icacls",
                        Arguments = $@"{filePath} /grant Administrators:F",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                process.Start();
                process.WaitForExit();
                Log($"Granted admin permissions for {filePath}");
            }
            catch (Exception ex)
            {
                Log($"Failed to grant admin permissions for {filePath}: {ex.Message}");
            }
        }

        private static void Log(string message)
        {
            try
            {
                var logFile = Path.Combine(logPath, $"log_{DateTime.Now:yyyyMMdd}.txt");
                File.AppendAllText(logFile, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - {message}{Environment.NewLine}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to log: {ex.Message}");
            }
        }
    }

    public class VirusTotalResult
    {
        public bool IsMalicious => Data?.Attributes?.LastAnalysisStats?.Malicious > 0;
        public string Result => IsMalicious ? "Malicious" : "Clean";

        public VirusTotalData? Data { get; set; }
    }

    public class VirusTotalData
    {
        public VirusTotalAttributes? Attributes { get; set; }
    }

    public class VirusTotalAttributes
    {
        public VirusTotalStats? LastAnalysisStats { get; set; }
    }

    public class VirusTotalStats
    {
        public int Malicious { get; set; }
        public int Suspicious { get; set; }
        public int Undetected { get; set; }
        public int Harmless { get; set; }
    }
}
