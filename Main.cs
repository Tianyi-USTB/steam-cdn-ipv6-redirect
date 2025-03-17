// filepath: Program.cs
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace SteamIpv6Cdn
{
    class Program
    {
        private const string HostsPath = @"C:\Windows\System32\drivers\etc\hosts";
        private const string LinuxHostsPath = @"/etc/hosts";
        private static string ActualHostsPath => RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? HostsPath : LinuxHostsPath;
        
        private const string HostEntryPrefix = "# SteamIpv6Cdn-";
        private const string HostEntryMarker = "#CDN2V6";
        
        private static readonly List<string> SteamCdnDomains = new List<string>
        {
            "cdn-ws.content.steamchina.com",
            "cdn.mileweb.cs.steampowered.com.8686c.com",
            "dl.steam.clngaa.com",
            "st.dl.eccdnx.com",
            "st.dl.bscstorage.net",
            "steampipe.steamcontent.tnkjmec.com",
            "cdn-qc.content.steamchina.com",
            "cdn-ali.content.steamchina.com",
            "xz.pphimalayanrt.com",
            "lv.queniujq.cn"
        };
        
        private static readonly Dictionary<string, IPAddress> DomainIpv6Cache = new Dictionary<string, IPAddress>();
        private static IPEndPoint LocalEndPoint = new IPEndPoint(IPAddress.Parse("127.0.0.19"), 80);
        private static CancellationTokenSource _cts = new CancellationTokenSource();
        
        private static long _bytesReceived = 0;
        private static long _bytesSent = 0;
        private static DateTime _lastSpeedUpdate = DateTime.Now;
        private static bool _debugMode = false; 

        static async Task Main(string[] args)
        {
            _debugMode = args.Contains("-d");

            if (!IsRunningAsAdmin())
            {
                Console.WriteLine("此程序需要管理员权限才能修改hosts文件。请以管理员身份运行。");
                return;
            }
            
            // 注册清理hosts的事件处理
            AppDomain.CurrentDomain.ProcessExit += (s, e) => 
            {
                Console.WriteLine("程序正在退出，清理hosts文件...");
                CleanupHosts();
            };
            
            Console.CancelKeyPress += (s, e) => 
            {
                e.Cancel = true; // 防止立即退出
                Console.WriteLine("检测到Ctrl+C，正在清理并退出...");
                CleanupHosts();
                _cts.Cancel();
            };
            
            try
            {
                // 预先解析所有域名的IPv6地址
                Console.WriteLine("正在解析所有Steam CDN域名的IPv6地址...");
                int resolvedCount = 0;
                
                foreach (string domain in SteamCdnDomains)
                {
                    IPAddress ipv6 = await ResolveIpv6AddressAsync(domain);
                    if (ipv6 != null)
                    {
                        DomainIpv6Cache[domain] = ipv6;
                        Console.WriteLine($"已解析 {domain} -> {ipv6}");
                        resolvedCount++;
                    }
                    else
                    {
                        Console.WriteLine($"无法解析 {domain} 的IPv6地址");
                    }
                }
                
                Console.WriteLine($"成功解析 {resolvedCount}/{SteamCdnDomains.Count} 个域名的IPv6地址");
                
                if (resolvedCount == 0)
                {
                    Console.WriteLine("没有可用的IPv6地址，请检查您的网络连接和DNS设置。");
                    return;
                }
                
                // 添加hosts条目
                await AddHostsEntriesAsync();
                
                // 启动转发代理服务器
                StartSpeedMonitor();
                await StartProxyServerAsync();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"发生错误: {ex.Message}");
            }
            finally
            {
                // 清理hosts文件
                CleanupHosts();
            }
        }
        
        private static async Task<IPAddress> ResolveIpv6AddressAsync(string domain)
        {
            try
            {
                // 使用DNS查询获取IPv6地址
                IPHostEntry hostEntry = await Dns.GetHostEntryAsync(domain);
                
                // 查找所有IPv6地址
                IPAddress[] ipv6Addresses = hostEntry.AddressList
                    .Where(ip => ip.AddressFamily == AddressFamily.InterNetworkV6)
                    .ToArray();
                
                if (ipv6Addresses.Length > 0)
                {
                    // 返回第一个IPv6地址
                    return ipv6Addresses[0];
                }
                
                return null;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"解析 {domain} 的IPv6地址时发生错误: {ex.Message}");
                return null;
            }
        }

        private static bool IsRunningAsAdmin()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                var principal = new System.Security.Principal.WindowsPrincipal(identity);
                return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            else
            {
                // Linux/macOS - 检查是否是root用户
                return geteuid() == 0;
            }
        }
        
        [DllImport("libc")]
        private static extern uint geteuid();

private static async Task AddHostsEntriesAsync()
{
    try
    {
        // 备份hosts文件
        string backupPath = Path.Combine(Path.GetTempPath(), $"hosts_backup_{DateTime.Now:yyyyMMddHHmmss}");
        File.Copy(ActualHostsPath, backupPath, true);
        Console.WriteLine($"已备份hosts文件至 {backupPath}");
        
        // 生成要添加的条目
        StringBuilder entriesBuilder = new StringBuilder();
        entriesBuilder.AppendLine($"{HostEntryPrefix}{Guid.NewGuid()}");
        
        foreach (string domain in SteamCdnDomains)
        {
            entriesBuilder.AppendLine($"127.0.0.19 {domain} {HostEntryMarker}");
        }
        
        string entries = entriesBuilder.ToString();
        Console.WriteLine("将添加以下条目到hosts文件:");
        Console.WriteLine(entries);
        
        // 在Windows下，直接使用File类写入
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            try
            {
                // 检查文件是否存在且可写
                if (!File.Exists(ActualHostsPath))
                {
                    throw new FileNotFoundException($"hosts文件不存在: {ActualHostsPath}");
                }
                
                // 尝试写入
                File.AppendAllText(ActualHostsPath, entries);
                Console.WriteLine("已成功写入hosts文件");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"写入hosts文件失败: {ex.Message}");
                Console.WriteLine("尝试使用管理员权限写入...");
                
                // 使用PowerShell以管理员权限写入
                string tempFile = Path.GetTempFileName();
                File.WriteAllText(tempFile, entries);
                
                Process process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "powershell",
                        Arguments = $"-Command \"Add-Content -Path '{ActualHostsPath}' -Value (Get-Content -Path '{tempFile}')\"",
                        UseShellExecute = true,
                        Verb = "runas",
                        CreateNoWindow = false,
                    }
                };
                
                process.Start();
                process.WaitForExit();
                
                if (process.ExitCode == 0)
                {
                    Console.WriteLine("使用PowerShell写入hosts文件成功");
                }
                else
                {
                    Console.WriteLine($"使用PowerShell写入hosts文件失败，退出码: {process.ExitCode}");
                }
                
                File.Delete(tempFile);
            }
        }
        else // Linux环境
        {
            // 使用临时文件和sudo写入
            string tempFile = Path.GetTempFileName();
            File.WriteAllText(tempFile, entries);
            
            // 首先检查文件是否存在
            Process checkProcess = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "bash",
                    Arguments = $"-c \"if [ -f {LinuxHostsPath} ]; then echo 'exists'; else echo 'not_exists'; fi\"",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                }
            };
            
            checkProcess.Start();
            string result = await checkProcess.StandardOutput.ReadToEndAsync();
            await checkProcess.WaitForExitAsync();
            
            if (result.Trim() != "exists")
            {
                Console.WriteLine($"hosts文件不存在: {LinuxHostsPath}");
                return;
            }
            
            Console.WriteLine("正在使用sudo写入hosts文件...");
            Console.WriteLine("如果弹出密码输入框，请输入您的sudo密码");
            
            // 使用sudo写入，显示命令窗口以便输入密码
            Process process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "sudo",
                    Arguments = $"bash -c \"cat '{tempFile}' >> {LinuxHostsPath}\"",
                    UseShellExecute = true,
                    CreateNoWindow = false,
                }
            };
            
            process.Start();
            await process.WaitForExitAsync();
            
            if (process.ExitCode == 0)
            {
                Console.WriteLine("使用sudo写入hosts文件成功");
            }
            else
            {
                Console.WriteLine($"使用sudo写入hosts文件失败，退出码: {process.ExitCode}");
            }
            
            File.Delete(tempFile);
        }
        
        // 验证hosts文件是否包含我们的条目
        string hostsContent = File.ReadAllText(ActualHostsPath);
        if (hostsContent.Contains(HostEntryMarker))
        {
            Console.WriteLine("验证成功：hosts文件已包含我们的条目");
        }
        else
        {
            Console.WriteLine("警告：验证失败，hosts文件可能未成功写入");
            Console.WriteLine("请尝试手动编辑hosts文件");
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine($"添加hosts条目时发生错误: {ex.Message}");
        Console.WriteLine($"详细堆栈: {ex.StackTrace}");
    }
}
        
        private static void CleanupHosts()
        {
            try
            {
                // 读取原hosts文件
                string content = File.ReadAllText(ActualHostsPath);
                
                // 拆分成行
                var lines = content.Split(new[] { '\r', '\n' }, StringSplitOptions.None).ToList();
                List<int> linesToRemove = new List<int>();
                
                // 找出所有需要删除的行
                for (int i = 0; i < lines.Count; i++)
                {
                    // 删除标记行
                    if (lines[i].StartsWith(HostEntryPrefix))
                    {
                        linesToRemove.Add(i);
                    }
                    // 删除带有CDN2V6标记的行
                    else if (lines[i].Contains(HostEntryMarker))
                    {
                        linesToRemove.Add(i);
                    }
                }
                
                // 从后往前删除行，避免索引变化
                linesToRemove.Sort((a, b) => b.CompareTo(a));
                foreach (int index in linesToRemove)
                {
                    lines.RemoveAt(index);
                }
                
                // 重写hosts文件
                string newContent = string.Join(Environment.NewLine, lines);
                
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    try
                    {
                        File.WriteAllText(ActualHostsPath, newContent);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Windows下写入hosts文件失败: {ex.Message}");
                        // 尝试使用PowerShell以管理员权限写入
                        string tempFile = Path.GetTempFileName();
                        File.WriteAllText(tempFile, newContent);
                        
                        Process process = new Process
                        {
                            StartInfo = new ProcessStartInfo
                            {
                                FileName = "powershell",
                                Arguments = $"-Command \"Set-Content -Path '{ActualHostsPath}' -Value (Get-Content -Path '{tempFile}')\"",
                                UseShellExecute = true,
                                Verb = "runas",
                                CreateNoWindow = false,
                            }
                        };
                        
                        process.Start();
                        process.WaitForExit();
                        File.Delete(tempFile);
                    }
                }
                else
                {
                    // Linux下使用sudo
                    string tempFile = Path.GetTempFileName();
                    File.WriteAllText(tempFile, newContent);
                    
                    // 修复引号问题，使用双引号包围路径，避免特殊字符问题
                    Process process = new Process
                    {
                        StartInfo = new ProcessStartInfo
                        {
                            FileName = "sudo",
                            Arguments = $"bash -c \"cat \\\"{tempFile}\\\" > \\\"{LinuxHostsPath}\\\"\"",
                            UseShellExecute = true, // 允许显示终端窗口以便输入密码
                            CreateNoWindow = false,
                        }
                    };
                    
                    process.Start();
                    process.WaitForExit();
                    File.Delete(tempFile);
                }
                
                Console.WriteLine("已清理hosts文件中的条目");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"清理hosts文件时发生错误: {ex.Message}");
            }
        }
        
        private static async Task StartProxyServerAsync()
        {
            // 创建并配置TCP监听器
            TcpListener listener = new TcpListener(LocalEndPoint);
            listener.Start();
            
            Console.WriteLine($"代理服务器已启动，监听 {LocalEndPoint}");
            Console.WriteLine($"将Steam CDN流量转发到IPv6地址");
            Console.WriteLine("按Ctrl+C停止服务器...");
            
            try
            {
                while (!_cts.Token.IsCancellationRequested)
                {
                    // 异步接受客户端连接，带有取消令牌
                    TcpClient client;
                    try
                    {
                        client = await listener.AcceptTcpClientAsync().WithCancellation(_cts.Token);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                    
                    // 对每个客户端连接启动新的任务处理
                    _ = HandleClientAsync(client);
                }
            }
            finally
            {
                listener.Stop();
                Console.WriteLine("代理服务器已停止");
            }
        }
        
        private static async Task HandleClientAsync(TcpClient client)
        {
            try
            {
                using (client)
                {
                        

                    // 获取客户端的请求数据（前4KB）用于获取Host头
                    NetworkStream clientStream = client.GetStream();
                    byte[] buffer = new byte[4096];
                    int bytesRead = await clientStream.ReadAsync(buffer, 0, buffer.Length);
                    
                    if (bytesRead == 0)
                    {
                        return;
                    }
                    
                    // 提取HTTP请求中的Host头
                    string requestData = Encoding.ASCII.GetString(buffer, 0, bytesRead);
                    string hostName = ExtractHostName(requestData);
                    
                    if (string.IsNullOrEmpty(hostName) || !DomainIpv6Cache.TryGetValue(hostName, out IPAddress targetIpv6))
                    {
                        // 如果无法提取Host或没有对应的IPv6地址，使用第一个可用的IPv6地址
                        if (DomainIpv6Cache.Count > 0)
                        {
                            var firstDomain = DomainIpv6Cache.First();
                            hostName = firstDomain.Key;
                            targetIpv6 = firstDomain.Value;
                        }
                        else
                        {
                            Console.WriteLine("没有可用的IPv6地址，无法转发请求");
                            return;
                        }
                    }
                    
                    if (_debugMode)
                    {
                        Console.WriteLine($"转发请求: {hostName} -> {targetIpv6}");
                    }
                    
                    // 连接到对应的IPv6服务器
                    using TcpClient targetClient = new TcpClient(AddressFamily.InterNetworkV6);
                    await targetClient.ConnectAsync(targetIpv6, 80);
                    NetworkStream targetStream = targetClient.GetStream();
                    
                    // 发送已读取的请求数据
                    await targetStream.WriteAsync(buffer, 0, bytesRead);
                    
                    // 更新上行流量统计
                    Interlocked.Add(ref _bytesSent, bytesRead);
                    
                    // 双向传输剩余数据
                    Task clientToTargetTask = ForwardDataAsync(clientStream, targetStream, true);
                    Task targetToClientTask = ForwardDataAsync(targetStream, clientStream, false);
                    
                    // 等待任一方向的传输完成
                    await Task.WhenAny(clientToTargetTask, targetToClientTask);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"处理连接时发生错误: {ex.Message}");
            }
        }
        
        private static string ExtractHostName(string httpRequest)
        {
            // 使用正则表达式提取Host头
            Match match = Regex.Match(httpRequest, @"Host: ([^\r\n:]+)", RegexOptions.IgnoreCase);
            if (match.Success)
            {
                return match.Groups[1].Value.Trim();
            }
            return null;
        }
        
        private static async Task ForwardDataAsync(NetworkStream source, NetworkStream destination, bool isUpload)
        {
            byte[] buffer = new byte[81920];
            int bytesRead;
            
            try
            {
                while ((bytesRead = await source.ReadAsync(buffer, 0, buffer.Length)) > 0)
                {
                    await destination.WriteAsync(buffer, 0, bytesRead);
                    
                    // 统计流量
                    if (isUpload)
                        Interlocked.Add(ref _bytesSent, bytesRead);
                    else
                        Interlocked.Add(ref _bytesReceived, bytesRead);
                }
            }
            catch (IOException)
            {
                // 流可能已关闭，忽略异常
            }
        }
        
        private static void StartSpeedMonitor()
        {
            Task.Run(async () =>
            {
                while (!_cts.Token.IsCancellationRequested)
                {
                    await Task.Delay(1000, _cts.Token);
                    
                    TimeSpan elapsed = DateTime.Now - _lastSpeedUpdate;
                    double seconds = elapsed.TotalSeconds;
                    
                    if (seconds > 0)
                    {
                        long bytesSent = Interlocked.Read(ref _bytesSent);
                        long bytesReceived = Interlocked.Read(ref _bytesReceived);
                        
                        double uploadSpeed = bytesSent / seconds / (1024.0 * 1024.0); // MB/s
                        double downloadSpeed = bytesReceived / seconds / (1024.0 * 1024.0); // MB/s
                        
                        Console.Write($"\r上行: {uploadSpeed:F2} MB/s | 下行: {downloadSpeed:F2} MB/s        ");
                        
                        Interlocked.Exchange(ref _bytesSent, 0);
                        Interlocked.Exchange(ref _bytesReceived, 0);
                        _lastSpeedUpdate = DateTime.Now;
                    }
                }
            });
        }
    }
    
    // 扩展方法，用于支持Task的取消
    public static class TaskExtensions
    {
        public static async Task<T> WithCancellation<T>(this Task<T> task, CancellationToken cancellationToken)
        {
            var tcs = new TaskCompletionSource<bool>();
            using var registration = cancellationToken.Register(s => ((TaskCompletionSource<bool>)s).TrySetResult(true), tcs);
            
            Task completedTask = await Task.WhenAny(task, tcs.Task);
            if (completedTask == tcs.Task)
            {
                throw new OperationCanceledException(cancellationToken);
            }
            
            return await task;
        }
    }
}