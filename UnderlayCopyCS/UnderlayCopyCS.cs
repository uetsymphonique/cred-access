using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

class UnderlayCopyCS
{
    const uint GENERIC_READ              = 0x80000000;
    const uint FILE_SHARE_READ           = 0x00000001;
    const uint FILE_SHARE_WRITE          = 0x00000002;
    const uint OPEN_EXISTING             = 3;
    const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    const uint FILE_READ_ATTRIBUTES      = 0x00000080;
    const uint FILE_ATTRIBUTE_NORMAL     = 0x00000080;
    const uint FILE_BEGIN                = 0;
    const ulong MFT_RECORD_MASK          = 0x0000FFFFFFFFFFFFUL;
    const ulong ROOT_RECORD              = 5;
    static readonly IntPtr INVALID_HANDLE = new IntPtr(-1);

    [StructLayout(LayoutKind.Sequential)]
    struct FILETIME { public uint Low; public uint High; }

    [StructLayout(LayoutKind.Sequential)]
    struct BY_HANDLE_FILE_INFORMATION
    {
        public uint FileAttributes;
        public FILETIME CreationTime;
        public FILETIME LastAccessTime;
        public FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateFileW(string fileName, uint desiredAccess, uint shareMode,
        IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetFileInformationByHandle(IntPtr handle, out BY_HANDLE_FILE_INFORMATION info);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetFilePointerEx(IntPtr handle, long distance, out long newPosition, uint moveMethod);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadFile(IntPtr handle, byte[] buffer, int bytesToRead, out int bytesRead, IntPtr overlapped);

    class Run { public long Vcn; public long Lcn; public long Clusters; }

    class Boot
    {
        public int BytesPerSector;
        public int SectorsPerCluster;
        public int ClusterSize;
        public long MftLcn;
        public int BytesPerMftRecord;
        public int IndexBufferSize;
    }

    class Fs
    {
        public string Volume;
        public IntPtr Handle;
        public Boot Boot;
        public List<Run> MftRuns = new List<Run>();

        public long MapVcnToLcn(long vcn)
        {
            for (int i = 0; i < MftRuns.Count; i++)
            {
                Run r = MftRuns[i];
                if (vcn >= r.Vcn && vcn < r.Vcn + r.Clusters) return r.Lcn + (vcn - r.Vcn);
            }
            return -1;
        }

        public byte[] ReadAt(long offset, int length)
        {
            long newPos;
            if (!SetFilePointerEx(Handle, offset, out newPos, FILE_BEGIN))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            byte[] buf = new byte[length];
            int total = 0;
            while (total < length)
            {
                int want = length - total;
                byte[] tmp = new byte[want];
                int got;
                if (!ReadFile(Handle, tmp, want, out got, IntPtr.Zero))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                if (got <= 0) throw new IOException("Unexpected end of volume read at offset " + offset);
                Array.Copy(tmp, 0, buf, total, got);
                total += got;
            }
            return buf;
        }
    }

    class IndexEntry { public ulong FileRef; public string Name; }

    static int Main(string[] args)
    {
        string source = null, dest = null, mode = "index";
        string recArg = null;
        bool resolveOnly = false;
        bool listOnly = false;
        bool recOnly = false;

        try
        {
            for (int i = 0; i < args.Length; i++)
            {
                string a = args[i];
                if (a == "-h" || a == "--help") { Usage(); return 0; }
                else if (a == "--resolve") resolveOnly = true;
                else if (a == "--list") listOnly = true;
                else if (a == "--rec")
                {
                    recOnly = true;
                    if (i + 1 >= args.Length) throw new ArgumentException("--rec requires a record number");
                    recArg = args[++i];
                }
                else if (a == "--mode")
                {
                    if (i + 1 >= args.Length) throw new ArgumentException("--mode requires a value");
                    mode = args[++i].ToLowerInvariant();
                }
                else if (source == null) source = a;
                else if (dest == null) dest = a;
                else throw new ArgumentException("Unexpected argument: " + a);
            }

            if (source == null) { Usage(); return 2; }
            if (!resolveOnly && !listOnly && !recOnly && dest == null) { Usage(); return 2; }
            if (mode != "index" && mode != "mft" && mode != "metadata")
                throw new ArgumentException("Unknown mode: " + mode);

            string volume = VolumeFromPath(source);
            IntPtr volHandle = CreateFileW(volume, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
            if (volHandle == INVALID_HANDLE)
                throw new Win32Exception(Marshal.GetLastWin32Error());
            Fs fs = new Fs();
            fs.Volume = volume;
            fs.Handle = volHandle;
            try
            {
                fs.Boot = ReadBoot(fs);
                LoadMftRuns(fs);

                if (listOnly || recOnly)
                {
                    Console.WriteLine(string.Format(
                        "Boot: BPS={0} SPC={1} Cluster={2} MftLcn={3} MftRec={4} IdxBuf={5}",
                        fs.Boot.BytesPerSector, fs.Boot.SectorsPerCluster, fs.Boot.ClusterSize,
                        fs.Boot.MftLcn, fs.Boot.BytesPerMftRecord, fs.Boot.IndexBufferSize));
                    Console.WriteLine("MftRuns: " + fs.MftRuns.Count);
                    for (int i = 0; i < fs.MftRuns.Count && i < 4; i++)
                    {
                        Run mr = fs.MftRuns[i];
                        Console.WriteLine(string.Format("  run Vcn={0} Lcn={1} Clusters={2}", mr.Vcn, mr.Lcn, mr.Clusters));
                    }
                }

                if (recOnly)
                {
                    if (recArg == null) throw new ArgumentException("--rec requires a record number: --rec <n> <path-on-volume>");
                    DumpRecord(fs, ulong.Parse(recArg));
                    return 0;
                }

                if (listOnly)
                {
                    ulong dirRec = ResolveByIndex(fs, source);
                    Console.WriteLine("Listing directory (MFT record #" + dirRec + "): " + source);
                    int count = 0;
                    foreach (IndexEntry e in EnumerateDirEntries(fs, dirRec))
                    {
                        if (count >= 300) { Console.WriteLine("  ..."); break; }
                        Console.WriteLine(string.Format("  {0,-12}  {1}", e.FileRef, e.Name));
                        count++;
                    }
                    Console.WriteLine("[*] " + count + " entries");
                    return 0;
                }

                ulong frn;
                string how;
                long realSize;
                List<Run> runs;

                if (mode == "metadata")
                {
                    ulong hfrn; long hsize;
                    GetHandleInfo(source, out hfrn, out hsize);
                    frn = hfrn;
                    realSize = hsize;
                    runs = GetExtentsFsutil(source);
                    how = "fsutil file queryextents (source opened for size)";
                }
                else
                {
                    if (mode == "index")
                    {
                        frn = ResolveByIndex(fs, source);
                        how = "directory index ($I30) - source never opened";
                    }
                    else
                    {
                        frn = GetFrnByHandle(source);
                        how = "file handle (FILE_READ_ATTRIBUTES)";
                    }
                    byte[] record = ReadRecord(fs, frn);
                    if (!GetDataInfo(record, out realSize, out runs))
                        throw new IOException("No unnamed $DATA attribute in MFT record #" + frn);
                }

                Console.WriteLine("Source Full Path : " + source);
                Console.WriteLine("Source File Size : " + realSize + " bytes");
                Console.WriteLine("Cluster size: " + fs.Boot.ClusterSize + " bytes");
                Console.WriteLine("MFT Record #" + frn);
                Console.WriteLine("Resolved via: " + how);

                if (resolveOnly)
                {
                    Console.WriteLine("[*] resolve-only: no data written");
                    return 0;
                }

                if (runs == null || runs.Count == 0)
                    throw new IOException("No non-resident $DATA runs (resident file not supported by raw copy)");

                CopyExtents(fs, runs, realSize, dest);
                Console.WriteLine("File copied successfully to " + dest);
            }
            finally
            {
                if (fs.Handle != IntPtr.Zero && fs.Handle != INVALID_HANDLE) CloseHandle(fs.Handle);
            }
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("[-] " + ex.Message);
            return 1;
        }
    }

    static void Usage()
    {
        Console.WriteLine("UnderlayCopyCS - raw NTFS acquisition of locked files (index / MFT / metadata modes)");
        Console.WriteLine();
        Console.WriteLine("Usage:");
        Console.WriteLine("  UnderlayCopyCS.exe <source> <dest> [--mode index|mft|metadata]");
        Console.WriteLine("  UnderlayCopyCS.exe <source> --resolve [--mode index|mft]");
        Console.WriteLine("  UnderlayCopyCS.exe <source> --list            (dump a directory's index)");
        Console.WriteLine("  UnderlayCopyCS.exe --rec <n> <path-on-volume> (dump raw MFT record #n)");
        Console.WriteLine();
        Console.WriteLine("Modes:");
        Console.WriteLine("  index     (default) resolve the file's MFT record by walking the NTFS");
        Console.WriteLine("            directory index off the raw volume - the source is NEVER opened.");
        Console.WriteLine("  mft       resolve the record by opening the source with FILE_READ_ATTRIBUTES");
        Console.WriteLine("            then GetFileInformationByHandle (UnderlayCopy.ps1 -Mode MFT parity).");
        Console.WriteLine("  metadata  resolve extents with 'fsutil file queryextents' (parity with");
        Console.WriteLine("            UnderlayCopy.ps1 -Mode Metadata).");
        Console.WriteLine();
        Console.WriteLine("Example:");
        Console.WriteLine("  UnderlayCopyCS.exe C:\\Windows\\NTDS\\ntds.dit C:\\Windows\\Temp\\ntds.dit");
    }

    static Boot ReadBoot(Fs fs)
    {
        byte[] s = fs.ReadAt(0, 512);
        if (s[3] != 'N' || s[4] != 'T' || s[5] != 'F' || s[6] != 'S')
            throw new IOException("Not an NTFS volume: " + fs.Volume);
        Boot b = new Boot();
        b.BytesPerSector = BitConverter.ToUInt16(s, 11);
        b.SectorsPerCluster = s[13];
        b.ClusterSize = b.BytesPerSector * b.SectorsPerCluster;
        b.MftLcn = BitConverter.ToInt64(s, 48);
        sbyte cpm = (sbyte)s[64];
        b.BytesPerMftRecord = cpm > 0 ? cpm * b.ClusterSize : (1 << (-cpm));
        sbyte cpi = (sbyte)s[68];
        b.IndexBufferSize = cpi > 0 ? cpi * b.ClusterSize : (1 << (-cpi));
        return b;
    }

    static void ApplyFixup(byte[] rec, int bytesPerSector)
    {
        int usaOff = BitConverter.ToUInt16(rec, 4);
        int usaCount = BitConverter.ToUInt16(rec, 6);
        for (int i = 1; i < usaCount; i++)
        {
            int target = i * bytesPerSector - 2;
            if (target < 0 || target + 1 >= rec.Length) break;
            rec[target] = rec[usaOff + i * 2];
            rec[target + 1] = rec[usaOff + i * 2 + 1];
        }
    }

    static void LoadMftRuns(Fs fs)
    {
        long phys = fs.Boot.MftLcn * fs.Boot.ClusterSize;
        byte[] rec = fs.ReadAt(phys, fs.Boot.BytesPerMftRecord);
        ApplyFixup(rec, fs.Boot.BytesPerSector);
        List<Run> runs = GetAttrRuns(rec, 0x80);
        if (runs == null || runs.Count == 0) throw new IOException("Could not read $MFT $DATA runs");
        fs.MftRuns = runs;
    }

    static byte[] ReadRecord(Fs fs, ulong recNum)
    {
        long off = (long)recNum * fs.Boot.BytesPerMftRecord;
        long vcn = off / fs.Boot.ClusterSize;
        long inCluster = off % fs.Boot.ClusterSize;
        long lcn = fs.MapVcnToLcn(vcn);
        if (lcn < 0) throw new IOException("MFT record #" + recNum + " is not mapped (sparse/unallocated)");
        long phys = lcn * fs.Boot.ClusterSize + inCluster;
        byte[] rec = fs.ReadAt(phys, fs.Boot.BytesPerMftRecord);
        ApplyFixup(rec, fs.Boot.BytesPerSector);
        return rec;
    }

    static List<Run> GetAttrRuns(byte[] rec, int attrType)
    {
        int off = BitConverter.ToUInt16(rec, 0x14);
        while (off > 0 && off + 8 <= rec.Length)
        {
            int type = BitConverter.ToInt32(rec, off);
            if (type == unchecked((int)0xFFFFFFFF)) break;
            int len = BitConverter.ToInt32(rec, off + 4);
            if (len <= 0) break;
            byte nonResident = rec[off + 8];
            ushort nameLen = rec[off + 9];
            if (type == attrType && nonResident == 1 && nameLen == 0)
            {
                int runsOff = BitConverter.ToUInt16(rec, off + 0x20);
                int start = off + runsOff;
                byte[] runBuf = new byte[(off + len) - start];
                Array.Copy(rec, start, runBuf, 0, runBuf.Length);
                return ParseRuns(runBuf);
            }
            off += len;
        }
        return null;
    }

    static List<Run> ParseRuns(byte[] data)
    {
        List<Run> runs = new List<Run>();
        int pos = 0;
        long curLcn = 0;
        long curVcn = 0;
        while (pos < data.Length)
        {
            byte header = data[pos++];
            if (header == 0) break;
            int lenSize = header & 0x0F;
            int offSize = (header >> 4) & 0x0F;
            if (lenSize == 0 || pos + lenSize + offSize > data.Length) break;
            long len = 0;
            for (int i = 0; i < lenSize; i++) len |= (long)data[pos++] << (8 * i);
            if (offSize == 0)
            {
                runs.Add(new Run { Vcn = curVcn, Lcn = -1, Clusters = len });
            }
            else
            {
                long offVal = 0;
                for (int i = 0; i < offSize; i++) offVal |= (long)data[pos++] << (8 * i);
                if ((data[pos - 1] & 0x80) != 0) offVal -= (long)1 << (8 * offSize);
                curLcn += offVal;
                runs.Add(new Run { Vcn = curVcn, Lcn = curLcn, Clusters = len });
            }
            curVcn += len;
        }
        return runs;
    }

    static bool GetDataInfo(byte[] rec, out long realSize, out List<Run> runs)
    {
        realSize = 0;
        runs = null;
        int off = BitConverter.ToUInt16(rec, 0x14);
        while (off > 0 && off + 8 <= rec.Length)
        {
            int type = BitConverter.ToInt32(rec, off);
            if (type == unchecked((int)0xFFFFFFFF)) break;
            int len = BitConverter.ToInt32(rec, off + 4);
            if (len <= 0) break;
            byte nonResident = rec[off + 8];
            ushort nameLen = rec[off + 9];
            if (type == 0x80 && nameLen == 0)
            {
                if (nonResident == 0) { realSize = BitConverter.ToInt32(rec, off + 0x10); return true; }
                realSize = BitConverter.ToInt64(rec, off + 0x30);
                int runsOff = BitConverter.ToUInt16(rec, off + 0x20);
                int start = off + runsOff;
                byte[] runBuf = new byte[(off + len) - start];
                Array.Copy(rec, start, runBuf, 0, runBuf.Length);
                runs = ParseRuns(runBuf);
                return true;
            }
            off += len;
        }
        return false;
    }

    static void DumpRecord(Fs fs, ulong recNum)
    {
        Console.WriteLine("Reading MFT record #" + recNum + " ...");
        byte[] rec = ReadRecord(fs, recNum);
        Console.WriteLine("  first8: " + BitConverter.ToString(rec, 0, 8));
        Console.WriteLine("  sig: " + Encoding.ASCII.GetString(rec, 0, 4));
        Console.WriteLine("  usaOff=0x" + BitConverter.ToUInt16(rec, 4).ToString("X")
            + " usaCnt=" + BitConverter.ToUInt16(rec, 6));
        Console.WriteLine("  firstAttrOff=0x" + BitConverter.ToUInt16(rec, 0x14).ToString("X")
            + " flags=0x" + BitConverter.ToUInt16(rec, 0x16).ToString("X"));
        int off = BitConverter.ToUInt16(rec, 0x14);
        int guard = 0;
        while (off > 0 && off + 8 <= rec.Length && guard++ < 64)
        {
            int type = BitConverter.ToInt32(rec, off);
            if (type == unchecked((int)0xFFFFFFFF)) { Console.WriteLine("  (end-of-attrs)"); break; }
            int len = BitConverter.ToInt32(rec, off + 4);
            if (len <= 0) { Console.WriteLine("  (bad attr len=" + len + ")"); break; }
            byte nr = rec[off + 8];
            ushort nl = rec[off + 9];
            Console.WriteLine(string.Format("  attr type=0x{0:X8} nonRes={1} nameLen={2} len={3}",
                type, nr, nl, len));
            if (type == 0x90 && nr == 0)
            {
                byte[] v = GetResidentValue(rec, off);
                Console.WriteLine("       $INDEX_ROOT valueLen=" + v.Length);
                if (v.Length >= 0x18)
                    Console.WriteLine(string.Format("       indexedAttr=0x{0:X8} entriesOff=0x{1:X} total=0x{2:X}",
                        BitConverter.ToInt32(v, 0), BitConverter.ToInt32(v, 0x10), BitConverter.ToInt32(v, 0x14)));
            }
            if (type == 0xA0 && nr == 1)
            {
                int runsOff = BitConverter.ToUInt16(rec, off + 0x20);
                int start = off + runsOff;
                int nbytes = (off + len) - start;
                if (nbytes > 0)
                {
                    byte[] runBuf = new byte[nbytes];
                    Array.Copy(rec, start, runBuf, 0, nbytes);
                    List<Run> runs = ParseRuns(runBuf);
                    Console.WriteLine("       $INDEX_ALLOCATION runs=" + runs.Count);
                    for (int k = 0; k < runs.Count && k < 3; k++)
                        Console.WriteLine(string.Format("       run Vcn={0} Lcn={1} Clusters={2}", runs[k].Vcn, runs[k].Lcn, runs[k].Clusters));
                }
            }
            off += len;
        }
    }

    // ---- index resolution -------------------------------------------------

    static ulong ResolveByIndex(Fs fs, string source)
    {
        string rest = StripPrefix(source);
        string[] parts = rest.Split(new char[] { '\\' }, StringSplitOptions.RemoveEmptyEntries);
        ulong cur = ROOT_RECORD;
        for (int i = 0; i < parts.Length; i++)
        {
            int scanned; List<string> sample;
            ulong next = FindChild(fs, cur, parts[i], out scanned, out sample);
            if (next == 0)
                throw new FileNotFoundException("Not found via directory index: " + parts[i]
                    + " (record #" + cur + ", scanned " + scanned + " entries; sample: "
                    + string.Join(", ", sample.ToArray()) + ")");
            cur = next;
        }
        return cur;
    }

    static string StripPrefix(string path)
    {
        string s = path;
        if (s.StartsWith("\\\\?\\")) s = s.Substring(4);
        if (s.Length >= 2 && s[1] == ':') s = s.Substring(2);
        return s.TrimStart('\\');
    }

    static ulong FindChild(Fs fs, ulong dirRec, string name, out int scanned, out List<string> sample)
    {
        scanned = 0;
        sample = new List<string>();
        foreach (IndexEntry e in EnumerateDirEntries(fs, dirRec))
        {
            scanned++;
            if (sample.Count < 12) sample.Add(e.Name);
            if (string.Equals(e.Name, name, StringComparison.OrdinalIgnoreCase)) return e.FileRef;
        }
        return 0;
    }

    static IEnumerable<IndexEntry> EnumerateDirEntries(Fs fs, ulong dirRec)
    {
        byte[] rec = ReadRecord(fs, dirRec);
        int off = BitConverter.ToUInt16(rec, 0x14);
        while (off > 0 && off + 8 <= rec.Length)
        {
            int type = BitConverter.ToInt32(rec, off);
            if (type == unchecked((int)0xFFFFFFFF)) break;
            int len = BitConverter.ToInt32(rec, off + 4);
            if (len <= 0) break;
            byte nonResident = rec[off + 8];
            ushort nameLen = rec[off + 9];
            string attrName = AttrName(rec, off);
            if (nameLen == 0 || attrName.Equals("$I30", StringComparison.OrdinalIgnoreCase))
            {
                if (type == 0x90 && nonResident == 0)
                {
                    byte[] v = GetResidentValue(rec, off);
                    foreach (IndexEntry e in ParseIndexRoot(v)) yield return e;
                }
                else if (type == 0xA0 && nonResident == 1)
                {
                    int runsOff = BitConverter.ToUInt16(rec, off + 0x20);
                    int start = off + runsOff;
                    byte[] runBuf = new byte[(off + len) - start];
                    Array.Copy(rec, start, runBuf, 0, runBuf.Length);
                    List<Run> runs = ParseRuns(runBuf);
                    foreach (IndexEntry e in ParseIndexAllocation(fs, runs)) yield return e;
                }
            }
            off += len;
        }
    }

    static byte[] GetResidentValue(byte[] rec, int attrOff)
    {
        int valLen = BitConverter.ToInt32(rec, attrOff + 0x10);
        int valOff = BitConverter.ToUInt16(rec, attrOff + 0x14);
        if (valLen <= 0 || attrOff + valOff + valLen > rec.Length) return new byte[0];
        byte[] v = new byte[valLen];
        Array.Copy(rec, attrOff + valOff, v, 0, valLen);
        return v;
    }

    static string AttrName(byte[] rec, int attrOff)
    {
        int nl = rec[attrOff + 9];
        if (nl == 0) return "";
        ushort nOff = BitConverter.ToUInt16(rec, attrOff + 0x0A);
        if (nOff == 0 || attrOff + nOff + nl * 2 > rec.Length) return "";
        return Encoding.Unicode.GetString(rec, attrOff + nOff, nl * 2);
    }

    static IEnumerable<IndexEntry> ParseIndexRoot(byte[] v)
    {
        if (v.Length < 0x20) yield break;
        int hdr = 0x10;
        int entriesOff = BitConverter.ToInt32(v, hdr);
        int total = BitConverter.ToInt32(v, hdr + 4);
        int start = hdr + entriesOff;
        int end = hdr + total;
        if (end > v.Length) end = v.Length;
        foreach (IndexEntry e in ParseIndexEntries(v, start, end)) yield return e;
    }

    static IEnumerable<IndexEntry> ParseIndexAllocation(Fs fs, List<Run> runs)
    {
        int blockSize = fs.Boot.IndexBufferSize;
        int clustersPerBlock = blockSize / fs.Boot.ClusterSize;
        if (clustersPerBlock < 1) clustersPerBlock = 1;
        for (int i = 0; i < runs.Count; i++)
        {
            Run r = runs[i];
            if (r.Lcn < 0) continue;
            for (long c = 0; c < r.Clusters; c += clustersPerBlock)
            {
                long byteOff = (r.Lcn + c) * fs.Boot.ClusterSize;
                byte[] buf = fs.ReadAt(byteOff, blockSize);
                if (buf[0] != 'I' || buf[1] != 'N' || buf[2] != 'D' || buf[3] != 'X') continue;
                ApplyFixup(buf, fs.Boot.BytesPerSector);
                int hdr = 0x18;
                int entriesOff = BitConverter.ToInt32(buf, hdr);
                int total = BitConverter.ToInt32(buf, hdr + 4);
                int start = hdr + entriesOff;
                int end = hdr + total;
                if (end > buf.Length) end = buf.Length;
                foreach (IndexEntry e in ParseIndexEntries(buf, start, end)) yield return e;
            }
        }
    }

    static IEnumerable<IndexEntry> ParseIndexEntries(byte[] v, int start, int end)
    {
        int pos = start;
        while (pos + 0x10 <= end && pos + 0x10 <= v.Length)
        {
            long fileRef = BitConverter.ToInt64(v, pos) & (long)MFT_RECORD_MASK;
            int entryLen = BitConverter.ToUInt16(v, pos + 8);
            int flags = BitConverter.ToInt32(v, pos + 12);
            if ((flags & 0x02) != 0) break;
            if (entryLen < 0x10) break;
            int nameLen = v[pos + 0x50];
            string name = "";
            if (nameLen > 0 && pos + 0x52 + nameLen * 2 <= v.Length)
                name = Encoding.Unicode.GetString(v, pos + 0x52, nameLen * 2).TrimEnd('\0');
            yield return new IndexEntry { FileRef = (ulong)fileRef, Name = name };
            pos += entryLen;
        }
    }

    // ---- handle / fsutil resolution ---------------------------------------

    static ulong GetFrnByHandle(string path)
    {
        ulong frn; long size;
        GetHandleInfo(path, out frn, out size);
        return frn;
    }

    static void GetHandleInfo(string path, out ulong frn, out long size)
    {
        string norm = path.StartsWith("\\\\?\\") ? path : "\\\\?\\" + path;
        IntPtr h = CreateFileW(norm, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
            IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
        if (h == INVALID_HANDLE) throw new Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            BY_HANDLE_FILE_INFORMATION info;
            if (!GetFileInformationByHandle(h, out info)) throw new Win32Exception(Marshal.GetLastWin32Error());
            ulong f = ((ulong)info.FileIndexHigh << 32) | info.FileIndexLow;
            frn = f & MFT_RECORD_MASK;
            size = ((long)info.FileSizeHigh << 32) | info.FileSizeLow;
        }
        finally { CloseHandle(h); }
    }

    static List<Run> GetExtentsFsutil(string path)
    {
        ProcessStartInfo psi = new ProcessStartInfo("fsutil", "file queryextents \"" + path + "\"");
        psi.UseShellExecute = false;
        psi.CreateNoWindow = true;
        psi.RedirectStandardOutput = true;
        psi.RedirectStandardError = true;
        string output;
        using (Process p = Process.Start(psi))
        {
            output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
            p.WaitForExit();
        }
        List<Run> runs = new List<Run>();
        Regex re = new Regex(@"VCN:\s*0x[0-9A-Fa-f]+\s+Clusters:\s*0x([0-9A-Fa-f]+)\s+LCN:\s*0x([0-9A-Fa-f]+)",
            RegexOptions.IgnoreCase);
        foreach (Match m in re.Matches(output))
        {
            long clusters = Convert.ToInt64(m.Groups[1].Value, 16);
            long lcn = Convert.ToInt64(m.Groups[2].Value, 16);
            runs.Add(new Run { Vcn = 0, Lcn = lcn, Clusters = clusters });
        }
        if (runs.Count == 0) throw new IOException("No extents parsed from fsutil output: " + output.Trim());
        return runs;
    }

    // ---- copy --------------------------------------------------------------

    static void CopyExtents(Fs fs, List<Run> runs, long realSize, string dest)
    {
        string dir = Path.GetDirectoryName(dest);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir)) Directory.CreateDirectory(dir);

        int chunk = 4 * 1024 * 1024;
        byte[] buffer = new byte[chunk];
        long written = 0;

        using (FileStream outFs = new FileStream(dest, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            for (int i = 0; i < runs.Count && written < realSize; i++)
            {
                Run r = runs[i];
                long extentBytes = r.Clusters * fs.Boot.ClusterSize;
                long toCopy = Math.Min(extentBytes, realSize - written);

                if (r.Lcn < 0)
                {
                    long zeros = toCopy;
                    while (zeros > 0)
                    {
                        int n = (int)Math.Min(chunk, zeros);
                        Array.Clear(buffer, 0, n);
                        outFs.Write(buffer, 0, n);
                        zeros -= n; written += n;
                    }
                    continue;
                }

                long offset = r.Lcn * fs.Boot.ClusterSize;
                while (toCopy > 0)
                {
                    int n = (int)Math.Min(chunk, toCopy);
                    byte[] data = fs.ReadAt(offset, n);
                    outFs.Write(data, 0, data.Length);
                    offset += data.Length; toCopy -= data.Length; written += data.Length;
                }
            }
        }
    }

    static string VolumeFromPath(string path)
    {
        string s = path;
        if (s.StartsWith("\\\\?\\")) s = s.Substring(4);
        if (s.Length >= 2 && s[1] == ':') return "\\\\.\\" + char.ToUpperInvariant(s[0]) + ":";
        throw new ArgumentException("Cannot derive volume from path: " + path);
    }
}
