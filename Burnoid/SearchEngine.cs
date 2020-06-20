using Burnoid.WindowsLibrary;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace Burnoid
{
    public class SearchEngine
    {
        public delegate void MemoryChangedEventHandler(List<MemorryValue> memorryValues);
        public event MemoryChangedEventHandler MemoryChanged;
        public int MatchChecker(string Text, string chunk)
        {
            return -1;
        }

        void DoRtlAdjustPrivilege()
        {
            bool bPrev = false;
            ntdll.RtlAdjustPrivilege((int)SePrivelege.SeDebugPrivilege, true, true, out bPrev);
        }

        public (long, Dictionary<string, int>) Search(Process process)
        {
            //List<MemoryDumpChunk> memoryDumpChunks = new List<MemoryDumpChunk>();
            Dictionary<string, int> memoryDumpChunks = new Dictionary<string, int>();
            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Restart();
            SYSTEM_INFO msi = new SYSTEM_INFO();
            Kernel32.GetSystemInfo(ref msi);
            MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();
            long ProcMinAddress = (long)msi.lpMinimumApplicationAddress;
            IntPtr procMinPtr = msi.lpMinimumApplicationAddress;
            long ProcMaxAddress = (long)msi.lpMaximumApplicationAddress;
            IntPtr processHandle = process.Handle;
            int bytesRead = 0;
            using (StreamWriter swByte = new StreamWriter("RAM_Dump_Byte.txt"))
            {
                using (StreamWriter swChar = new StreamWriter("RAM_Dump_Char.txt"))
                {
                    using (StreamWriter swSectors = new StreamWriter("RAM_Dump_Sectors.txt"))
                    {
                        using (StreamWriter swInt = new StreamWriter("RAM_Dump_Int.txt"))
                        {
                            swByte.WriteLine(DateTime.Now);
                            swByte.WriteLine("");
                            int sector = 0;
                            MemoryDumpChunk memoryDumpChunk = new MemoryDumpChunk();
                            while (ProcMinAddress < ProcMaxAddress)
                            {
                                Kernel32.VirtualQueryEx(processHandle, procMinPtr, out mbi, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));
                                swByte.WriteLine("Sector done!" + "Address: " + string.Format("0x{0}", (procMinPtr).ToString("X16")) + " Number: " + sector);
                                swChar.WriteLine("Sector done!" + "Address: " + string.Format("0x{0}", (procMinPtr).ToString("X16")) + " Number: " + sector);
                                swSectors.WriteLine("Sector done!" + "Address: " + string.Format("0x{0}", (procMinPtr).ToString("X16")) + " Number: " + sector);
                                if (mbi.Protect == Kernel32.PAGE_READWRITE && mbi.State == Kernel32.MEM_COMMIT)
                                {
                                    byte[] buffer = new byte[mbi.RegionSize];

                                    Kernel32.ReadProcessMemory((int)processHandle, mbi.BaseAddress, buffer, mbi.RegionSize, ref bytesRead);

                                    byte[] IntBufferValue = new byte[sizeof(int)];
                                    int bufIter = 0;
                                    string intAddress = string.Format("0x{0}", (mbi.BaseAddress).ToString("X16"));
                                    if ((mbi.RegionSize % 4) != 0)
                                    {
                                        throw new Exception("x");
                                    }
                                    for (int x = 0; x < mbi.RegionSize; x++)
                                    {
                                        string Address = string.Format("0x{0}", (mbi.BaseAddress + x).ToString("X16"));
                                        byte Value = buffer[x];
                                        memoryDumpChunk.Address = Address;
                                        memoryDumpChunk.charValue = (char)Value;
                                        memoryDumpChunk.intValue = (int)Value;
                                        memoryDumpChunk.byteValue = Value;
                                        memoryDumpChunk.boolValue = Convert.ToBoolean(Value);
                                        memoryDumpChunk.shortValue = (short)Value;
                                        memoryDumpChunk.longValue = (long)Value;
                                        memoryDumpChunk.uintValue = (uint)Value;
                                        memoryDumpChunk.ulongValue = (uint)Value;
                                        //memoryDumpChunks.Add(memoryDumpChunk);
                                        swByte.WriteLine(Address + " : " + memoryDumpChunk.byteValue);
                                        swChar.WriteLine(Address + " : " + memoryDumpChunk.charValue);

                                        if (bufIter < 4)
                                        {
                                            IntBufferValue[bufIter] = memoryDumpChunk.byteValue;
                                        }
                                        if (bufIter == 4)
                                        {
                                            bufIter = 0;
                                            int value = BitConverter.ToInt32(IntBufferValue, 0);
                                            swInt.WriteLine(intAddress + " : Int32: " + value + " Hex: " + string.Format("0x{0}", BitConverter.ToInt32(IntBufferValue, 0).ToString("X16")) + " UInt32: " + BitConverter.ToUInt32(IntBufferValue, 0));
                                            memoryDumpChunks.Add(intAddress, value);
                                            IntBufferValue[bufIter] = memoryDumpChunk.byteValue;
                                            intAddress = Address;
                                        }

                                        bufIter++;
                                    }
                                }

                                ProcMinAddress += mbi.RegionSize;
                                procMinPtr = new IntPtr(ProcMinAddress);
                                sector++;
                            }
                        }
                    }
                }
            }
            stopwatch.Stop();
            return (stopwatch.ElapsedMilliseconds, memoryDumpChunks);
        }
        public async Task ContiniousScanAsync(Process process)
        {
            new Task(() => ContiniousScan(process)).Start();
        }
        private void ContiniousScan(Process process)
        {
            Dictionary<string, byte> MemoryDictionary = new Dictionary<string, byte>();
            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Restart();
            SYSTEM_INFO msi = new SYSTEM_INFO();
            Kernel32.GetSystemInfo(ref msi);
            MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();
            IntPtr maxApplicationAddress = msi.lpMaximumApplicationAddress;
            IntPtr minApplicationAddress = msi.lpMinimumApplicationAddress;
            IntPtr ProcHandle = process.Handle;
            int bytesRead = 0;

            bool LoopScanning = true;
            Dictionary<string, byte> oldDictionary = new Dictionary<string, byte>();
            while (LoopScanning)
            {
                MemoryDictionary.Clear();
                minApplicationAddress = msi.lpMinimumApplicationAddress;
                while ((long)minApplicationAddress < (long)maxApplicationAddress)
                {
                    Kernel32.VirtualQueryEx(ProcHandle, minApplicationAddress, out mbi, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));
                    if (mbi.Protect == Kernel32.PAGE_READWRITE && mbi.State == Kernel32.MEM_COMMIT)
                    {
                        byte[] buffer = new byte[mbi.RegionSize];
                        Kernel32.ReadProcessMemory((int)ProcHandle, mbi.BaseAddress, buffer, mbi.RegionSize, ref bytesRead);
                        for (int x = 0; x < mbi.RegionSize; x++)
                        {
                            MemoryDictionary.Add(string.Format("0x{0}", (mbi.BaseAddress + x).ToString("X16")), buffer[x]);
                        }
                    }
                    minApplicationAddress = new IntPtr(((long)minApplicationAddress + mbi.RegionSize));
                }
                if (oldDictionary.Count != 0)
                {
                    List<MemorryValue> memvals = CheckDictionaries(oldDictionary, MemoryDictionary);
                    if (memvals.Count > 0)
                    {
                        MemoryChanged.Invoke(memvals);
                    }
                }
                oldDictionary = new Dictionary<string, byte>(MemoryDictionary);
            }
        }
        private List<MemorryValue> CheckDictionaries(Dictionary<string, byte> oldDict, Dictionary<string, byte> newDict)
        {
            Dictionary<string, byte> shortestDict = (oldDict.Count > newDict.Count ? newDict : oldDict);
            List<MemorryValue> memorryValues = new List<MemorryValue>();
            foreach (KeyValuePair<string, byte> kvp in shortestDict)
            {
                if (oldDict.ContainsKey(kvp.Key) && newDict.ContainsKey(kvp.Key))
                {
                    byte oldValue = oldDict[kvp.Key];
                    byte newValue = newDict[kvp.Key];
                    if (oldValue != newValue)
                    {
                        memorryValues.Add(new MemorryValue() { Address = kvp.Key, newValue = newValue, oldValue = oldValue });
                    }
                }
            }
            return memorryValues;
        }
        public class MemoryDumpChunk
        {
            public string Address;
            public char charValue;
            public int intValue;
            public byte byteValue;
            public bool boolValue;
            public short shortValue;
            public long longValue;
            public uint uintValue;
            public ulong ulongValue;
        }

        public struct MemorryValue
        {
            public string Address { get; set; }
            public byte oldValue { get; set; }
            public byte newValue { get; set; }
        }

    }
}
