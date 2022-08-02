using System;
using System.IO;
using System.Linq;
using System.Reflection.PortableExecutable;

//standalone .exe aob scanner
//offsets are worked out where possible/easy.
//expect things to break in new patches.
//aobs from pav, nord, myself, various CE tables etc. all technically fromsoft IP.

namespace aobScanExe
{
    class Program
    {
        static void Main(string[] args)
        {
            var gameExes = new string[] {
                @"C:\temp\er\eldenring_1.02.3.exe",
                @"C:\temp\er\eldenring_1.03.2.exe",
                @"C:\temp\er\eldenring_1.04.1.exe",
                @"C:\temp\er\eldenring_1.05.0.exe",
                @"C:\temp\DarkSoulsIII_1.15.exe",
                @"C:\temp\sekiro_1.06.unpacked.exe", //unpacked with steamless
            };
            foreach (var exe in gameExes)
            {
                Console.WriteLine("Processing exe: " + exe);
                new Program().run(exe);
                Console.WriteLine();
            }
            Console.ReadLine();
        }
        public void run(string exe)
        {
            var strim = new FileStream(exe, FileMode.Open, FileAccess.Read, FileShare.Read);
            var headers = new PEHeaders(strim);
            //from exes tend to have two relevant .text sections
            SectionHeader header = new SectionHeader();
            SectionHeader header2 = new SectionHeader();
            bool gotFirst = false;
            foreach (var sec in headers.SectionHeaders)
            {
                if (sec.Name == ".text")
                {
                    if (gotFirst)
                    {
                        header2 = sec;
                        break;
                    }
                    else
                    {
                        header = sec;
                        gotFirst = true;
                    }
                }
            }
            Console.WriteLine($"First text section: offset {header.PointerToRawData} size {header.SizeOfRawData}, virtual addr hex {header.VirtualAddress:X2}");
            Console.WriteLine($"Second text section: offset {header2.PointerToRawData} size {header2.SizeOfRawData}, virtual addr hex {header2.VirtualAddress:X2}");
            //read all in memory - faster than seeking through
            var textSection = new byte[header.SizeOfRawData];
            strim.Seek(header.PointerToRawData, SeekOrigin.Begin);
            if (strim.Read(textSection) != header.SizeOfRawData)
            {
                Console.WriteLine("Read failed");
                return;
            }
            var textSection2 = new byte[header2.SizeOfRawData];
            strim.Seek(header2.PointerToRawData, SeekOrigin.Begin);
            if (strim.Read(textSection2) != header2.SizeOfRawData)
            {
                Console.WriteLine("Read failed");
                return;
            }

            Console.WriteLine();

            Action doERScan = () =>
            {
                //up to date as of ER 1.05; will mostly work on older versions.
                findAddr(textSection, header.VirtualAddress, "48 8B 05 ???????? 48 85 C0 74 0F 48 39 88", "worldChrManOff", 3, 7); //CS::WorldChrManImp //if this finds too many, try 48 8B 05 ???????? 48 85 C0 74 0F 48 39 88 ???????? 75 06 89 B1 5C030000 0F28 05 ???????? 4C 8D 45 E7
                findAddr(textSection, header.VirtualAddress, "E8 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 4C 8B A8 ?? ?? ?? ?? 4D 85 ED 0F 84 ?? ?? ?? ??", "CS::WorldChrManImp (alternate)", 5 + 3, 5 + 3 + 4);
                findAddr(textSection, header.VirtualAddress, "E8 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 4C 8B A8 ?? ?? ?? ?? 4D 85 ED 0F 84 ?? ?? ?? ??", "CS::WorldChrManImp offset", 5 + 7 + 3);
                findAddr(textSection, header.VirtualAddress, "0F 29 74 24 40 0F 1F 40 00", "hitboxBase", 12, 12 + 7);
                findAddr(textSection, header.VirtualAddress, "803D ???????? 00 74 1f ba 05000000", "groupMask",  2, 7); //may not be exactly group mask if they change it between patches
                //or F3 0F 7F 4D D0 80 3D ?? ?? ?? ?? 00 74 1F BA 05
                //C6 05 ?? ?? ?? 02 01 finds movs to offsets starting with 02 (from instruction), first result is generally an address near group mask (eg. +9)
                findAddr(textSection, header.VirtualAddress, "0F B6 25 ?? ?? ?? ?? 44 0F B6 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 F8", "meshesOff",  3, 7); //or just 44 0F B6 25 ?? ?? ?? ?? 44 0F B6 3D ?? ?? ?? ??
                //fallback search: search C6 05 ?? ?? ?? ?? 00. many results. look for pair of two consecutive addresses in two consecutive instructions
                findAddr(textSection, header.VirtualAddress, "48 8B 05 ?? ?? ?? ?? 0F B6 40 10 C3", "CS::GameMan", 3, 7); //assuming the offset is fixed at +10
                findAddr(textSection, header.VirtualAddress, "80 BF B8 00 00 00 00 74 53", "logoScreenBase",  justOffset: 7); //if the regs change, look for a mov byte ptr +280, call, cmp byte ptr +B8, 74 53 (je short distance)
                findAddr(textSection, header.VirtualAddress, "48 8B 48 08 49 89 8D A8 06 00 00", "targetHookLoc_1.03"); //or 48 8B 48 08 49 89 8D A8 06 00 00 49 8B CE E8
                findAddr(textSection, header.VirtualAddress, "48 8B 48 08 49 89 8D A0 06 00 00", "targetHookLoc_1.04");
                //or: 488b8f88000000e8?????? 4th result is shortly before it. look for mov rcx of rdi+88. expect addr ending in 2.
                findAddr(textSection, header.VirtualAddress, "803D ???????? 00 74 09 48 8D4D A0 E8 ???????? 4D 85E4", "miscDebugBase",  2, 7); //expect debug flags to be re-ordered in new patches
                findAddr(textSection, header.VirtualAddress, "0FB63D ???????? 48 85C0 75 2E", "noAIUpdate",  3, 7);
                //multiple results but may find debug base or nearby address: e8 ?? ?? ?? ?? 80 3d ?? ?? ?? ?? 00 0f 85
                findAddr(textSection, header.VirtualAddress, "48 8b 05 ?? ?? ?? ?? 0f b6 3d ?? ?? ?? ?? 48 85 c0", "possibly noAIUpdate 1.03.2/1.04.0", 3, 7);
                findAddr(textSection, header.VirtualAddress, "48 8B 05 ?? ?? ?? ?? 41 83 FF 02 ?? ?? 48 85 C0", "chrDbg", 3, 7);
                findAddr(textSection, header.VirtualAddress, "48 8B 0D ?? ?? ?? ?? 83 79 ?? 00 0F 85 ?? ?? ?? ?? 49 8B 87 ?? ?? ?? ?? 48 8B 88 ?? ?? ?? ?? E8", "newMenuSystem", 3, 7);
                findAddr(textSection, header.VirtualAddress, "48 89 5C 24 10 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24", "fontDrawOffset WIP take last match");
                //findAddr(textSection, header.VirtualAddress, "EB AC 7A 44 78 42 56 5C", "fontDrawOffset 1.03.2?"); //look around here, may not be the exactly address, try +D?
                findAddr(textSection, header.VirtualAddress, "48 8B 0D ???????? 48 85 C9 ???? 83 CF 20", "DbgEventManOff", 3, 7);
                findAddr(textSection, header.VirtualAddress, "e8 ?? ?? ?? ?? 84 c0 74 06 e8 ?? ?? ?? ??", "Event patch search WIP, look around first"); //many results, take first? finds both addresses (as calls)
                findAddr(textSection, header.VirtualAddress, "48 8B 0D ?? ?? ?? ?? 48 ?? ?? ?? 44 0F B6 61 ?? E8 ?? ?? ?? ?? 48 63 87 ?? ?? ?? ?? 48 ?? ?? ?? 48 85 C0", "CS::FieldArea", 3, 7);
                findAddr(textSection, header.VirtualAddress, "EB 05 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 84 C0 75 0C", "free cam patch loc WIP, follow jumps from here"); //follow jumps until an xor al,al followed by actual or obfuscated return. don't scroll up, weird asm.
                findAddr(textSection, header.VirtualAddress, "32 C0 48 8D 64 24 08 FF 64 24 F8 48 8D 05 ?? ?? ?? ?? C3 0F 28 C3", "free cam patch loc older patch?");
                //E9 ?? ?? ?? ?? 48 C7 45 E0 07 00 00 00 may help in some older patches; take 3rd result in 1.04.0.
                //it's meant to be //LockTgtMan->IsLockMode, but i don't know what to do with this. ask Pav if AOBs break
                findAddr(textSection, header.VirtualAddress, "8B 83 C8 00 00 00 FF C8 83 F8 01", "free cam player control patch loc"); //(offset C8 may change). weird cmp may change too.
                findAddr(textSection, header.VirtualAddress, "74 ?? C7 45 38 58 02 00 00 C7 45 3C 02 00 00 00 C7 45 40 01 00 00 00 48 ?? ?? ?? ?? ?? ?? 48 89 45 48 48 8D 4D 38 E8 ?? ?? ?? ?? E9", "map open in combat WIP", justOffset: -7); //should find a JE not long after
                findAddr(textSection, header.VirtualAddress, "E8 ?? ?? ?? ?? 84 C0 75 ?? 38 83 ?? ?? ?? ?? 75 ?? 83 e7 fe", "map stay open in combat");
                //for some older patch, maybe 1.03.2: E8 ?? ?? ?? ?? 84 C0 75 ?? 38 83 EA 3C 00 00 finds the call
                //maybe try E8 ?? ?? ?? ?? 84 C0 75 ?? 38 83 ?? ?? 00 00, multiple results, 2nd last? //follow the call, check for x-refs. should be about 5. can use this to find one from the other, and also crafting check etc.
                findAddr(textSection, header.VirtualAddress, "48 8B 41 08 0F BE 80 B1 E9 00 00", "enemyRepeatActionOff (1st sect)", justOffset: 7); //expect obfuscated ret afterwards
                findAddr(textSection2, header2.VirtualAddress, "48 8B 41 08 0F BE 80 B1 E9 00 00", "enemyRepeatActionOff (2nd sect)", justOffset: 7); //moves between sections across patches, so check both. kinda weird ngl.
                findAddr(textSection, header.VirtualAddress, "48 83EC 48 48 C74424 28 FEFFFFFF E8 ?? ?? ?? ?? 48", "warp call one");
                findAddr(textSection, header.VirtualAddress, "488B05 ???????? 8988 300C0000 C3", "warp call two");
                findAddr(textSection, header.VirtualAddress, "48 C7 05 ?? ?? ?? ?? 00 00 00 00 C6 05 ?? ?? ?? ?? 01 48 83 C4 28 C3", "usrInputMgrImplOff (WIP take first)", 3, 11); //interestingly, the following instruction refs something 8 bytes before it
                findAddr(textSection, header.VirtualAddress, "80B9 ????0000 00 48 8B5C24 40", "steam input flag check", 2); //in case the offset changes, this should find it
                findAddr(textSection, header.VirtualAddress, "48 8B 05 ?? ?? ?? ?? F3 0F 10 88 ?? ?? ?? ?? F3 0F", "csFlipperOff", 3, 7); //identical to sekiro, likely to keep working.
                findAddr(textSection, header.VirtualAddress, "48 8B 05 ?? ?? ?? ?? F3 0F 10 88 ?? ?? ?? ?? F3 0F", "csFlipperOff gameSpeedOffset", 7 + 4);
                findAddr(textSection, header.VirtualAddress, "4883EC20F681????000001488bd97408", "no-death offset in CSChrDataModule", 4 + 2);
                findAddr(textSection, header.VirtualAddress, "48 8B 05 ?? ?? ?? ?? 48 85 C0 74 05 48 8B 40 58 C3 C3", "toPGDataOff", 3, 7); //obsolete, *ptr + 8 to CS::PlayerGameData

                //CS::CSTrophyImp has 14 references, not sure how best to pick one for an AOB. just find it by RTTI scan if necessary.
                findAddr(textSection, header.VirtualAddress, "48833D ???????? 00 75 31 4C 8B05 ???????? 4C 8945 10 BA 08000000 8D4A 18", "CS::CSTrophyImp", 3, 8);

                findAddr(textSection, header.VirtualAddress, "90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90", "codeCave_48_nops");
                findAddr(textSection, header.VirtualAddress, "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00", "codeCave_48_zeroes"); //mostly pointless, just open x64dbg and go to end
            };

            Action doDS3Scan = () =>
            {
                findAddr(textSection, header.VirtualAddress, "75 1F 4C8D0D ???????? 4C8D05 ???????? 488D0D ???????? BA B1000000 E8 ???????? C605 ???????? 01", "debug flags / WorldChrManDbg?", 2 + 7 + 7 + 7 + 5 + 5 + 2, 2 + 7 + 7 + 7 + 5 + 5 + 2 + 5);
                findAddr(textSection, header.VirtualAddress, "E8 ???????? 488B05 ???????? 488B40 10 B9 F0000000 C680 72050000 01 C605 ???????? 01 C605 ???????? 01", "GROUP_MASK", 5 + 7 + 4 + 5 + 7 + 2, 5 + 7 + 4 + 5 + 7 + 2 + 5);
                findAddr(textSection, header.VirtualAddress, "E8 ???????? EB 03 488BC6 488905 ???????? 48833D ???????? 00 75 35 4C8B05 ???????? 4C8945 D7 BA 08000000 8D4A 30 E8 ???????? ", "hitbox base WIP take first", 5 + 2 + 3 + 7 + 3, 5 + 2 + 3 + 7 + 3 + 5);
                findAddr(textSection, header.VirtualAddress, "4053 56 4156 4883EC 40 440FB635 ???????? 4C896424 70 4C896C24 38 4C897C24 30 440FB63D ???????? ", "meshes off", 2 + 1 + 2 + 4 + 8 + 5 + 5 + 5 + 4, 2 + 1 + 2 + 4 + 8 + 5 + 5 + 5 + 4 + 4);
                //findAddr(textSection, header.VirtualAddress, "48 8B 05 ?? ?? ?? ?? F3 0F 10 88 ?? ?? ?? ?? F3 0F", "csFlipperOff", 3, 7); //doesn't work for DS3
            };

            Action doSekiroScan = () =>
            {
                findAddr(textSection, header.VirtualAddress, "48 8B 05 ?? ?? ?? ?? F3 0F 10 88 ?? ?? ?? ?? F3 0F", "csFlipperOff", 3, 7);
            };

            if (exe.ToLower().Contains("elden")) { doERScan(); }
            if (exe.ToLower().Contains("darksoulsiii")) { doDS3Scan(); }
            if (exe.ToLower().Contains("sekiro")) { doSekiroScan(); }
        }

        //borrowed from https://github.com/Wulf2k/ER-Patcher.git
        public byte[] hs2b(string hex)
        {
            hex = hex.Replace(" ", "");
            hex = hex.Replace("-", "");
            hex = hex.Replace(":", "");

            byte[] b = new byte[hex.Length >> 1];
            for (int i = 0; i <= b.Length - 1; ++i)
            {
                b[i] = (byte)((hex[i * 2] - (hex[i * 2] < 58 ? 48 : (hex[i * 2] < 97 ? 55 : 87))) * 16 + (hex[i * 2 + 1] - (hex[i * 2 + 1] < 58 ? 48 : (hex[i * 2 + 1] < 97 ? 55 : 87))));
            }
            return b;
        }

        public byte[] hs2w(string hex)
        {
            hex = hex.Replace(" ", "");
            hex = hex.Replace("-", "");
            hex = hex.Replace(":", "");

            byte[] wild = new byte[hex.Length >> 1];
            for (int i = 0; i <= wild.Length - 1; ++i)
            {
                if (hex[i * 2].Equals('?'))
                {
                    wild[i] = 1;
                }
            }
            return wild;
        }

        public int FindBytes(byte[] buf, byte[] find, byte[] wild, int index = 0)
        {
            if (buf == null || find == null || buf.Length == 0 || find.Length == 0 || find.Length > buf.Length) return -1;
            for (int i = index; i < buf.Length - find.Length + 1; i++)
            {
                if (buf[i] == find[0])
                {
                    for (int m = 1; m < find.Length; m++)
                    {
                        if ((buf[i + m] != find[m]) && (wild[m] != 1)) break;
                        if (m == find.Length - 1) return i;
                    }
                }
            }
            return -1;
        }

        public int findAddr(byte[] buf, int startAddr, string find, string desc, int readoffset32 = -1000, int nextInstOffset = -1000, int justOffset = -1000)
        {
            int count = 0;

            byte[] fb = hs2b(find);
            byte[] fwb = hs2w(find);

            int index = 0;
            
            while (index != -1)
            {
                index = FindBytes(buf, fb, fwb, index);
                if (index != -1)
                {
                    count++;
                    int rva = index + startAddr;
                    string output = desc + " found at index " + index + " offset hex " + rva.ToString("X2");

                    if (readoffset32 > -1000)
                    {
                        int index32 = index + readoffset32;
                        var val = BitConverter.ToInt32(buf, index32);
                        output += " raw val " + val.ToString("X2");
                        if (nextInstOffset > -1000)
                        {
                            int next = startAddr + index + nextInstOffset + val;
                            output += " final offset " + next.ToString("X2");
                        }
                    }

                    if (justOffset > -1000)
                    {
                        output += " with offset " + (rva + justOffset).ToString("X2");
                    }

                    Console.WriteLine(output);
                    index += fb.Length; //keep searching in case there's multiple.
                }
            }
            if (0 == count) { Console.WriteLine("Nothing found for " + desc); }
            return count;
        }
    }
}
