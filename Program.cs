using System;
using System.IO;
using System.Linq;
using System.Reflection.PortableExecutable;

//standalone .exe aob scanner
//offsets are worked out where possible/easy.
//expect things to break in new patches.
//aobs from pav, nord, myself, various CE tables etc. all technically fromsoft IP.

//make sure sekiro is unpacked with steamless

namespace aobScanExe
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.Write("Enter test AOB, or blank to run all: ");
            var testAob = Console.ReadLine();

            Console.Write(@"Enter exe folder (default C:\fromexes): ");
            var exesFolder = Console.ReadLine();
            if (string.IsNullOrEmpty(exesFolder)) { exesFolder = @"C:\fromexes"; }

            var gameExes = Directory.GetFiles(exesFolder, "*.exe");

            foreach (var exe in gameExes)
            {
                Console.WriteLine("Processing exe: " + exe);
                //var sw = new System.Diagnostics.Stopwatch();
                //sw.Start();
                var scanner = new Program();
                //scanner.outputConsole = false;
                scanner.run(exe, testAob);
                //sw.Stop();
                //Console.WriteLine($"time: {sw.ElapsedMilliseconds}");
                Console.WriteLine();
            }
            Console.ReadLine();
        }
        public void run(string exe, string testAob = null)
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
            //Console.WriteLine($"First text section: offset {header.PointerToRawData} size {header.SizeOfRawData}, virtual addr hex {header.VirtualAddress:X2}");
            //Console.WriteLine($"Second text section: offset {header2.PointerToRawData} size {header2.SizeOfRawData}, virtual addr hex {header2.VirtualAddress:X2}");
            int emptySpaceLocation = headers.SectionHeaders[0].VirtualAddress + headers.SectionHeaders[0].VirtualSize;
            int emptySpaceSize = headers.SectionHeaders[1].VirtualAddress - emptySpaceLocation;
            if (testAob == null)
            {
                Console.WriteLine($"Empty space after first section: offset {emptySpaceLocation:X} size {emptySpaceSize:X}");
            }
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
                //findAddr(textSection, header.VirtualAddress, "48 8B 05 ???????? 48 85 C0 74 0F 48 39 88", "worldChrManOff", 3, 7, startIndex: 4100000); //CS::WorldChrManImp //if this finds too many, try 48 8B 05 ???????? 48 85 C0 74 0F 48 39 88 ???????? 75 06 89 B1 5C030000 0F28 05 ???????? 4C 8D 45 E7
                findAddr(textSection, header.VirtualAddress, "E8 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 4C 8B A8 ?? ?? ?? ?? 4D 85 ED 0F 84 ?? ?? ?? ??", "CS::WorldChrManImp", 5 + 3, 5 + 3 + 4, startIndex: 1800000);
                findAddr(textSection, header.VirtualAddress, "E8 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 4C 8B A8 ?? ?? ?? ?? 4D 85 ED 0F 84 ?? ?? ?? ??", "CS::WorldChrManImp offset", 5 + 7 + 3, startIndex: 1800000);
                findAddr(textSection, header.VirtualAddress, "48 8B0D ???????? E8 ???????? F3 0F1057 ?? 48 8BCB 0FB693 ????0000 E8 ???????? 48 8BCB E8 ???????? 48 8B0D ????????", "hitboxBase", 1 + 2, 1 + 2 + 4, startIndex: 10900000);
                findAddr(textSection, header.VirtualAddress, "80B9 ????0000 00 48 8BF9 BE FFFFFFFF 74 ?? 48 8B19 48 85DB 74 ??", "hitboxOffset", 2, startIndex: 5200000);
                //group mask is a bit of a meme as it can change between patches. should be 010101.... in memory (doesn't need live game; can check in x64dbg).
                findAddr(textSection, header.VirtualAddress, "803D ???????? 00 0F1000 0F1145 D0 0F84 ????0000 803D ???????? 00 0F85 ????0000 803D ???????? 00 B3 01 C605 ???????? 00 74 ?? BA 01000000", "groupMaskBase", 2, 2 + 4 + 1, startIndex: 6500000); //not always first address
                findAddr(textSection, header.VirtualAddress, "803D ???????? 00 74 1f ba 05000000", "groupMaskTrees",  2, 7, startIndex: 6500000);
                findAddr(textSection, header.VirtualAddress, "803D ???????? 00 B3 01 C605 ???????? 0074 1F BA 01000000 48 8D4D ?? E8 ????????", "groupMaskMap", 2, 2 + 4 + 1, startIndex: 6500000); //803D ???????? 00 B3 01 C605 ???????? 0074 1F BA 01000000 48 8D4D ?? E8 ???????? F3 0F6F4D ?? 0F1000 66 0FEBC8 F3 0F7F4D ?? 803D ???????? 0074 1F
                findAddr(textSection, header.VirtualAddress, "0F B6 25 ?? ?? ?? ?? 44 0F B6 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 F8", "meshesOff",  3, 7, startIndex: 7100000); //or just 44 0F B6 25 ?? ?? ?? ?? 44 0F B6 3D ?? ?? ?? ??
                //fallback search: search C6 05 ?? ?? ?? ?? 00. many results. look for pair of two consecutive addresses in two consecutive instructions
                findAddr(textSection, header.VirtualAddress, "48 8B 05 ?? ?? ?? ?? 0F B6 40 10 C3", "CS::GameMan", 3, 7, startIndex: 6500000); //assuming the offset is fixed at +10
                findAddr(textSection, header.VirtualAddress, "74 53 48 8B05 ???????? 48 85C0 75 ?? 48 8D0D ???????? E8 ???????? 4C 8BC8 4C 8D05 ???????? BA ????0000 48 8D0D ???????? E8 ????????", "logoScreenBase", startIndex: 10900000);
                findAddr(textSection, header.VirtualAddress, "48 8B48 ?? 49 898D ????0000 49 8BCE E8 ???????? 84C0 75 ?? 49 8B5E ?? 48 8D4D ?? E8 ????????", "targetHookLoc", startIndex: 7100000);
                findAddr(textSection, header.VirtualAddress, "48 8B48 ?? 49 898D ????0000 49 8BCE E8 ???????? 84C0 75 ?? 49 8B5E ?? 48 8D4D ?? E8 ????????", "targetHookLoc offset", 1 + 2 + 1 + 1 + 2, startIndex: 7100000);
                //findAddr(textSection, header.VirtualAddress, "803D ???????? 00 74 09 48 8D4D A0 E8 ???????? 4D 85E4", "miscDebugBase",  2, 7, startIndex: 4200000); //this just seems to be something else, not 100% sure, but should be able to find everything from no goods or no ai update
                findAddr(textSection, header.VirtualAddress, "803D ???????? 00 75 05 45 33C0 EB 03 41 B0 01 48 8D8424 ??000000 48 898424 ??000000 41 8B06 898424 ??000000 48 8D8E ????0000 48 8D9424 ??000000 E8 ???????? 0FB6D0", "noGoodsConsume", 2, 2 + 4 + 1, startIndex: 6300000);
                findAddr(textSection, header.VirtualAddress, "0FB63D ???????? 48 85C0 75 2E", "noAIUpdate",  3, 7, startIndex: 3800000);
                //multiple results but may find debug base or nearby address: e8 ?? ?? ?? ?? 80 3d ?? ?? ?? ?? 00 0f 85
                //findAddr(textSection, header.VirtualAddress, "48 8b 05 ?? ?? ?? ?? 0f b6 3d ?? ?? ?? ?? 48 85 c0", "possibly noAIUpdate 1.03.2/1.04.0", 3, 7, startIndex: 3800000); //TODO: work out what this is, maybe remove
                findAddr(textSection, header.VirtualAddress, "48 8B 05 ?? ?? ?? ?? 41 83 FF 02 ?? ?? 48 85 C0", "chrDbg", 3, 7, startIndex: 5000000);
                findAddr(textSection, header.VirtualAddress, "48 8B05 ???????? 33DB 48 897424 ?? 48 8BF1 895C24 ?? 48 85C0 75 ??", "CSMenuManImp", 3, 7, startIndex: 7400000); //CSMenuManImp
                findAddr(textSection, header.VirtualAddress, "48 895C24 10 55 56 57 41 54 41 55 41 56 41 57 48 8D6C24 ?? 48 81EC ???????? 0F29B424 ????????", "fontDrawOffset", startIndex: 39000000);
                findAddr(textSection, header.VirtualAddress, "48 8B 0D ???????? 48 85 C9 ???? 83 CF 20", "DbgEventManOff", 3, 7, startIndex: 10000000);
                //findAddr(textSection, header.VirtualAddress, "e8 ?? ?? ?? ?? 84 c0 74 06 e8 ?? ?? ?? ??", "Event patch search WIP, look around first"); //many results, take first? finds both addresses (as calls)
                findAddr(textSection, header.VirtualAddress, "E8 ???????? 84C0 74 06 E8 ???????? 90 48 8BC7", "Event patch func 1", 1, 1 + 4, startIndex: 5500000);
                findAddr(textSection, header.VirtualAddress, "E8 ???????? 84C0 74 06 E8 ???????? 90 48 8BC7", "Event patch func 2", 1 + 4 + 2 + 1 + 1 + 1, 1 + 4 + 2 + 1 + 1 + 1 + 4, startIndex: 5500000);
                findAddr(textSection, header.VirtualAddress, "48 8B 0D ?? ?? ?? ?? 48 ?? ?? ?? 44 0F B6 61 ?? E8 ?? ?? ?? ?? 48 63 87 ?? ?? ?? ?? 48 ?? ?? ?? 48 85 C0", "CS::FieldArea", 3, 7, startIndex: 6400000);
                findAddr(textSection, header.VirtualAddress, "EB 05 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 84 C0 75 0C", "free cam patch loc, 1st called addr", readoffset32: 1 + 1 + 1 + 4 + 1, 1 + 1 + 1 + 4 + 1 + 4, startIndex: 7000000); //generally a jmp followed by an int3-int3 or nop-int3. normally we patch the final destination of the jumps, but it should work here too.
                //old method: manually follow jumps until an xor al,al followed by actual or obfuscated return. don't scroll up, weird asm.
                //findAddr(textSection, header.VirtualAddress, "32 C0 48 8D 64 24 08 FF 64 24 F8 48 8D 05 ?? ?? ?? ?? C3 0F 28 C3", "free cam patch loc older patch?", startIndex: 2000000); //only works in 1.03.2 //found at index 2237653 offset hex 2234D5
                //E9 ?? ?? ?? ?? 48 C7 45 E0 07 00 00 00 may help in some older patches; take 3rd result in 1.04.0.
                //it's meant to be //LockTgtMan->IsLockMode, but i don't know what to do with this. ask Pav if AOBs break
                findAddr(textSection, header.VirtualAddress, "8B 83 ?? 00 00 00 FF C8 83 F8 01", "free cam player control patch loc", startIndex: 6500000); //(offset C8 may change). weird cmp may change too.
                findAddr(textSection2, header2.VirtualAddress, "8B 83 ?? 00 00 00 FF C8 83 F8 01", "free cam player control patch loc (2nd section)"); //patches before 1.04. not yet confirmed that it still works. start index is pointless for 2nd section as it's so random.
                findAddr(textSection, header.VirtualAddress, "8B 93 c8 00 00 00 85 d2 0f ?? ?? ?? 00 00", "free cam player control patch loc 1.12", startIndex: 6500000); //code here changes too much for a stable aob
                findAddr(textSection, header.VirtualAddress, "E8 ???????? 84C0 74 ?? C745 ?? ???????? C745 ?? ???????? C745 ?? ???????? 48 8D05 ????????", "map open in combat", startIndex: 8000000);
                findAddr(textSection, header.VirtualAddress, "E8 ?? ?? ?? ?? 84 C0 75 ?? 38 83 ?? ?? 00 00 75 ?? 83 ?? fe 89", "map stay open in combat", startIndex: 9800000);
                //for some older patch, maybe 1.03.2: E8 ?? ?? ?? ?? 84 C0 75 ?? 38 83 EA 3C 00 00 finds the call
                //maybe try E8 ?? ?? ?? ?? 84 C0 75 ?? 38 83 ?? ?? 00 00, multiple results, 2nd last? //follow the call, check for x-refs. should be about 5. can use this to find one from the other, and also crafting check etc.
                findAddr(textSection, header.VirtualAddress, "48 8B 41 08 0F BE 80 ?? E9 00 00", "enemyRepeatActionOff (1st sect)", justOffset: 7); //expect obfuscated ret afterwards
                findAddr(textSection2, header2.VirtualAddress, "48 8B 41 08 0F BE 80 ?? E9 00 00", "enemyRepeatActionOff (2nd sect)", justOffset: 7); //moves between sections across patches, so check both. kinda weird ngl.
                findAddr(textSection, header.VirtualAddress, "48 83EC 48 48 C74424 28 FEFFFFFF E8 ?? ?? ?? ?? 48", "warp call one", startIndex: 6000000);
                findAddr(textSection, header.VirtualAddress, "488B05 ???????? 8988 ??0C0000 C3", "warp call two", startIndex: 6500000); //fixed for <1.04 but not tested in game
                findAddr(textSection, header.VirtualAddress, "48 8905 ???????? 48 8B05 ???????? E8 ???????? 4C 8B08 41 B8 ??000000 48 8D15 ????0000 48 8BC8 41 FF51 ?? 48 8B1D ????????", "usrInputMgrImplOff", 3, 7, startIndex: 1000000);
                findAddr(textSection, header.VirtualAddress, "80B9 ????0000 00 48 8B5C24 40", "steam input flag check", 2, startIndex: 31500000); //in case the offset changes, this should find it
                findAddr(textSection, header.VirtualAddress, "48 8B 05 ?? ?? ?? ?? F3 0F 10 88 ?? ?? ?? ?? F3 0F", "csFlipperOff", 3, 7, startIndex: 13800000); //identical to sekiro, likely to keep working.
                findAddr(textSection, header.VirtualAddress, "48 8B 05 ?? ?? ?? ?? F3 0F 10 88 ?? ?? ?? ?? F3 0F", "csFlipperOff gameSpeedOffset", 7 + 4, startIndex: 13800000);
                findAddr(textSection, header.VirtualAddress, "8973 ?? C743 ?? ??88883C EB ?? 8973 ??", "frame time target (1/60.0f)", justOffset: 6, startIndex: 13000000); //probably need windowed/borderless and your screen hz high enough to work
                findAddr(textSection, header.VirtualAddress, "4883EC20F681????000001488bd97408", "no-death offset in CSChrDataModule", 4 + 2, startIndex: 4200000);
                findAddr(textSection, header.VirtualAddress, "48 8B 05 ?? ?? ?? ?? 48 85 C0 74 05 48 8B 40 58 C3 C3", "GameDataMan", 3, 7, startIndex: 2300000); //*ptr + 8 to CS::PlayerGameData

                findAddr(textSection, header.VirtualAddress, "48833D ???????? 00 75 31 4C 8B05 ???????? 4C 8945 10 BA 08000000 8D4A 18", "CS::CSTrophyImp", 3, 8, startIndex: 13800000);

                findAddr(textSection, header.VirtualAddress, "894B 08 48 85F6 74 ?? 48 8D5424 ?? 48 8BCE E8 ???????? EB ??", "NPC part damage hook", startIndex: 5700000);

                findAddr(textSection, header.VirtualAddress, "74 28 48 8B45 ?? 48 85C0 74 07 F3 0F1048 ?? EB 08 F3 0F100D ????????", "Weapon upgrade rune cost", startIndex: 7500000);//patch to EB (jmp)
                findAddr(textSection, header.VirtualAddress, "8BF8 44 8BC3 48 8D55 ?? 48 8D4D ?? E8 ????????", "Weapon upgrade material cost", startIndex: 8500000); //patch to 31 FF (xor edi,edi)

                findAddr(textSection, header.VirtualAddress, "74 ?? 48 8B0D ???????? BE 01000000 897424 ?? 48 85C9 75 ?? 48 8D0D ???????? E8 ????????", "soundDrawPatchLoc", startIndex: 3200000);

                findAddr(textSection, header.VirtualAddress, "40 3835 ???????? 0F84 ????0000 48 8D5424 ?? 48 8BCF E8 ????0000 48 8D4C24 ?? E8 ???????? 6644 85BF ????000074 ?? 48 8B05 ???????? 48 85C0 75 ?? 48 8D0D ???????? E8 ???????? 4C 8BC8 4C 8D05 ????????BA ????0000 48 8D0D ????????E8 ???????? 48 8B05 ????????48 8B80 ????????48 8D5424 ?? 48 8B88 ????????48 8B49 ?? E8 ???????? EB ?? 8B8F ????0000 E8 ???????? F3 0F1145 ?? 48 8D4C24 ?? 66 859F ????000074 ?? B2 ?? EB ??", "allTargetingDebugDraw", 3, 3 + 4, startIndex: 3200000); //yes, it's long, take off more than a little and it gets two matches

                findAddr(textSection, header.VirtualAddress, "48 8B 0D ???????? C7 44 24 50 FFFFFFFF", "MapItemManImpl", 3, 7, startIndex: 5700000); //or 48 8B 0D ???????? C7 44 24 50 FF FF FF FF C7 45 A0 FF FF FF FF 48 85 C9 75 2E
                findAddr(textSection, header.VirtualAddress, "8B 02 83 F8 0A", "ItemSpawnCall", justOffset: -0x52, startIndex: 5400000); //this function changed in earlier patches; this AOB is surprisingly more robust than one from the start of the function. //TODO: alternate for old patches?
                //full func, 1.03.x to 1.06: 40 55 56 57 41 54 41 55 41 56 41 57 48 8DAC24 ??FFFFFF  48 81EC ????0000 48 C745 ?? FEFFFFFF 48 899C24 ????0000  48 8B05 ???????? 48 33C4 48 8985 ??000000 44 894C24 ?? 4D 8B?? 4C 894424 ?? 4C 8B?? 33FF 897C24 ?? 8B02 83F8 ?? 0F87 ????0000
                findAddr(textSection, header.VirtualAddress, "40 55 56 57 41 54 41 55 41 56 41 57 48 8D6C24 ?? 48 81EC ????0000 48 C745 ?? FEFFFFFF 48 899C24 ????0000 48 8B05 ???????? 48 33C4 48 8945 ?? 44 894C24 ?? 4D 8B??4C 894424 ?? 4C 8B??33FF 897C24 ?? 8B02 83F8 ?? 0F87 ????0000", "ItemSpawnCall 1.02.x", startIndex: 5400000);

                findAddr(textSection, header.VirtualAddress, "803D ???????? 00 75 ?? 48 8BCB E8 ???????? 48 8BC8 E8 ???????? 84C0 74 ?? 48 833D ???????? 00", "allChrNoDeath", 2, 2 + 4 + 1, startIndex: 4200000);
                findAddr(textSection, header.VirtualAddress, "803D ???????? 00 0F85 ???????? 32C0 48 83C4 20 5B C3", "playerNoDeath", 2, 2 + 4 + 1, startIndex: 4200000); //alternative to setting no-death directly on the player character

                findAddr(textSection, header.VirtualAddress, "48 8B40 68 8078 36 00 0F95C0 40 B7 01 8806 48 8B5C24 30 40 0FB6C7 48 8B7424 38 48 83C4 20 5F C3", "torrentDisabledCheckOne", justOffset: 4 + 4, startIndex: 12900000); //patch from 0F95C0 to 30C090 for torrent everywhere
                //^nothing masked but works on all patches. try 0F95C0 40 B7 01 8806 48 8B5C24 ?? 40 0FB6C7 48 8B7424 ?? 48 83C4 ?? 5F C3 if it breaks but expect multiple matches.
                findAddr(textSection, header.VirtualAddress, "E8 ???????? 48 8B48 ?? 8079 36 00 0F95C0 48 83C4 ?? C3", "torrentDisabledCheckTwo", justOffset: 5 + 4 + 4, startIndex: 7000000); //patch from 0F95C0 to 30C090 for torrent everywhere
                //^+36 is not masked as that's the offset in MSBE and should not change

                findAddr(textSection, header.VirtualAddress, "C783 ????0000 FFFFFFFF 0F280D ???????? 66 0F7F4D ?? F2 0F118B ????0000 66 0F73D9 ?? 66 0F7E8B", "mapIDinPlayerIns", readoffset32: 2, startIndex: 6300000); //immediately follows x,y,z,angle

                //findAddr(textSection, header.VirtualAddress, "4C 8DB0 ????0000 49 8B06 49 8BCE FF10 8BE8 33FF 49 BF FFFFFFFFFFFFFF1F 85C0 0F8E ????????", "worldChrManOffTowardsTorrent", 1 + 2); //fixed at 0xB6F0. this value +0x18 eventually gets to torrent.
                //the 0x18378 offset (which changes with patches) is not found in the game. the following is the closest:
                //findAddr(textSection, header.VirtualAddress, "48 8D83 ??????00 48 8983 ????0000 48 C783 ????0000 FFFFFFFF C783 ????0000 FFFFFFFF 66 89AB ????0000 40 88AB ????0000 0F2805 ????????", "worldChrManSomeOffset", 1 + 2); //fixed at 0x18370.
                findAddr(textSection, header.VirtualAddress, "48 8B8CFE ??????00 48 85C9 74 ?? 4C 8B01 8BD0 41 FF50 ?? 48 8B7C24 ?? 48 8B5C24 ?? 48 83C4 ??", "worldChrManChrSetOffset", 4, startIndex: 5000000);
                findAddr(textSection, header.VirtualAddress, "48 8B81 ????0000 48 C702 FFFFFFFF 48 85C0 74 0A 48 8B80 ????0000 48 8902 48 8BC2", "PGDataOffset", 3, startIndex: 6400000); //patch stable, but just in case
                findAddr(textSection, header.VirtualAddress, "48 8B81 ????0000 48 C702 FFFFFFFF 48 85C0 74 0A 48 8B80 ????0000 48 8902 48 8BC2", "TorrentIDOffset", 3 + 4 + 3 + 4 + 3 + 2 + 3, startIndex: 6400000); //from this ID, eg. 0x1XX00000, we need the XX. prob should sanity check the rest.

                findAddr(textSection, header.VirtualAddress, "48 833D ???????? 00 0F84 ????0000 44 8BE6 85 C0 0F 84 ????0000", "GLOBAL_CSEventFlagMan", 1 + 2, 1 + 2 + 4 + 1, startIndex: 2000000); //singleton, type CS::CSFD4VirtualMemoryFlag

                findAddr(textSection, header.VirtualAddress, "80 b9 ?? ?? 00 00 00 74 08 0f b6 81 ?? ?? 00 00 c3 0f b6 81 ?? ?? 00 00 c3", "CS::PlayerGameData::GetScadutreeBlessing (scadu offset in pgdata)", readoffset32: 20, startIndex: 2000000); //if scan fails, can assume .exe is pre-dlc

                var cave = "";
                for (int i = 0; i < 0xA0; i++) { cave += "90"; }
                findAddr(textSection, header.VirtualAddress, cave, "codeCave_0x60_nops", startIndex: 100000); //this seems fixed at 0x2543F
                //findAddr(textSection, header.VirtualAddress, "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00", "codeCave_48_zeroes"); //mostly pointless, just open x64dbg and go to end
            };

            Action doDS3Scan = () =>
            {
                findAddr(textSection, header.VirtualAddress, "48 8B15 ???????? C74424 18 ???? 0000 C74424 10 00000000 8B4A ?? FFC1 894C24 ?? 79 ??", "NS_SPRJ::GameDataMan", 3, 3 + 4);
                findAddr(textSection, header.VirtualAddress, "48 8B0D ???????? 48 85C9 75 ?? 4C 8D0D ???????? 4C 8D05 ???????? 48 8D0D ???????? BA ?? 000000 E8 ???????? 48 8B0D ???????? 8B53 08 48 83C4 20 5B E9 ????????", "NS_SPRJ::WorldChrManImp", 3, 3 + 4);
                findAddr(textSection, header.VirtualAddress, "48 8B05 ???????? 0F2880 500A0000 48 8BC1 66 0F7F01 C3", "NS_SPRJ::GameMan", 3, 3 + 4);
                findAddr(textSection, header.VirtualAddress, "48 8B05 ???????? 48 6358 20 48 85C9 75 26 4C 8D0D ???????? 4C 8D05 ???????? BA ??000000 48 8D0D ???????? E8 ???????? 48 8B0D ????????", "NS_SPRJ::FieldArea", 3, 3 + 4);
                findAddr(textSection, header.VirtualAddress, "48 8B05 ???????? 4C 8BE1 4C 8BB8 ???? 0000 49 8BCF E8 ???????? 83CB FF", "NS_SPRJ::FrpgNetManImp / BaseEOff", 3, 3 + 4);
                findAddr(textSection, header.VirtualAddress, "48 8B0D ???????? 894424 28 48 85C9 75 ?? 4C 8D0D ???????? 4C 8D05 ???????? 48 8D0D ???????? BA ?? 000000 E8 ????????", "BaseFOff", 3, 3 + 4);
                findAddr(textSection, header.VirtualAddress, "48 833D ???????? 00 75 1F 4C 8D0D ???????? 4C 8D05 ???????? 48 8D0D ???????? BA ?? 000000 E8 ???????? 803D ???????? 00 0F84 ???? 0000", "NS_SPRJ::WorldChrManDbgImp", 3, 3 + 4 + 1);
                findAddr(textSection, header.VirtualAddress, "75 1F 4C8D0D ???????? 4C8D05 ???????? 488D0D ???????? BA B1000000 E8 ???????? C605 ???????? 01", "debug flags / WorldChrManDbg (alternate)", 2 + 7 + 7 + 7 + 5 + 5 + 2, 2 + 7 + 7 + 7 + 5 + 5 + 2 + 5);
                findAddr(textSection, header.VirtualAddress, "48 8B0D ???????? 48 85C9 75 26 4C 8D0D ???????? 4C 8D05 ???????? BA ?? 000000 48 8D0D ???????? E8 ???????? 48 8B0D ???????? 45 33C0 41 8D50 51 E8 ???????? ", "NS_SPRJ::SoloParamRepositoryImp", 3, 3 + 4);
                findAddr(textSection, header.VirtualAddress, "48 8B0D ???????? 8B18 48 85C9 75 26 4C 8D0D ???????? 4C 8D05 ???????? 48 8D0D ???????? BA ?? 000000 E8 ???????? 48 8B0D ???????? 45 33C9 41 B0 01 8BD3 E8 ????????", "GameFlagDataOff?", 3, 3 + 4);
                findAddr(textSection, header.VirtualAddress, "48 8B0D ???????? E8 ???????? 48 8BD8 48 85C0 0F84 ???? 0000 C786 ???? 0000 02000000 0F2835 ???????? 48 8BCE E8 ????????", "NS_SPRJ::LockTgtManImp", 3, 3 + 4);
                findAddr(textSection, header.VirtualAddress, "C605 ???????? 01 48 8B4C24 40 48 33CC E8 ???????? 48 8B5C24 70 48 8BB424 80000000 48 83C4 60 5F C3", "debug_flagsOff", 2, 2 + 4 + 1);
                findAddr(textSection, header.VirtualAddress, "E8 ???????? 488B05 ???????? 488B40 10 B9 F0000000 C680 72050000 01 C605 ???????? 01 C605 ???????? 01", "GROUP_MASK", 5 + 7 + 4 + 5 + 7 + 2, 5 + 7 + 4 + 5 + 7 + 2 + 5);
                findAddr(textSection, header.VirtualAddress, "48 8B0D ???????? 0F57C0 0F2F81 ???? 0000 0F93C0 C3", "NS_SPRJ::MenuMan", 3, 3 + 4);
                findAddr(textSection, header.VirtualAddress, "E8 ???????? EB 03 488BC6 488905 ???????? 48833D ???????? 00 75 35 4C8B05 ???????? 4C8945 D7 BA 08000000 8D4A 30 E8 ???????? ", "hitbox base WIP take first", 5 + 2 + 3 + 7 + 3, 5 + 2 + 3 + 7 + 3 + 5);
                findAddr(textSection, header.VirtualAddress, "48 8B0D ???????? 48 85C9 74 0D 33C0 48 3981 ?? 000000 0F95C0 C3 32C0 C3", "AppMenu::NewMenuSystem", 3, 3 + 4);
                findAddr(textSection, header.VirtualAddress, "48 8B0D ???????? 8B1B 8B38 48 85C9 75 26 4C 8D0D ???????? 4C 8D05 ???????? 48 8D0D ???????? BA ?? 000000 E8 ???????? 48 8B0D ???????? E8 ????????", "NS_SPRJ::SprjWorldAiManagerImp", 3, 3 + 4);
                findAddr(textSection, header.VirtualAddress, "4053 56 4156 4883EC 40 440FB635 ???????? 4C896424 70 4C896C24 38 4C897C24 30 440FB63D ???????? ", "meshes off", 2 + 1 + 2 + 4 + 8 + 5 + 5 + 5 + 4, 2 + 1 + 2 + 4 + 8 + 5 + 5 + 5 + 4 + 4);
                findAddr(textSection, header.VirtualAddress, "41 FF50 10 48 897C24 40 48 8B0D ???????? 48 85C9 75 4E 380D ???????? 74 17 4C 8D05 ???????? 8D51 41 48 8D0D ???????? E8 ????????", "usrInputMgrImplOff", 4 + 5 + 3, 4 + 5 + 3 + 4); //or do rtti search for DLUID::DLUserInputManagerImpl<DLKR::DLMultiThreadingPolicy>.
                findAddr(textSection, header.VirtualAddress, "E8 ???????? 48 8905 ???????? 48 8B05 ???????? E8 ???????? 4C 8B08 41 B8 01000000 48 8D15 ???????? 48 8BC8 41 FF51 08", "usrInputMgrImplOff (alternate aob)", 1 + 4 + 1 + 2, 1 + 4 + 1 + 2 + 4); //just in case
                findAddr(textSection, header.VirtualAddress, "80B9 ????0000 00 75 ?? 48 8B49 ?? 4C 8D05 ???????? BA ??000000 48 8B01 C74424 ?? ?? 000000 FF50 ??", "steam input stutter disable", 2); //always 24b but just in case. the actual stutter occurs from the virtual function call further down.

                findAddr(textSection, header.VirtualAddress, "48 8B80 ????0000 48 8B08 48 8B51 ?? 48 8BC2 48 C1E8 ?? A8 01 75 09 48 C1EA ?? F6C2 01 74 07 B0 01 48 83C4 ??", "targetHookLoc"); //works in all except 1.04. longer than it needs to be.
                //no AOB for code cave (find manually at end of exe)
                findAddr(textSection, header.VirtualAddress, "E8 ???????? 0F287424 50 0F287C24 40 44 0F284424 30 48 83C4 60 5B", "fontDrawFirstPatchLoc"); //i honestly don't know what this does, other than preventing a crash.

                

                //note: ~8% of the first text section is obfuscated in the exe. take a live dump of it and patch the exe with it to get a 'live' exe for the following AOBs to work.

                findAddr(textSection, header.VirtualAddress, "803D ???????? 00 75 05 40 32F6 EB 03 40 B6 01 A8 04 75 0D 803D ???????? 00", "Enemy Targeting Draw 1 (live exe)", 2, 2 + 4 + 1); //draw 2 is always this addr +1. also needs 'all debug drawing' enabled.
                findAddr(textSection, header.VirtualAddress, "48 8B41 08 0FBE80 81B60000", "DbgGetForceActIdx (live exe)", justOffset: 4 + 3); //patch 81 to 82 to repeat enemy actions
                findAddr(textSection, header.VirtualAddress, "8B83 ??000000 FFC8 83F8 01 0F87 ???????? 48 83BB ??000000 000F84 ???????? 83BB ??000000 00 0F85 ????????", "freeCamPlayerControlPatchLoc (live exe)"); //works in elden ring and sekiro too?!

                findAddr(textSection, header.VirtualAddress, "40 53 55 56 41 54 41 56 48 83EC 20 49 8BE8 4C 8B41 ?? 4D 8BF1 48 8BF2 48 8BD9 4C 3BC2 0F82 ????????", "mod engine hook WIP take first");
                findAddr(textSection, header.VirtualAddress, "74 68 48 8b cf 48 89 5c 24 30 E8", "loose params 1");
                findAddr(textSection, header.VirtualAddress, "0F 85 C5 00 00 00 48 8D 4C 24 28 E8", "loose params 2");
                findAddr(textSection, header.VirtualAddress, "E8 ?? ?? ?? ?? 90 E9 ?? ?? ?? ?? 53 E9 ?? ?? ?? ?? E2 0C FFF1", "loose params 3 (offline exe)"); //only works on the original exe; last part is obfuscated
                findAddr(textSection, header.VirtualAddress, "E9 ?? ?? ?? ?? 90 E8 ?? ?? ?? ?? 90 E9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 90 E9 ?? ?? ?? ??", "loose params 3 WIP", justOffset: 0x11, singleMatch: false); //will get multiple results. try second result. check called func and look for rcx+60 a few instructions down.

                findAddr(textSection, header.VirtualAddress, "2943 08 837B 08 00 8983 ????0000 7F ?? 80BB ????0000 00 75 ??", "NPC part damage hook");

                findAddr(textSection, header.VirtualAddress, "C783 ????0000 0000803F F3 0F108B ????0000", "Global Speed", justOffset: 2 + 4); //1.0f hardcoded in the asm

                findAddr(textSection, header.VirtualAddress, "E8 ???????? 0FB6D8 66 0F7F7D ?? 66 0F7F75 ?? 44 8BCB 48 8D45", "debugMenuFirstPatchLoc"); //debug menu patch replaces this call with a set al, 1 and nops.

                findAddr(textSection, header.VirtualAddress, "E8 ???????? 90 4D 8BC7 49 8BD4 48 8BC8 E8 ???????? C74424 50 01000000", "noLogoPatchLoc");
            };

            Action doSekiroScan = () =>
            {
                findAddr(textSection, header.VirtualAddress, "48 8B 05 ?? ?? ?? ?? F3 0F 10 88 ?? ?? ?? ?? F3 0F", "csFlipperOff", 3, 7);
            };

            Action doAllGameScans = () =>
            {
                findAddr(textSection, header.VirtualAddress, "48 ?? ?? ?? 80 b9 ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 ?? 8b ?? ?? 44 24 20 01", "alt stutter fix, patch in 4885C990909090", justOffset: 4, singleMatch: false);
                //if there's multiple matches, patch them all. patch seems complicated but it just sets the zero flag with test rcx,rcx. easier than patching the JNZ as it's in different places in different games.
            };

            if (!string.IsNullOrEmpty(testAob))
            {
                findAddr(textSection, header.VirtualAddress, testAob, "Test AOB (section 1)", singleMatch: false);
                findAddr(textSection2, header2.VirtualAddress, testAob, "Test AOB (section 2)", singleMatch: false);
            }
            else
            {
                if (exe.ToLower().Contains("elden")) { doERScan(); }
                if (exe.ToLower().Contains("darksoulsiii")) { doDS3Scan(); }
                if (exe.ToLower().Contains("sekiro")) { doSekiroScan(); }
                //if (exe.ToLower().Contains("armor")) { doDS3Scan(); doSekiroScan(); doERScan(); } //try all for the moment
                doAllGameScans();
            }
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

        public int FindBytes(byte[] buf, byte[] find, byte[] wild, int startIndex = 0, int lastIndex = -1)
        {
            if (buf == null || find == null || buf.Length == 0 || find.Length == 0 || find.Length > buf.Length) return -1;
            if (lastIndex < 1) { lastIndex = buf.Length - find.Length; }
            for (int i = startIndex; i < lastIndex + 1; i++)
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

        public bool outputConsole = true;

        const bool DISABLE_START_INDEX = false;
        const bool DISABLE_SINGLE_MATCH = false;

        public int findAddr(byte[] buf, int blockVirtualAddr, string find, string desc, int readoffset32 = -1000, int nextInstOffset = -1000, int justOffset = -1000, int startIndex = 0, bool singleMatch = true)
        {//TODO: for single match and non-zero start index, try zero start index if no match is found?
            int count = 0;

            byte[] fb = hs2b(find);
            byte[] fwb = hs2w(find);

            int index = DISABLE_START_INDEX ? 0 : startIndex;
            if (DISABLE_SINGLE_MATCH) { singleMatch = false; }

            int result = -1;

            do
            {
                index = FindBytes(buf, fb, fwb, index);
                if (index != -1)
                {
                    count++;
                    int rva = index + blockVirtualAddr;
                    result = rva;
                    string output = desc + " found at index " + index + " offset hex " + rva.ToString("X2");

                    if (readoffset32 > -1000)
                    {
                        int index32 = index + readoffset32;
                        var val = BitConverter.ToInt32(buf, index32);
                        result = val;
                        output += " raw val " + val.ToString("X2");
                        if (nextInstOffset > -1000)
                        {
                            int next = blockVirtualAddr + index + nextInstOffset + val;
                            result = next;
                            output += " final offset " + next.ToString("X2");
                        }
                    }

                    if (justOffset > -1000)
                    {
                        result = rva + justOffset;
                        output += " with offset " + (rva + justOffset).ToString("X2");
                    }

                    if (outputConsole) { Console.WriteLine(output); }
                    index += fb.Length; //keep searching in case there's multiple.
                }
            }
            while (index != -1 && !singleMatch);
            if (0 == count && outputConsole) { Console.WriteLine("Nothing found for " + desc); }
            return result;
        }
    }
}
