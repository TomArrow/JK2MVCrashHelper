using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;

namespace JK2MVCrashHelper
{

    public partial class MainWindow : Window
    {
        static Regex stackTraceRegex = new Regex(@"#(?<num>\d+)\s+(?<stuff>[^\n\r]*?)\[(?<addr>0x[0-9a-f]+)\]",RegexOptions.Compiled|RegexOptions.IgnoreCase|RegexOptions.Singleline);
        static Regex gdbBtRegex = new Regex(@"#(?<num>\d+)\s+(?<addr>0x[0-9a-f]+)\s+in\s+(?<func>[^\s]+)",RegexOptions.Compiled|RegexOptions.IgnoreCase|RegexOptions.Singleline);
        static Regex gdbProcMapRegex = new Regex(@"[\^\n\r]\s+(?<addr>0x[0-9a-f]+)\s+(?<addr2>0x[0-9a-f]+)\s+(?<addr3>0x[0-9a-f]+)\s+(?<addr4>0x[0-9a-f]+)\s+(?<perms>[^\s]+)[\t ]*(?<file>[^\$\r\n]*)",RegexOptions.Compiled|RegexOptions.IgnoreCase|RegexOptions.Singleline);

        public MainWindow()
        {
            InitializeComponent();
        }

        struct stackTraceEntry {
            public Int64 number;
            public UInt64 address;
            public string stuff;
        }
        struct backTraceEntry {
            public Int64 number;
            public UInt64 address;
            public string functionName;
        }
        struct procMapEntry {
            public UInt64 start;
            public UInt64 end;
            public UInt64 len;
            public UInt64 offset;
            public string perms;
            public string file;
        }


        private void Button_Click(object sender, RoutedEventArgs e)
        {
            string stackTrace = stackTraceTxt.Text;
            string gdbBt = gdbBtTxt.Text;
            string gdbProcMap = gdbProcMapTxt.Text;
            MatchCollection stackTraceFrames = stackTraceRegex.Matches(stackTrace);
            MatchCollection gdbBtFrames = gdbBtRegex.Matches(gdbBt);
            MatchCollection gdbProcMapEntries = gdbProcMapRegex.Matches(gdbProcMap);

            if(stackTraceFrames is null || stackTraceFrames.Count == 0)
            {
                MessageBox.Show("Unable to parse crash log stack trace. Check if it is the correct format, or fix the program to understand the format.");
                return;
            }
            if(gdbBtFrames is null || gdbBtFrames.Count == 0)
            {
                MessageBox.Show("Unable to parse current process gdb backtrace. Check if it is the correct format, or fix the program to understand the format.");
                return;
            }
            if(gdbProcMapEntries is null || gdbProcMapEntries.Count == 0)
            {
                MessageBox.Show("Unable to parse current process gdb process map. Check if it is the correct format, or fix the program to understand the format.");
                return;
            }

            List<stackTraceEntry> stackEntries = new List<stackTraceEntry>();
            stackTraceEntry? stackTraceLikelyvmMain = null;
            bool foundNormal = false;
            foreach(Match match in stackTraceFrames)
            {
                stackTraceEntry newEntry;
                newEntry.number = Int64.Parse(match.Groups["num"].Value);
                newEntry.address = Convert.ToUInt64(match.Groups["addr"].Value,16);
                newEntry.stuff = match.Groups["stuff"].Value;
                if(!foundNormal && (string.IsNullOrWhiteSpace(newEntry.stuff) || newEntry.stuff.Contains("game",StringComparison.InvariantCultureIgnoreCase)))
                {
                    stackTraceLikelyvmMain = newEntry;
                }
                else
                {
                    foundNormal = true;
                    break;
                }
                stackEntries.Add(newEntry);
            }

            if (!stackTraceLikelyvmMain.HasValue)
            {
                MessageBox.Show("Did not find likely dllmain in crash log stacktrace.");
                return;
            }

            List<backTraceEntry> backTraceEntries = new List<backTraceEntry>();
            backTraceEntry? vmMainEntry = null;
            foreach(Match match in gdbBtFrames)
            {
                backTraceEntry newEntry;
                newEntry.number = Int64.Parse(match.Groups["num"].Value);
                newEntry.address = Convert.ToUInt64(match.Groups["addr"].Value,16);
                newEntry.functionName = match.Groups["func"].Value;
                if(newEntry.functionName == "vmMain")
                {
                    vmMainEntry = newEntry;
                }
                backTraceEntries.Add(newEntry);
            }

            if (!vmMainEntry.HasValue)
            {
                MessageBox.Show("Did not find vmMain in current process GDB backtrace.");
                return;
            }

            List<procMapEntry> procMapEntries = new List<procMapEntry>();
            procMapEntry? relevantProcMap = null;
            foreach(Match match in gdbProcMapEntries)
            {
                procMapEntry newEntry;
                newEntry.start = Convert.ToUInt64(match.Groups["addr"].Value,16);
                newEntry.end = Convert.ToUInt64(match.Groups["addr2"].Value,16);
                newEntry.len = Convert.ToUInt64(match.Groups["addr3"].Value,16);
                newEntry.offset = Convert.ToUInt64(match.Groups["addr4"].Value,16);
                newEntry.file = match.Groups["file"].Value;
                newEntry.perms = match.Groups["perms"].Value;

                if(newEntry.start <= vmMainEntry.Value.address && newEntry.end >= vmMainEntry.Value.address)
                {
                    relevantProcMap = newEntry;
                }

                procMapEntries.Add(newEntry);
            }
                        
            if (!relevantProcMap.HasValue)
            {
                MessageBox.Show("Did not find relevant entry in current process GDB process mappings.");
                return;
            }

            procMapEntry lowestProcMap = relevantProcMap.Value;
            foreach(procMapEntry entry in procMapEntries)
            {
                if(entry.start < lowestProcMap.start && entry.file.Equals(lowestProcMap.file))
                {
                    lowestProcMap = entry;
                }
            }


            string modulePath = Path.GetFileName(relevantProcMap.Value.file);
            UInt64 vmMainOffset = vmMainEntry.Value.address - lowestProcMap.start - 1;// + lowestProcMap.offset;
            StringBuilder sb = new StringBuilder();
            foreach (stackTraceEntry stackEntry in stackEntries)
            {
                UInt64 fixedOffset = stackEntry.address - stackTraceLikelyvmMain.Value.address + vmMainOffset;
                string hexOffset = fixedOffset.ToString("X");
                sb.AppendLine($"addr2line -Cfpe {modulePath} 0x{hexOffset}");
            }
            resultTxt.Text = sb.ToString();

            Console.Write(sb.ToString());
        }
    }
}
