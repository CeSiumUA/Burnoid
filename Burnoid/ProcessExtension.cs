using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace Burnoid
{
    public static class ProcessExtension
    {
        public static IEnumerable<ProcessModule> GetModules(this Process process)
        {
            return GetProcessModules(process.Modules);
        }
        private static IEnumerable<ProcessModule> GetProcessModules(ProcessModuleCollection processModuleCollection)
        {
            List<ProcessModule> processModules = new List<ProcessModule>();
            foreach (ProcessModule processModule in processModuleCollection)
            {
                processModules.Add(processModule);
            }
            return processModules;
        }
        public static ProcessModule GetProcessModule(this Process process, string ModuleName)
        {
            return GetProcessModuleInternal(process.Modules, ModuleName);
        }
        public static ProcessModule GetProcessModule(this ProcessModuleCollection processModuleCollection, string ModuleName)
        {
            return GetProcessModule(processModuleCollection, ModuleName);
        }

        private static ProcessModule GetProcessModuleInternal(ProcessModuleCollection processModuleCollection, string ModuleName)
        {
            return GetProcessModules(processModuleCollection).Where(a => a.ModuleName.Contains(ModuleName)).FirstOrDefault();
        }

        public static List<ProcessModuleHEX> GetFormattedProcessModules(this IEnumerable<ProcessModule> processModules)
        {
            return new List<ProcessModuleHEX>(processModules.Select(x => new ProcessModuleHEX()
            {
                ModuleName = x.ModuleName,
                FileName = x.FileName,
                BaseAddress = string.Format("0x{0}", x.BaseAddress.ToString("X16")),
                ModuleMemorySize = x.ModuleMemorySize.ToString(),
                EntryPointAddress = string.Format("0x{0}", x.EntryPointAddress.ToString("X16"))
            }));
        }

    }

    public class ProcessModuleHEX
    {
        public string ModuleName;
        public string FileName;
        public string BaseAddress;
        public string ModuleMemorySize;
        public string EntryPointAddress;
    }
}
