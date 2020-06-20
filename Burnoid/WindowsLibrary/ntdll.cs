using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Burnoid.WindowsLibrary
{
    public static class ntdll
    {
        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern IntPtr RtlAdjustPrivilege(int Privelege, bool bEnablePrivelege, bool IsThreadPrivilege, out bool PreviousValue);
    }
    public enum SePrivelege
    {
        SeCreateTokenPrivilege = 1,

        SeAssignPrimaryTokenPrivilege = 2,

        SeLockMemoryPrivilege = 3,

        SeIncreaseQuotaPrivilege = 4,

        SeUnsolicitedInputPrivilege = 5,

        SeMachineAccountPrivilege = 6,

        SeTcbPrivilege = 7,

        SeSecurityPrivilege = 8,

        SeTakeOwnershipPrivilege = 9,

        SeLoadDriverPrivilege = 10,

        SeSystemProfilePrivilege = 11,

        SeSystemtimePrivilege = 12,

        SeProfileSingleProcessPrivilege = 13,

        SeIncreaseBasePriorityPrivilege = 14,

        SeCreatePagefilePrivilege = 15,

        SeCreatePermanentPrivilege = 16,

        SeBackupPrivilege = 17,

        SeRestorePrivilege = 18,

        SeShutdownPrivilege = 19,

        SeDebugPrivilege = 20,

        SeAuditPrivilege = 21,

        SeSystemEnvironmentPrivilege = 22,

        SeChangeNotifyPrivilege = 23,

        SeRemoteShutdownPrivilege = 24,

        SeUndockPrivilege = 25,

        SeSyncAgentPrivilege = 26,

        SeEnableDelegationPrivilege = 27,

        SeManageVolumePrivilege = 28,

        SeImpersonatePrivilege = 29,

        SeCreateGlobalPrivilege = 30,

        SeTrustedCredManAccessPrivilege = 31,

        SeRelabelPrivilege = 32,

        SeIncreaseWorkingSetPrivilege = 33,

        SeTimeZonePrivilege = 34,

        SeCreateSymbolicLinkPrivilege = 35
    }
}
