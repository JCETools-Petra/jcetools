using System;
using System.Diagnostics;
using System.Runtime.InteropServices;


namespace HWID___Joshhh.Module
{
    internal class AntiDebug
    {
        [DllImport("kernel32.dll")]
        private static extern bool IsDebuggerPresent();

        [DllImport("kernel32.dll")]
        private static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool isDebuggerPresent);

        public static void CheckForDebuggers()
        {
            if (Debugger.IsAttached || IsDebuggerPresent())
            {
                // Handle the case where a debugger is detected
                Environment.Exit(1);
            }

            bool isDebuggerPresent;
            CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, out isDebuggerPresent);
            if (isDebuggerPresent)
            {
                // Handle the case where a debugger is detected
                Environment.Exit(1);
            }
        }
    }
}
