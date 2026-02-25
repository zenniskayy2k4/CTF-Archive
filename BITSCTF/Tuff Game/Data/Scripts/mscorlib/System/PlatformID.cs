using System.Runtime.InteropServices;

namespace System
{
	/// <summary>Identifies the operating system, or platform, supported by an assembly.</summary>
	[Serializable]
	[ComVisible(true)]
	public enum PlatformID
	{
		/// <summary>The operating system is Win32s. This value is no longer in use.</summary>
		Win32S = 0,
		/// <summary>The operating system is Windows 95 or Windows 98. This value is no longer in use.</summary>
		Win32Windows = 1,
		/// <summary>The operating system is Windows NT or later.</summary>
		Win32NT = 2,
		/// <summary>The operating system is Windows CE. This value is no longer in use.</summary>
		WinCE = 3,
		/// <summary>The operating system is Unix.</summary>
		Unix = 4,
		/// <summary>The development platform is Xbox 360. This value is no longer in use.</summary>
		Xbox = 5,
		/// <summary>The operating system is Macintosh. This value was returned by Silverlight. On .NET Core, its replacement is Unix.</summary>
		MacOSX = 6
	}
}
