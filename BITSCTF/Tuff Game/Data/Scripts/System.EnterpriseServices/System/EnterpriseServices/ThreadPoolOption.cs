using System.Runtime.InteropServices;

namespace System.EnterpriseServices
{
	/// <summary>Indicates the thread pool in which the work, submitted by <see cref="T:System.EnterpriseServices.Activity" />, runs.</summary>
	[Serializable]
	[ComVisible(false)]
	public enum ThreadPoolOption
	{
		/// <summary>No thread pool is used. If this value is used to configure a <see cref="T:System.EnterpriseServices.ServiceConfig" /> that is passed to an <see cref="T:System.EnterpriseServices.Activity" />, an exception is thrown.</summary>
		None = 0,
		/// <summary>The same type of thread pool apartment as the caller's thread apartment is used.</summary>
		Inherit = 1,
		/// <summary>A single-threaded apartment (STA) is used.</summary>
		STA = 2,
		/// <summary>A multithreaded apartment (MTA) is used.</summary>
		MTA = 3
	}
}
