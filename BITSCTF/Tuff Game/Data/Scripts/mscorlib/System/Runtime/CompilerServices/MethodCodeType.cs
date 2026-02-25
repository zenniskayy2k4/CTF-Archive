using System.Runtime.InteropServices;

namespace System.Runtime.CompilerServices
{
	/// <summary>Defines how a method is implemented.</summary>
	[Serializable]
	[ComVisible(true)]
	public enum MethodCodeType
	{
		/// <summary>Specifies that the method implementation is in Microsoft intermediate language (MSIL).</summary>
		IL = 0,
		/// <summary>Specifies that the method is implemented in native code.</summary>
		Native = 1,
		/// <summary>Specifies that the method implementation is in optimized intermediate language (OPTIL).</summary>
		OPTIL = 2,
		/// <summary>Specifies that the method implementation is provided by the runtime.</summary>
		Runtime = 3
	}
}
