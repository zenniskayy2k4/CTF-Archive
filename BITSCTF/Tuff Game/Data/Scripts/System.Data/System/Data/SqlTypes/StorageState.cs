namespace System.Data.SqlTypes
{
	/// <summary>The <see cref="T:System.Data.SqlTypes.StorageState" /> enumeration is not intended for use as a stand-alone component, but as an enumeration from which other classes derive standard functionality.</summary>
	public enum StorageState
	{
		/// <summary>Buffer size.</summary>
		Buffer = 0,
		/// <summary>Stream.</summary>
		Stream = 1,
		/// <summary>Unmanaged buffer.</summary>
		UnmanagedBuffer = 2
	}
}
