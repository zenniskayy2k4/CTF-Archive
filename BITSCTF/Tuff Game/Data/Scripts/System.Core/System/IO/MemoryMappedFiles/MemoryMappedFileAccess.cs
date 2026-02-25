namespace System.IO.MemoryMappedFiles
{
	/// <summary>Specifies access capabilities and restrictions for a memory-mapped file or view. </summary>
	[Serializable]
	public enum MemoryMappedFileAccess
	{
		/// <summary>Read and write access to the file.</summary>
		ReadWrite = 0,
		/// <summary>Read-only access to the file.</summary>
		Read = 1,
		/// <summary>Write-only access to file.</summary>
		Write = 2,
		/// <summary>Read and write access to the file, with the restriction that any write operations will not be seen by other processes. </summary>
		CopyOnWrite = 3,
		/// <summary>Read access to the file that can store and run executable code.</summary>
		ReadExecute = 4,
		/// <summary>Read and write access to the file that can can store and run executable code.</summary>
		ReadWriteExecute = 5
	}
}
