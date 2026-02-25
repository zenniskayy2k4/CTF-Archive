namespace System.Reflection
{
	/// <summary>Provides information about the type of code contained in an assembly.</summary>
	public enum AssemblyContentType
	{
		/// <summary>The assembly contains .NET Framework code.</summary>
		Default = 0,
		/// <summary>The assembly contains Windows Runtime code.</summary>
		WindowsRuntime = 1
	}
}
