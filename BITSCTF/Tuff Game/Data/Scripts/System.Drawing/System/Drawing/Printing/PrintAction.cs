namespace System.Drawing.Printing
{
	/// <summary>Specifies the type of print operation occurring.</summary>
	public enum PrintAction
	{
		/// <summary>The print operation is printing to a file.</summary>
		PrintToFile = 0,
		/// <summary>The print operation is a print preview.</summary>
		PrintToPreview = 1,
		/// <summary>The print operation is printing to a printer.</summary>
		PrintToPrinter = 2
	}
}
