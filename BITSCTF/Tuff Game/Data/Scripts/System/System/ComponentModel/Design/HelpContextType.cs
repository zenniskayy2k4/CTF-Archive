namespace System.ComponentModel.Design
{
	/// <summary>Defines identifiers that indicate information about the context in which a request for Help information originated.</summary>
	public enum HelpContextType
	{
		/// <summary>A general context.</summary>
		Ambient = 0,
		/// <summary>A window.</summary>
		Window = 1,
		/// <summary>A selection.</summary>
		Selection = 2,
		/// <summary>A tool window selection.</summary>
		ToolWindowSelection = 3
	}
}
