namespace System.Runtime.InteropServices
{
	/// <summary>Describes the type of a COM member.</summary>
	public enum ComMemberType
	{
		/// <summary>The member is a normal method.</summary>
		Method = 0,
		/// <summary>The member gets properties.</summary>
		PropGet = 1,
		/// <summary>The member sets properties.</summary>
		PropSet = 2
	}
}
