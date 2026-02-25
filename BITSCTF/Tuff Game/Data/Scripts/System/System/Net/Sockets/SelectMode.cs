namespace System.Net.Sockets
{
	/// <summary>Defines the polling modes for the <see cref="M:System.Net.Sockets.Socket.Poll(System.Int32,System.Net.Sockets.SelectMode)" /> method.</summary>
	public enum SelectMode
	{
		/// <summary>Read status mode.</summary>
		SelectRead = 0,
		/// <summary>Write status mode.</summary>
		SelectWrite = 1,
		/// <summary>Error status mode.</summary>
		SelectError = 2
	}
}
