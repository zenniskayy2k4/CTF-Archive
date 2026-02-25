namespace System.Net.Sockets
{
	/// <summary>The type of asynchronous socket operation most recently performed with this context object.</summary>
	public enum SocketAsyncOperation
	{
		/// <summary>None of the socket operations.</summary>
		None = 0,
		/// <summary>A socket Accept operation.</summary>
		Accept = 1,
		/// <summary>A socket Connect operation.</summary>
		Connect = 2,
		/// <summary>A socket Disconnect operation.</summary>
		Disconnect = 3,
		/// <summary>A socket Receive operation.</summary>
		Receive = 4,
		/// <summary>A socket ReceiveFrom operation.</summary>
		ReceiveFrom = 5,
		/// <summary>A socket ReceiveMessageFrom operation.</summary>
		ReceiveMessageFrom = 6,
		/// <summary>A socket Send operation.</summary>
		Send = 7,
		/// <summary>A socket SendPackets operation.</summary>
		SendPackets = 8,
		/// <summary>A socket SendTo operation.</summary>
		SendTo = 9
	}
}
