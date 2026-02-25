namespace System.Net.WebSockets
{
	/// <summary>Indicates the message type.</summary>
	public enum WebSocketMessageType
	{
		/// <summary>The message is clear text.</summary>
		Text = 0,
		/// <summary>The message is in binary format.</summary>
		Binary = 1,
		/// <summary>A receive has completed because a close message was received.</summary>
		Close = 2
	}
}
