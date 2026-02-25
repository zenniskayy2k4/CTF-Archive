namespace System.Net.WebSockets
{
	/// <summary>Contains the list of possible WebSocket errors.</summary>
	public enum WebSocketError
	{
		/// <summary>Indicates that there was no native error information for the exception.</summary>
		Success = 0,
		/// <summary>Indicates that a WebSocket frame with an unknown opcode was received.</summary>
		InvalidMessageType = 1,
		/// <summary>Indicates a general error.</summary>
		Faulted = 2,
		/// <summary>Indicates that an unknown native error occurred.</summary>
		NativeError = 3,
		/// <summary>Indicates that the incoming request was not a valid websocket request.</summary>
		NotAWebSocket = 4,
		/// <summary>Indicates that the client requested an unsupported version of the WebSocket protocol.</summary>
		UnsupportedVersion = 5,
		/// <summary>Indicates that the client requested an unsupported WebSocket subprotocol.</summary>
		UnsupportedProtocol = 6,
		/// <summary>Indicates an error occurred when parsing the HTTP headers during the opening handshake.</summary>
		HeaderError = 7,
		/// <summary>Indicates that the connection was terminated unexpectedly.</summary>
		ConnectionClosedPrematurely = 8,
		/// <summary>Indicates the WebSocket is an invalid state for the given operation (such as being closed or aborted).</summary>
		InvalidState = 9
	}
}
