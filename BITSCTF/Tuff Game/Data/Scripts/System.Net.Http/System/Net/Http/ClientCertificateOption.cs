namespace System.Net.Http
{
	/// <summary>Specifies how client certificates are provided.</summary>
	public enum ClientCertificateOption
	{
		/// <summary>The application manually provides the client certificates to the <see cref="T:System.Net.Http.WebRequestHandler" />. This value is the default.</summary>
		Manual = 0,
		/// <summary>The <see cref="T:System.Net.Http.HttpClientHandler" /> will attempt to provide  all available client certificates  automatically.</summary>
		Automatic = 1
	}
}
