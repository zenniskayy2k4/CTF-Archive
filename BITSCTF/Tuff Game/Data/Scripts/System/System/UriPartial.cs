namespace System
{
	/// <summary>Defines the parts of a URI for the <see cref="M:System.Uri.GetLeftPart(System.UriPartial)" /> method.</summary>
	public enum UriPartial
	{
		/// <summary>The scheme segment of the URI.</summary>
		Scheme = 0,
		/// <summary>The scheme and authority segments of the URI.</summary>
		Authority = 1,
		/// <summary>The scheme, authority, and path segments of the URI.</summary>
		Path = 2,
		/// <summary>The scheme, authority, path, and query segments of the URI.</summary>
		Query = 3
	}
}
