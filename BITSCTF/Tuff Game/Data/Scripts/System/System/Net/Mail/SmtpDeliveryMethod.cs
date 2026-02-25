namespace System.Net.Mail
{
	/// <summary>Specifies how email messages are delivered.</summary>
	public enum SmtpDeliveryMethod
	{
		/// <summary>Email is sent through the network to an SMTP server.</summary>
		Network = 0,
		/// <summary>Email is copied to the directory specified by the <see cref="P:System.Net.Mail.SmtpClient.PickupDirectoryLocation" /> property for delivery by an external application.</summary>
		SpecifiedPickupDirectory = 1,
		/// <summary>Email is copied to the pickup directory used by a local Internet Information Services (IIS) for delivery.</summary>
		PickupDirectoryFromIis = 2
	}
}
