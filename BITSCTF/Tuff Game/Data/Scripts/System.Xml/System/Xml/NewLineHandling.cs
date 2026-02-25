namespace System.Xml
{
	/// <summary>Specifies how to handle line breaks.</summary>
	public enum NewLineHandling
	{
		/// <summary>New line characters are replaced to match the character specified in the <see cref="P:System.Xml.XmlWriterSettings.NewLineChars" />  property.</summary>
		Replace = 0,
		/// <summary>New line characters are entitized. This setting preserves all characters when the output is read by a normalizing <see cref="T:System.Xml.XmlReader" />.</summary>
		Entitize = 1,
		/// <summary>The new line characters are unchanged. The output is the same as the input.</summary>
		None = 2
	}
}
