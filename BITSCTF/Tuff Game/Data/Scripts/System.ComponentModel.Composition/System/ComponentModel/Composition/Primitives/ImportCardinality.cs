namespace System.ComponentModel.Composition.Primitives
{
	/// <summary>Indicates the cardinality of the <see cref="T:System.ComponentModel.Composition.Primitives.Export" /> objects required by an <see cref="T:System.ComponentModel.Composition.Primitives.ImportDefinition" />.</summary>
	public enum ImportCardinality
	{
		/// <summary>Zero or one <see cref="T:System.ComponentModel.Composition.Primitives.Export" /> objects are required by the <see cref="T:System.ComponentModel.Composition.Primitives.ImportDefinition" />.</summary>
		ZeroOrOne = 0,
		/// <summary>Exactly one <see cref="T:System.ComponentModel.Composition.Primitives.Export" /> object is required by the <see cref="T:System.ComponentModel.Composition.Primitives.ImportDefinition" />.</summary>
		ExactlyOne = 1,
		/// <summary>Zero or more <see cref="T:System.ComponentModel.Composition.Primitives.Export" /> objects are required by the <see cref="T:System.ComponentModel.Composition.Primitives.ImportDefinition" />.</summary>
		ZeroOrMore = 2
	}
}
