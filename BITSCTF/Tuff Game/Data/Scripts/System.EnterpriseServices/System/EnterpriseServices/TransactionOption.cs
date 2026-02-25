namespace System.EnterpriseServices
{
	/// <summary>Specifies the automatic transaction type requested by the component.</summary>
	[Serializable]
	public enum TransactionOption
	{
		/// <summary>Ignores any transaction in the current context.</summary>
		Disabled = 0,
		/// <summary>Creates the component in a context with no governing transaction.</summary>
		NotSupported = 1,
		/// <summary>Shares a transaction, if one exists.</summary>
		Supported = 2,
		/// <summary>Shares a transaction, if one exists, and creates a new transaction if necessary.</summary>
		Required = 3,
		/// <summary>Creates the component with a new transaction, regardless of the state of the current context.</summary>
		RequiresNew = 4
	}
}
