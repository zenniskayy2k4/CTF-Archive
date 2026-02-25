namespace System.Transactions
{
	/// <summary>Specifies whether transaction flow across thread continuations is enabled for <see cref="T:System.Transactions.TransactionScope" />.</summary>
	public enum TransactionScopeAsyncFlowOption
	{
		/// <summary>Specifies that transaction flow across thread continuations is suppressed.</summary>
		Suppress = 0,
		/// <summary>Specifies that transaction flow across thread continuations is enabled.</summary>
		Enabled = 1
	}
}
