namespace System.Transactions
{
	/// <summary>Provides additional options for creating a transaction scope.</summary>
	public enum TransactionScopeOption
	{
		/// <summary>A transaction is required by the scope. It uses an ambient transaction if one already exists. Otherwise, it creates a new transaction before entering the scope. This is the default value.</summary>
		Required = 0,
		/// <summary>A new transaction is always created for the scope.</summary>
		RequiresNew = 1,
		/// <summary>The ambient transaction context is suppressed when creating the scope. All operations within the scope are done without an ambient transaction context.</summary>
		Suppress = 2
	}
}
