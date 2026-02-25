namespace System.Transactions
{
	/// <summary>Describes the current status of a distributed transaction.</summary>
	public enum TransactionStatus
	{
		/// <summary>The status of the transaction is unknown, because some participants must still be polled.</summary>
		Active = 0,
		/// <summary>The transaction has been committed.</summary>
		Committed = 1,
		/// <summary>The transaction has been rolled back.</summary>
		Aborted = 2,
		/// <summary>The status of the transaction is unknown.</summary>
		InDoubt = 3
	}
}
