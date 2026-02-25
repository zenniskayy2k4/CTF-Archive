namespace System.Data
{
	/// <summary>Specifies the type of SQL query to be used by the <see cref="T:System.Data.OleDb.OleDbRowUpdatedEventArgs" />, <see cref="T:System.Data.OleDb.OleDbRowUpdatingEventArgs" />, <see cref="T:System.Data.SqlClient.SqlRowUpdatedEventArgs" />, or <see cref="T:System.Data.SqlClient.SqlRowUpdatingEventArgs" /> class.</summary>
	public enum StatementType
	{
		/// <summary>An SQL query that is a SELECT statement.</summary>
		Select = 0,
		/// <summary>An SQL query that is an INSERT statement.</summary>
		Insert = 1,
		/// <summary>An SQL query that is an UPDATE statement.</summary>
		Update = 2,
		/// <summary>An SQL query that is a DELETE statement.</summary>
		Delete = 3,
		/// <summary>A SQL query that is a batch statement.</summary>
		Batch = 4
	}
}
