namespace System.ComponentModel
{
	/// <summary>Identifies the type of data operation performed by a method, as specified by the <see cref="T:System.ComponentModel.DataObjectMethodAttribute" /> applied to the method.</summary>
	public enum DataObjectMethodType
	{
		/// <summary>Indicates that a method is used for a data operation that fills a <see cref="T:System.Data.DataSet" /> object.</summary>
		Fill = 0,
		/// <summary>Indicates that a method is used for a data operation that retrieves data.</summary>
		Select = 1,
		/// <summary>Indicates that a method is used for a data operation that updates data.</summary>
		Update = 2,
		/// <summary>Indicates that a method is used for a data operation that inserts data.</summary>
		Insert = 3,
		/// <summary>Indicates that a method is used for a data operation that deletes data.</summary>
		Delete = 4
	}
}
