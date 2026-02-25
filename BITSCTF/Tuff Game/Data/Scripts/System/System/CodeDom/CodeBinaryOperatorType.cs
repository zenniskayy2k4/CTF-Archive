namespace System.CodeDom
{
	/// <summary>Defines identifiers for supported binary operators.</summary>
	public enum CodeBinaryOperatorType
	{
		/// <summary>Addition operator.</summary>
		Add = 0,
		/// <summary>Subtraction operator.</summary>
		Subtract = 1,
		/// <summary>Multiplication operator.</summary>
		Multiply = 2,
		/// <summary>Division operator.</summary>
		Divide = 3,
		/// <summary>Modulus operator.</summary>
		Modulus = 4,
		/// <summary>Assignment operator.</summary>
		Assign = 5,
		/// <summary>Identity not equal operator.</summary>
		IdentityInequality = 6,
		/// <summary>Identity equal operator.</summary>
		IdentityEquality = 7,
		/// <summary>Value equal operator.</summary>
		ValueEquality = 8,
		/// <summary>Bitwise or operator.</summary>
		BitwiseOr = 9,
		/// <summary>Bitwise and operator.</summary>
		BitwiseAnd = 10,
		/// <summary>Boolean or operator. This represents a short circuiting operator. A short circuiting operator will evaluate only as many expressions as necessary before returning a correct value.</summary>
		BooleanOr = 11,
		/// <summary>Boolean and operator. This represents a short circuiting operator. A short circuiting operator will evaluate only as many expressions as necessary before returning a correct value.</summary>
		BooleanAnd = 12,
		/// <summary>Less than operator.</summary>
		LessThan = 13,
		/// <summary>Less than or equal operator.</summary>
		LessThanOrEqual = 14,
		/// <summary>Greater than operator.</summary>
		GreaterThan = 15,
		/// <summary>Greater than or equal operator.</summary>
		GreaterThanOrEqual = 16
	}
}
