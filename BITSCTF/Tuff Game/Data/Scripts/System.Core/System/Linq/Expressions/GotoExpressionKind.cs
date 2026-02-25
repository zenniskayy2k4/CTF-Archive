namespace System.Linq.Expressions
{
	/// <summary>Specifies what kind of jump this <see cref="T:System.Linq.Expressions.GotoExpression" /> represents.</summary>
	public enum GotoExpressionKind
	{
		/// <summary>A <see cref="T:System.Linq.Expressions.GotoExpression" /> that represents a jump to some location.</summary>
		Goto = 0,
		/// <summary>A <see cref="T:System.Linq.Expressions.GotoExpression" /> that represents a return statement.</summary>
		Return = 1,
		/// <summary>A <see cref="T:System.Linq.Expressions.GotoExpression" /> that represents a break statement.</summary>
		Break = 2,
		/// <summary>A <see cref="T:System.Linq.Expressions.GotoExpression" /> that represents a continue statement.</summary>
		Continue = 3
	}
}
