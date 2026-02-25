using UnityEngine.Bindings;

namespace UnityEngine.Android
{
	[NativeType(Header = "Modules/AndroidJNI/Public/GameStateHelper.h")]
	public enum AndroidGameState
	{
		Unknown = 0,
		None = 1,
		GamePlayInterruptible = 2,
		GamePlayUninterruptible = 3,
		Content = 4
	}
}
