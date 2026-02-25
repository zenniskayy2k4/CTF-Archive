namespace UnityEngine.UIElements.UIR
{
	internal enum CommandType
	{
		Draw = 0,
		ImmediateCull = 1,
		Immediate = 2,
		PushView = 3,
		PopView = 4,
		PushScissor = 5,
		PopScissor = 6,
		PushDefaultMaterial = 7,
		PopDefaultMaterial = 8,
		BeginDisable = 9,
		EndDisable = 10,
		CutRenderChain = 11
	}
}
