namespace UnityEngine.UIElements.UIR
{
	internal enum EntryType : ushort
	{
		DrawSolidMesh = 0,
		DrawTexturedMesh = 1,
		DrawTexturedMeshSkipAtlas = 2,
		DrawDynamicTexturedMesh = 3,
		DrawTextMesh = 4,
		DrawGradients = 5,
		DrawImmediate = 6,
		DrawImmediateCull = 7,
		DrawChildren = 8,
		BeginStencilMask = 9,
		EndStencilMask = 10,
		PopStencilMask = 11,
		PushClippingRect = 12,
		PopClippingRect = 13,
		PushScissors = 14,
		PopScissors = 15,
		PushGroupMatrix = 16,
		PopGroupMatrix = 17,
		PushDefaultMaterial = 18,
		PopDefaultMaterial = 19,
		CutRenderChain = 20,
		DedicatedPlaceholder = 21
	}
}
