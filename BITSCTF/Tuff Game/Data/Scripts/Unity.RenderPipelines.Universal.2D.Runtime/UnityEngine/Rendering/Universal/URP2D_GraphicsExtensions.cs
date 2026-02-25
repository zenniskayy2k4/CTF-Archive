namespace UnityEngine.Rendering.Universal
{
	public static class URP2D_GraphicsExtensions
	{
		public static SpriteMaskInteraction GetSpriteMaskInteraction(this MeshRenderer meshRenderer)
		{
			return meshRenderer.Internal_GetSpriteMaskInteraction();
		}

		public static SpriteMaskInteraction GetSpriteMaskInteraction(this SkinnedMeshRenderer skinnedMeshRenderer)
		{
			return skinnedMeshRenderer.Internal_GetSpriteMaskInteraction();
		}

		public static void SetSpriteMaskInteraction(this MeshRenderer meshRenderer, SpriteMaskInteraction maskInteraction)
		{
			meshRenderer.Internal_SetSpriteMaskInteraction(maskInteraction);
		}

		public static void SetSpriteMaskInteraction(this SkinnedMeshRenderer skinnedMeshRenderer, SpriteMaskInteraction maskInteraction)
		{
			skinnedMeshRenderer.Internal_SetSpriteMaskInteraction(maskInteraction);
		}
	}
}
