using System;
using Unity.Collections;
using UnityEngine.Animations;

namespace UnityEngine.U2D.Common
{
	internal static class InternalEngineBridge
	{
		public static void SetLocalAABB(SpriteRenderer spriteRenderer, Bounds aabb)
		{
			spriteRenderer.SetLocalAABB(aabb);
		}

		public static void SetDeformableBuffer(SpriteRenderer spriteRenderer, NativeArray<byte> src)
		{
			spriteRenderer.SetDeformableBuffer(src);
		}

		public static void SetBoneTransforms(SpriteRenderer spriteRenderer, NativeArray<Matrix4x4> src)
		{
			spriteRenderer.SetBoneTransforms(src);
		}

		public static bool IsUsingDeformableBuffer(SpriteRenderer spriteRenderer, IntPtr buffer)
		{
			return spriteRenderer.IsUsingDeformableBuffer(buffer);
		}

		public static void SetupMaterialProperties(SpriteRenderer spriteRenderer)
		{
			SpriteRendererDataAccessExtensions.SetupMaterialProperties(spriteRenderer);
		}

		public static Vector2 GUIUnclip(Vector2 v)
		{
			return GUIClip.Unclip(v);
		}

		public static Rect GetGUIClipTopMostRect()
		{
			return GUIClip.topmostRect;
		}

		public static Rect GetGUIClipTopRect()
		{
			return GUIClip.GetTopRect();
		}

		public static Rect GetGUIClipVisibleRect()
		{
			return GUIClip.visibleRect;
		}

		public static bool IsGPUSkinningEnabled()
		{
			return SpriteRendererDataAccessExtensions.IsGPUSkinningEnabled();
		}

		public static bool IsSRPBatchingEnabled(SpriteRenderer spriteRenderer)
		{
			return spriteRenderer.IsSRPBatchingEnabled();
		}

		public static void SetBatchDeformableBufferAndLocalAABBArray(SpriteRenderer[] spriteRenderers, NativeArray<IntPtr> buffers, NativeArray<int> bufferSizes, NativeArray<Bounds> bounds)
		{
			SpriteRendererDataAccessExtensions.SetBatchDeformableBufferAndLocalAABBArray(spriteRenderers, buffers, bufferSizes, bounds);
		}

		public static void SetBatchBoneTransformsAABBArray(SpriteRenderer[] spriteRenderers, NativeArray<IntPtr> buffers, NativeArray<int> bufferSizes, NativeArray<Bounds> bounds)
		{
			SpriteRendererDataAccessExtensions.SetBoneTransformsArray(spriteRenderers, buffers, bufferSizes, bounds);
		}

		public static int ConvertFloatToInt(float f)
		{
			return DiscreteEvaluationAttributeUtilities.ConvertFloatToDiscreteInt(f);
		}

		public static float ConvertIntToFloat(int i)
		{
			return DiscreteEvaluationAttributeUtilities.ConvertDiscreteIntToFloat(i);
		}

		public static void MarkDirty(this Object obj)
		{
			obj.MarkDirty();
		}
	}
}
