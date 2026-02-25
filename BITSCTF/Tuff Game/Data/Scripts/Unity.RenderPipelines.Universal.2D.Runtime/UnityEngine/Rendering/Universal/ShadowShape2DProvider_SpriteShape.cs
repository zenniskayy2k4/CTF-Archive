using System;
using Unity.Collections;
using Unity.Mathematics;
using UnityEngine.U2D;

namespace UnityEngine.Rendering.Universal
{
	[Serializable]
	internal class ShadowShape2DProvider_SpriteShape : ShadowShape2DProvider
	{
		private const float k_InitialTrim = 0.02f;

		internal void UpdateShadows(SpriteShapeController spriteShapeController, ShadowShape2D persistantShapeData)
		{
			NativeArray<float2> shadowShapeData = spriteShapeController.GetShadowShapeData();
			int length = shadowShapeData.Length;
			if (length > 0)
			{
				bool flag = shadowShapeData[0].x == shadowShapeData[length - 1].x && shadowShapeData[0].y == shadowShapeData[length - 1].y;
				int num = (flag ? (length - 1) : length);
				int num2 = 2 * length;
				NativeArray<Vector3> vertices = new NativeArray<Vector3>(num, Allocator.Temp);
				NativeArray<int> indices = new NativeArray<int>(num2 - 2, Allocator.Temp);
				for (int i = 0; i < num; i++)
				{
					vertices[i] = new Vector3(shadowShapeData[i].x, shadowShapeData[i].y, 0f);
				}
				for (int j = 0; j < length - 1; j++)
				{
					int num3 = 2 * j;
					indices[num3] = j;
					indices[num3 + 1] = j + 1;
				}
				if (flag)
				{
					int num4 = 2 * num;
					indices[num4 - 1] = 0;
				}
				persistantShapeData.SetShape(vertices, indices, ShadowShape2D.OutlineTopology.Lines);
				vertices.Dispose();
				indices.Dispose();
			}
			shadowShapeData.Dispose();
		}

		public override int Priority()
		{
			return 10;
		}

		public override void Enabled(Component sourceComponent, ShadowShape2D persistantShadowShape)
		{
			((SpriteShapeController)sourceComponent).ForceShadowShapeUpdate(forceUpdate: true);
		}

		public override void Disabled(Component sourceComponent, ShadowShape2D persistantShadowShape)
		{
			((SpriteShapeController)sourceComponent).ForceShadowShapeUpdate(forceUpdate: false);
		}

		public override bool IsShapeSource(Component sourceComponent)
		{
			return sourceComponent as SpriteShapeController;
		}

		public override void OnPersistantDataCreated(Component sourceComponent, ShadowShape2D persistantShadowShape)
		{
			SpriteShapeController spriteShapeController = (SpriteShapeController)sourceComponent;
			spriteShapeController.TryGetComponent<SpriteShapeRenderer>(out var component);
			float trimEdgeFromBounds = ShadowShapeProvider2DUtility.GetTrimEdgeFromBounds(component.bounds, 0.02f);
			persistantShadowShape.SetDefaultTrim(trimEdgeFromBounds);
			UpdateShadows(spriteShapeController, persistantShadowShape);
		}

		public override void OnBeforeRender(Component sourceComponent, Bounds worldCullingBounds, ShadowShape2D persistantShadowShape)
		{
			UpdateShadows((SpriteShapeController)sourceComponent, persistantShadowShape);
		}
	}
}
