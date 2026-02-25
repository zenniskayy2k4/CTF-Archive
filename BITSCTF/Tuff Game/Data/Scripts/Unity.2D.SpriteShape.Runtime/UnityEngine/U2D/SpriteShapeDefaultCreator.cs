using Unity.Collections;
using Unity.Jobs;
using Unity.Mathematics;

namespace UnityEngine.U2D
{
	internal class SpriteShapeDefaultCreator : SpriteShapeGeometryCreator
	{
		private static SpriteShapeDefaultCreator creator;

		internal static SpriteShapeDefaultCreator defaultInstance
		{
			get
			{
				if (null == creator)
				{
					creator = ScriptableObject.CreateInstance<SpriteShapeDefaultCreator>();
					creator.hideFlags = HideFlags.DontSave;
				}
				return creator;
			}
		}

		public override int GetVertexArrayCount(SpriteShapeController sc)
		{
			NativeArray<ShapeControlPoint> shapeControlPoints = sc.GetShapeControlPoints();
			sc.CalculateMaxArrayCount(shapeControlPoints);
			shapeControlPoints.Dispose();
			return sc.maxArrayCount;
		}

		public override JobHandle MakeCreatorJob(SpriteShapeController sc, NativeArray<ushort> indices, NativeSlice<Vector3> positions, NativeSlice<Vector2> texCoords, NativeSlice<Vector4> tangents, NativeArray<SpriteShapeSegment> segments, NativeArray<float2> colliderData)
		{
			bool useUTess = sc.ValidateUTess2D();
			NativeArray<Bounds> bounds = sc.spriteShapeRenderer.GetBounds();
			SpriteShapeGenerator jobData = new SpriteShapeGenerator
			{
				m_Bounds = bounds,
				m_PosArray = positions,
				m_Uv0Array = texCoords,
				m_TanArray = tangents,
				m_GeomArray = segments,
				m_IndexArray = indices,
				m_ColliderPoints = colliderData,
				m_Stats = sc.stats,
				m_ShadowPoints = sc.shadowData
			};
			jobData.generateCollider = SpriteShapeController.generateCollider;
			jobData.generateGeometry = SpriteShapeController.generateGeometry;
			NativeArray<ShapeControlPoint> shapeControlPoints = sc.GetShapeControlPoints();
			NativeArray<SplinePointMetaData> splinePointMetaData = sc.GetSplinePointMetaData();
			jobData.Prepare(sc, sc.spriteShapeParameters, sc.maxArrayCount, shapeControlPoints, splinePointMetaData, sc.angleRangeInfoArray, sc.edgeSpriteArray, sc.cornerSpriteArray, useUTess);
			JobHandle result = jobData.Schedule();
			shapeControlPoints.Dispose();
			splinePointMetaData.Dispose();
			return result;
		}

		public override int GetVersion()
		{
			int num = 1;
			return ((-2128831035 ^ GetInstanceID()) * 16777619) ^ num;
		}
	}
}
