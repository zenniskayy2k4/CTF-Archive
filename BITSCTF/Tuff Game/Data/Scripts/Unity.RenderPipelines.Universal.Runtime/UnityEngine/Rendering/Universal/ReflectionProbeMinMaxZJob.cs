using Unity.Burst;
using Unity.Collections;
using Unity.Jobs;
using Unity.Mathematics;

namespace UnityEngine.Rendering.Universal
{
	[BurstCompile]
	internal struct ReflectionProbeMinMaxZJob : IJobFor
	{
		public Fixed2<float4x4> worldToViews;

		[ReadOnly]
		public NativeArray<VisibleReflectionProbe> reflectionProbes;

		[ReadOnly]
		public bool reflectionProbeRotation;

		public NativeArray<float2> minMaxZs;

		public void Execute(int index)
		{
			float2 value = math.float2(float.MaxValue, float.MinValue);
			int index2 = index % reflectionProbes.Length;
			VisibleReflectionProbe visibleReflectionProbe = reflectionProbes[index2];
			int index3 = index / reflectionProbes.Length;
			float4x4 a = worldToViews[index3];
			float3 float5 = visibleReflectionProbe.bounds.center;
			float3 float6 = visibleReflectionProbe.bounds.extents;
			quaternion q = ((!reflectionProbeRotation) ? quaternion.identity : ((quaternion)visibleReflectionProbe.localToWorldMatrix.rotation));
			for (int i = 0; i < 8; i++)
			{
				int num = ((i << 1) & 2) - 1;
				int num2 = (i & 2) - 1;
				int num3 = ((i >> 1) & 2) - 1;
				float3 v = float6 * math.float3(num, num2, num3);
				float3 float7 = math.rotate(q, v);
				float4 float8 = math.mul(a, math.float4(float7 + float5, 1f));
				float8.z *= -1f;
				value.x = math.min(value.x, float8.z);
				value.y = math.max(value.y, float8.z);
			}
			minMaxZs[index] = value;
		}
	}
}
