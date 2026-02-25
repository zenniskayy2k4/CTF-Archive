using Unity.Mathematics;

namespace UnityEngine.Splines
{
	public abstract class SplineComponent : MonoBehaviour
	{
		public enum AlignAxis
		{
			[InspectorName("Object X+")]
			XAxis = 0,
			[InspectorName("Object Y+")]
			YAxis = 1,
			[InspectorName("Object Z+")]
			ZAxis = 2,
			[InspectorName("Object X-")]
			NegativeXAxis = 3,
			[InspectorName("Object Y-")]
			NegativeYAxis = 4,
			[InspectorName("Object Z-")]
			NegativeZAxis = 5
		}

		private readonly float3[] m_AlignAxisToVector = new float3[6]
		{
			math.right(),
			math.up(),
			math.forward(),
			math.left(),
			math.down(),
			math.back()
		};

		protected float3 GetAxis(AlignAxis axis)
		{
			return m_AlignAxisToVector[(int)axis];
		}
	}
}
