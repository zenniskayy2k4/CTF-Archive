using UnityEngine.Bindings;

namespace UnityEngine.Rendering
{
	[NativeHeader("Runtime/Export/Graphics/MachineLearning.bindings.h")]
	[NativeHeader("Runtime/Graphics/MachineLearning/MachineLearningTensor.h")]
	public enum MachineLearningDataType
	{
		Unknown = 0,
		Float32 = 1,
		Float16 = 2,
		UInt32 = 3,
		UInt16 = 4,
		UInt8 = 5,
		Int32 = 6,
		Int16 = 7,
		Int8 = 8,
		Float64 = 9,
		UInt64 = 10,
		Int64 = 11
	}
}
