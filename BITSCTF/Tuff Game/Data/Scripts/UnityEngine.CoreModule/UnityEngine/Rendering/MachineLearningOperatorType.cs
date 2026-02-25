using UnityEngine.Bindings;

namespace UnityEngine.Rendering
{
	[NativeHeader("Runtime/Graphics/MachineLearning/MachineLearningOperatorAttributes.h")]
	[NativeHeader("Runtime/Graphics/MachineLearning/MachineLearningOperator.h")]
	[NativeHeader("Runtime/Graphics/MachineLearning/MachineLearningContext.h")]
	public enum MachineLearningOperatorType : uint
	{
		None = 0u,
		Identity = 1u,
		Gemm = 2u,
		Conv = 3u,
		ReLU = 4u,
		ReduceMax = 5u,
		ReduceMean = 6u,
		ReduceMin = 7u,
		ReduceProd = 8u,
		ReduceSum = 9u,
		ReduceSumSquare = 10u,
		ReduceL1 = 11u,
		ReduceL2 = 12u,
		ReduceLogSum = 13u,
		ReduceLogSumExp = 14u
	}
}
