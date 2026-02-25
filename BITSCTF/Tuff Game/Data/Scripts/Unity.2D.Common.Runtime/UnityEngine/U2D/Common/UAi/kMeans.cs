using Unity.Collections;
using Unity.Collections.LowLevel.Unsafe;
using Unity.Mathematics;

namespace UnityEngine.U2D.Common.UAi
{
	internal static class kMeans
	{
		private static float CalculateDistance(MatrixMxN<float> data, int dataIndex, MatrixMxN<float> centroid, int centroidIndex)
		{
			float num = 0f;
			for (int i = 0; i < data.DimensionY; i++)
			{
				num += Mathf.Pow(centroid.Get(centroidIndex, i) - data.Get(dataIndex, i), 2f);
			}
			return Mathf.Sqrt(num);
		}

		private unsafe static float CalculateClustering(MatrixMxN<float> data, NativeArray<int> clusters, ref MatrixMxN<float> means, ref NativeArray<int> centroids, int clusterCount, ref NativeArray<int> clusterItems)
		{
			UnsafeUtility.MemSet(means.GetArray().GetUnsafePtr(), 0, UnsafeUtility.SizeOf<int>() * means.Length);
			for (int i = 0; i < data.DimensionX; i++)
			{
				int num = clusters[i];
				clusterItems[num]++;
				for (int j = 0; j < data.DimensionY; j++)
				{
					float num2 = means.Get(num, j);
					means.Set(num, j, data.Get(i, j) + num2);
				}
			}
			for (int k = 0; k < means.DimensionX; k++)
			{
				for (int l = 0; l < means.DimensionY; l++)
				{
					int num3 = clusterItems[k];
					float num4 = means.Get(k, l);
					num4 /= (float)((num3 <= 0) ? 1 : num3);
					means.Set(k, l, num4);
				}
			}
			float num5 = 0f;
			NativeArray<float> nativeArray = new NativeArray<float>(clusterCount, Allocator.Temp);
			for (int m = 0; m < clusterCount; m++)
			{
				nativeArray[m] = float.MaxValue;
			}
			for (int n = 0; n < data.DimensionX; n++)
			{
				int num6 = clusters[n];
				float num7 = CalculateDistance(data, n, means, num6);
				num5 += num7;
				if (num7 < nativeArray[num6])
				{
					nativeArray[num6] = num7;
					centroids[num6] = n;
				}
			}
			nativeArray.Dispose();
			return num5;
		}

		private static bool AssignClustering(MatrixMxN<float> data, NativeArray<int> clusters, ref NativeArray<int> centroidIdx, int clusterCount)
		{
			bool result = false;
			for (int i = 0; i < data.DimensionX; i++)
			{
				float num = float.MaxValue;
				int num2 = -1;
				for (int j = 0; j < clusterCount; j++)
				{
					int centroidIndex = centroidIdx[j];
					float num3 = CalculateDistance(data, i, data, centroidIndex);
					if (num3 < num)
					{
						num = num3;
						num2 = j;
					}
				}
				if (num2 != -1 && clusters[i] != num2)
				{
					result = true;
					clusters[i] = num2;
				}
			}
			return result;
		}

		private unsafe static void ClusterInternal(MatrixMxN<float> data, NativeArray<int> clusters, MatrixMxN<float> means, NativeArray<int> centroids, NativeArray<int> clusterItems, int clusterCount, int maxIterations)
		{
			bool flag = true;
			int num = 0;
			Unity.Mathematics.Random random = new Unity.Mathematics.Random(1u);
			for (int i = 0; i < clusters.Length; i++)
			{
				clusters[i] = random.NextInt(0, clusterCount);
			}
			while (flag && num++ < maxIterations)
			{
				UnsafeUtility.MemSet(clusterItems.GetUnsafePtr(), 0, UnsafeUtility.SizeOf<int>() * clusterCount);
				CalculateClustering(data, clusters, ref means, ref centroids, clusterCount, ref clusterItems);
				flag = AssignClustering(data, clusters, ref centroids, clusterCount);
			}
		}

		public static int[] Cluster3(NativeArray<float3> items, int clusterCount, Allocator alloc, int maxIterations = 64)
		{
			MatrixMxN<float> data = new MatrixMxN<float>(items.Length, 3, alloc, NativeArrayOptions.UninitializedMemory);
			NativeArray<int> clusters = new NativeArray<int>(items.Length, alloc, NativeArrayOptions.UninitializedMemory);
			MatrixMxN<float> means = new MatrixMxN<float>(clusterCount, 3, alloc, NativeArrayOptions.ClearMemory);
			for (int i = 0; i < items.Length; i++)
			{
				data.Set(i, 0, items[i].x);
				data.Set(i, 1, items[i].y);
				data.Set(i, 2, items[i].z);
			}
			NativeArray<int> centroids = new NativeArray<int>(clusterCount, alloc, NativeArrayOptions.UninitializedMemory);
			NativeArray<int> clusterItems = new NativeArray<int>(clusterCount, alloc, NativeArrayOptions.UninitializedMemory);
			ClusterInternal(data, clusters, means, centroids, clusterItems, clusterCount, maxIterations);
			int[] result = centroids.ToArray();
			clusterItems.Dispose();
			centroids.Dispose();
			means.Dispose();
			clusters.Dispose();
			data.Dispose();
			return result;
		}
	}
}
