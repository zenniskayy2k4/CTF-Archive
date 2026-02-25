using System.Text;
using UnityEngine;

public class FlagGeneration : MonoBehaviour
{
	private const byte KEY = 90;

	private readonly byte[] encryptedFlag = new byte[51]
	{
		33, 15, 55, 55, 5, 110, 57, 46, 47, 59,
		54, 54, 35, 5, 47, 52, 34, 106, 40, 107,
		107, 52, 61, 5, 46, 106, 5, 61, 105, 46,
		5, 60, 54, 110, 61, 5, 41, 105, 105, 55,
		41, 5, 46, 106, 106, 5, 105, 110, 41, 35,
		39
	};

	private string decryptFlag()
	{
		byte[] array = new byte[encryptedFlag.Length];
		for (int i = 0; i < encryptedFlag.Length; i++)
		{
			array[i] = (byte)(encryptedFlag[i] ^ 0x5A);
		}
		return Encoding.ASCII.GetString(array);
	}
}
