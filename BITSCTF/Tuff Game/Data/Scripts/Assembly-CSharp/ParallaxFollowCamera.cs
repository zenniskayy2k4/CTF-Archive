using UnityEngine;

public class ParallaxFollowCamera : MonoBehaviour
{
	[Header("Layers")]
	public Transform[] layerRoots;

	public float[] parallaxFactors;

	private Transform cam;

	private Vector3 lastCamPos;

	private float[] spriteWidths;

	private void Start()
	{
		cam = Camera.main.transform;
		lastCamPos = cam.position;
		spriteWidths = new float[layerRoots.Length];
		for (int i = 0; i < layerRoots.Length; i++)
		{
			SpriteRenderer component = layerRoots[i].GetChild(0).GetComponent<SpriteRenderer>();
			spriteWidths[i] = component.bounds.size.x;
		}
	}

	private void LateUpdate()
	{
		Vector3 vector = cam.position - lastCamPos;
		for (int i = 0; i < layerRoots.Length; i++)
		{
			Transform transform = layerRoots[i];
			float num = parallaxFactors[i];
			float num2 = spriteWidths[i];
			int childCount = transform.childCount;
			transform.position += new Vector3(vector.x * num, 0f, 0f);
			for (int j = 0; j < childCount; j++)
			{
				Transform child = transform.GetChild(j);
				if (child.position.x < cam.position.x - num2)
				{
					child.position += Vector3.right * num2 * childCount;
				}
			}
		}
		lastCamPos = cam.position;
	}
}
