using System.Collections;
using UnityEngine;

public class FirstTimeMovePrompt : MonoBehaviour
{
	private const string SeenKey = "HasSeenMovePrompt";

	private void Start()
	{
		if (PlayerPrefs.GetInt("HasSeenMovePrompt", 0) == 1)
		{
			base.gameObject.SetActive(value: false);
			return;
		}
		PlayerPrefs.SetInt("HasSeenMovePrompt", 1);
		PlayerPrefs.Save();
		StartCoroutine(HideAfterDelay(3f));
	}

	private IEnumerator HideAfterDelay(float delay)
	{
		yield return new WaitForSeconds(delay);
		base.gameObject.SetActive(value: false);
	}
}
